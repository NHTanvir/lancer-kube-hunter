//! Shared scan engine used by both the CLI and the GUI frontends. The `core`
//! logic is frontend-agnostic: callers build a [`ScanConfig`] and call
//! [`run_scan`].

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use serde_json::Value;

use crate::types::{Event, Finding, Mode};
use crate::{discovery, hunting, runner::Runner};

/// Hunters that always run, even under `--custom` (discovery seeds + banner).
const ALWAYS_ON: &[&str] = &[
    "HostDiscovery",
    "FromPodHostDiscovery",
    "PortDiscovery",
    "ServiceDiscovery",
    "KubernetesClusterDiscovery",
    "StartedInfo",
];

#[derive(Debug, Clone, Default)]
pub struct ScanConfig {
    /// Already-resolved seed IPs (from --remote/--cidr/--interface/auto-discover).
    pub targets:        Vec<IpAddr>,
    /// Scanning local interfaces (gates ARP/DNS-spoof surface hunters).
    pub interface:      bool,
    /// Active mode (enables ActiveHunter subclasses).
    pub active:         bool,
    /// Service-account bearer token for authenticated probes.
    pub sa_token:       Option<String>,
    /// Hunter-name whitelist (`--custom`); empty = run all.
    pub custom:         Vec<String>,
    /// Port override (`--ports`); None = default K8s + NodePort set.
    pub ports:          Option<Vec<u16>>,
    /// Per-port connect timeout.
    pub port_timeout:   Duration,
    /// In-cluster credentials (host, port, token) when running in a pod.
    pub in_cluster:     Option<(String, String, String)>,
}

/// Build the hunter registry for a config, applying the `--custom` whitelist.
pub fn build_hunters(cfg: &ScanConfig) -> Vec<std::sync::Arc<dyn crate::hunter::Hunter>> {
    let mut hunters = discovery::all_hunters();
    hunters.extend(hunting::all_hunters());

    if !cfg.custom.is_empty() {
        let allow: HashSet<String> = cfg.custom.iter().map(|s| s.to_ascii_lowercase()).collect();
        hunters.retain(|h| {
            ALWAYS_ON.contains(&h.name()) || allow.contains(&h.name().to_ascii_lowercase())
        });
    }
    hunters
}

/// Run a full scan and return the collected findings.
pub async fn run_scan(cfg: ScanConfig) -> anyhow::Result<Vec<Finding>> {
    let mode = if cfg.active { Mode::Active } else { Mode::Passive };
    let hunters = build_hunters(&cfg);

    let runner = Runner::new(
        mode,
        hunters,
        cfg.port_timeout,
        cfg.ports.clone(),
        cfg.sa_token.clone(),
        cfg.interface,
    )?;

    // Seed events: ScanStarted first (always-on modules), then in-cluster, then hosts.
    let mut events = vec![Event::ScanStarted];
    if let Some((host, port, token)) = &cfg.in_cluster {
        events.push(Event::InCluster {
            host: host.clone(),
            port: port.clone(),
            token: token.clone(),
        });
    }
    for ip in &cfg.targets {
        events.push(Event::NewHost { host: *ip });
    }

    Ok(runner.run(events).await)
}

// ── Target resolution helpers ─────────────────────────────────────────────────

/// Expand a CIDR string into host IPs.
pub fn expand_cidr(cidr: &str) -> anyhow::Result<Vec<IpAddr>> {
    let net: ipnet::IpNet = cidr.parse()
        .map_err(|_| anyhow::anyhow!("Invalid CIDR: {cidr}"))?;
    Ok(net.hosts().collect())
}

/// Resolve a host string (IP or DNS name) to one or more IPs.
pub async fn resolve_host(host: &str) -> Vec<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![ip];
    }
    // DNS resolution via tokio (append a dummy port for lookup_host).
    match tokio::net::lookup_host((host, 0u16)).await {
        Ok(addrs) => addrs.map(|sa| sa.ip()).collect(),
        Err(_) => vec![],
    }
}

/// The /24 subnet around the primary outbound interface (for `--interface`).
pub fn local_subnet_hosts() -> Vec<IpAddr> {
    match primary_local_ip() {
        Ok(ip) => format!("{ip}/24")
            .parse::<ipnet::IpNet>()
            .map(|n| n.trunc().hosts().collect())
            .unwrap_or_default(),
        Err(_) => vec![],
    }
}

fn primary_local_ip() -> anyhow::Result<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    Ok(socket.local_addr()?.ip())
}

/// Detect in-cluster environment: KUBERNETES_SERVICE_HOST + the mounted SA token.
pub fn detect_in_cluster() -> Option<(String, String, String)> {
    let host = std::env::var("KUBERNETES_SERVICE_HOST").ok()?;
    let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_string());
    let token = std::fs::read_to_string(
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
    ).ok()?;
    Some((host, port, token))
}

/// `--k8s-auto-discover-nodes`: parse a kubeconfig (or use in-cluster creds) and
/// query the API server for node InternalIPs.
pub async fn kubeconfig_nodes(kubeconfig: Option<&str>) -> Vec<IpAddr> {
    let (server, token) = match resolve_kube_access(kubeconfig) {
        Some(v) => v,
        None => return vec![],
    };

    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let url = format!("{}/api/v1/nodes", server.trim_end_matches('/'));
    let mut req = client.get(&url);
    if let Some(t) = &token {
        req = req.bearer_auth(t);
    }
    let json: Value = match req.send().await {
        Ok(r) => r.json().await.unwrap_or_default(),
        Err(_) => return vec![],
    };

    let mut out = vec![];
    if let Some(items) = json["items"].as_array() {
        for item in items {
            if let Some(addrs) = item["status"]["addresses"].as_array() {
                for a in addrs {
                    if a["type"] == "InternalIP" {
                        if let Some(s) = a["address"].as_str() {
                            if let Ok(ip) = s.parse() {
                                out.push(ip);
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// Resolve (server URL, bearer token) from a kubeconfig path, or fall back to
/// in-cluster credentials.
fn resolve_kube_access(kubeconfig: Option<&str>) -> Option<(String, Option<String>)> {
    if let Some(path) = kubeconfig {
        let raw = std::fs::read_to_string(path).ok()?;
        let doc: Value = serde_yaml::from_str(&raw).ok()?;
        // Pick the current context's cluster server + user token (best-effort:
        // fall back to the first cluster/user when context wiring is absent).
        let server = doc["clusters"].as_array()
            .and_then(|c| c.first())
            .and_then(|c| c["cluster"]["server"].as_str())
            .map(String::from)?;
        let token = doc["users"].as_array()
            .and_then(|u| u.first())
            .and_then(|u| u["user"]["token"].as_str())
            .map(String::from);
        return Some((server, token));
    }

    // In-cluster fallback.
    let (host, port, token) = detect_in_cluster()?;
    Some((format!("https://{host}:{port}"), Some(token)))
}
