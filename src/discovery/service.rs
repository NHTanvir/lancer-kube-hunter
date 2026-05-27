use std::sync::Arc;
use async_trait::async_trait;
use serde_json::Value;

use crate::hunter::Hunter;
use crate::types::{Event, EventKind, HunterCtx, Mode, Output};

/// Probes each open port to identify the K8s service type and emits typed events.
pub struct ServiceDiscovery;

#[async_trait]
impl Hunter for ServiceDiscovery {
    fn name(&self)          -> &'static str { "ServiceDiscovery" }
    fn mode(&self)          -> Mode         { Mode::Passive }
    fn subscribes_to(&self) -> EventKind    { EventKind::OpenPort }

    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output> {
        let (host, port) = match event.as_ref() {
            Event::OpenPort { host, port } => (*host, *port),
            _ => return vec![],
        };

        match port {
            6443 | 443 | 8443 => probe_api_server(&ctx, host, port, true).await,
            8080               => probe_api_server(&ctx, host, port, false).await,
            8001               => probe_kube_proxy(&ctx, host, port).await,
            10250              => probe_kubelet_secure(&ctx, host, port).await,
            10255              => probe_kubelet_readonly(&ctx, host, port).await,
            2379 | 2380        => probe_etcd(&ctx, host, port).await,
            _                  => vec![],
        }
    }
}

async fn probe_api_server(
    ctx: &HunterCtx, host: std::net::IpAddr, port: u16, tls: bool,
) -> Vec<Output> {
    let scheme = if tls { "https" } else { "http" };
    let url = format!("{scheme}://{host}:{port}/version");

    let resp = ctx.http_insecure.get(&url).send().await;
    if let Ok(r) = resp {
        if let Ok(json) = r.json::<Value>().await {
            if json["major"].is_string() || json["minor"].is_string() {
                tracing::info!("  [*] API server detected at {}:{}", host, port);
                return vec![Output::Event(Event::ApiServer { host, port, tls })];
            }
        }
    }

    // Also try /api/v1 as fallback
    let url2 = format!("{scheme}://{host}:{port}/api/v1");
    if let Ok(r) = ctx.http_insecure.get(&url2).send().await {
        if let Ok(json) = r.json::<Value>().await {
            if json["kind"].as_str() == Some("APIResourceList") {
                tracing::info!("  [*] API server detected at {}:{} (via /api/v1)", host, port);
                return vec![Output::Event(Event::ApiServer { host, port, tls })];
            }
        }
    }

    vec![]
}

async fn probe_kubelet_secure(
    ctx: &HunterCtx, host: std::net::IpAddr, port: u16,
) -> Vec<Output> {
    let url = format!("https://{host}:{port}/healthz");
    if let Ok(r) = ctx.http_insecure.get(&url).send().await {
        if r.status().is_success() {
            tracing::info!("  [*] Kubelet (secure) at {}:{}", host, port);
            return vec![Output::Event(Event::KubeletSecure { host, port })];
        }
    }
    vec![]
}

async fn probe_kubelet_readonly(
    ctx: &HunterCtx, host: std::net::IpAddr, port: u16,
) -> Vec<Output> {
    let url = format!("http://{host}:{port}/healthz");
    if let Ok(r) = ctx.http_insecure.get(&url).send().await {
        if r.status().is_success() {
            tracing::info!("  [*] Kubelet (read-only) at {}:{}", host, port);
            return vec![Output::Event(Event::KubeletReadOnly { host, port })];
        }
    }
    vec![]
}

async fn probe_kube_proxy(
    ctx: &HunterCtx, host: std::net::IpAddr, port: u16,
) -> Vec<Output> {
    let url = format!("http://{host}:{port}/api/v1");
    if let Ok(r) = ctx.http_insecure.get(&url).send().await {
        if r.status().is_success() {
            if let Ok(json) = r.json::<Value>().await {
                if json["kind"].as_str() == Some("APIResourceList") {
                    tracing::info!("  [*] kube-proxy at {}:{}", host, port);
                    return vec![Output::Event(Event::KubeProxy { host, port })];
                }
            }
        }
    }
    vec![]
}

async fn probe_etcd(
    ctx: &HunterCtx, host: std::net::IpAddr, port: u16,
) -> Vec<Output> {
    // etcd v3 health endpoint
    for scheme in &["http", "https"] {
        let url = format!("{scheme}://{host}:{port}/health");
        if let Ok(r) = ctx.http_insecure.get(url).send().await {
            if r.status().is_success() {
                tracing::info!("  [*] etcd at {}:{}", host, port);
                return vec![Output::Event(Event::Etcd { host, port })];
            }
        }
    }
    vec![]
}
