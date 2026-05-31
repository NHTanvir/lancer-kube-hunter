use std::time::Duration;
use clap::Parser;

use crate::report::{Dispatch, Format};
use crate::scan::{self, ScanConfig};

#[derive(Parser, Debug, Clone)]
#[command(
    name    = "lancer-kube-hunter",
    version,
    about   = "Kubernetes attack-surface scanner — Rust clone of kube-hunter (+ native GUI)"
)]
pub struct Cli {
    /// Scan a single remote IP or hostname (repeatable)
    #[arg(long, value_name = "HOST")]
    pub remote: Vec<String>,

    /// Probe the local network interface subnet
    #[arg(long, alias = "internal", default_value_t = false)]
    pub interface: bool,

    /// Scan a CIDR range, e.g. 10.0.0.0/24 (repeatable)
    #[arg(long, value_name = "CIDR")]
    pub cidr: Vec<String>,

    /// Use the K8s API to enumerate nodes and add them as targets
    #[arg(long = "k8s-auto-discover-nodes", default_value_t = false)]
    pub k8s_auto_discover_nodes: bool,

    /// Explicit kubeconfig path (for --k8s-auto-discover-nodes)
    #[arg(long, value_name = "PATH")]
    pub kubeconfig: Option<String>,

    /// Force pod (in-cluster) mode
    #[arg(long, default_value_t = false)]
    pub pod: bool,

    /// Cloud quick scan — cap subnet scanning to a /24
    #[arg(long, default_value_t = false)]
    pub quick: bool,

    /// Enable active (write/exploit) hunters — use only with explicit permission
    #[arg(long, default_value_t = false)]
    pub active: bool,

    /// Impersonate a specific service-account bearer token
    #[arg(long = "service-account-token", value_name = "TOKEN")]
    pub service_account_token: Option<String>,

    /// Run only the listed hunters (plus always-on discovery/report core)
    #[arg(long, num_args = 1.., value_name = "HUNTER")]
    pub custom: Vec<String>,

    /// List all available tests (combine with --active to include active tests)
    #[arg(long, default_value_t = false)]
    pub list: bool,

    /// Print discovered node/service mapping only (no vulnerability output)
    #[arg(long, default_value_t = false)]
    pub mapping: bool,

    /// Use raw hunter class names instead of human-readable names
    #[arg(long = "raw-hunter-names", default_value_t = false)]
    pub raw_hunter_names: bool,

    /// Log level: DEBUG | INFO | WARNING
    #[arg(long, default_value = "INFO", value_name = "LEVEL")]
    pub log: String,

    /// Report format: plain | json | yaml | sarif | markdown
    #[arg(long = "report", alias = "output", default_value = "plain", value_name = "FORMAT")]
    pub report: String,

    /// Dispatch method: stdout | http
    #[arg(long, default_value = "stdout", value_name = "METHOD")]
    pub dispatch: String,

    /// Collector URL override (also read from KUBEHUNTER_HTTP_DISPATCH_URL)
    #[arg(long = "report-url", value_name = "URL")]
    pub report_url: Option<String>,

    /// Run the headless CLI surface (default invocation opens the GUI)
    #[arg(long, default_value_t = false)]
    pub cli: bool,

    /// Run the built-in parity self-test matrix and exit
    #[arg(long = "self-test", default_value_t = false)]
    pub self_test: bool,

    /// Comma-separated ports to scan (overrides the built-in K8s + NodePort set)
    #[arg(long, value_name = "PORTS")]
    pub ports: Option<String>,

    /// Per-port connect timeout in milliseconds
    #[arg(long = "port-timeout", default_value_t = 1500, value_name = "MS")]
    pub port_timeout: u64,
}

impl Cli {
    pub fn custom_ports(&self) -> Option<Vec<u16>> {
        self.ports.as_ref().map(|s| {
            s.split(',').filter_map(|p| p.trim().parse().ok()).collect()
        })
    }

    pub fn report_format(&self) -> Format {
        Format::parse(&self.report)
    }

    pub fn dispatch_method(&self) -> Dispatch {
        Dispatch::parse(&self.dispatch)
    }

    /// True when the bare GUI should launch (no headless intent expressed).
    pub fn wants_gui(&self) -> bool {
        if self.cli || self.list || self.self_test || self.mapping {
            return false;
        }
        // Any scan target / pod intent means a headless run.
        self.remote.is_empty()
            && self.cidr.is_empty()
            && !self.interface
            && !self.pod
            && !self.k8s_auto_discover_nodes
    }

    /// Resolve all CLI inputs into a concrete [`ScanConfig`].
    pub async fn build_config(&self) -> anyhow::Result<ScanConfig> {
        let mut targets = vec![];
        for r in &self.remote {
            let resolved = scan::resolve_host(r).await;
            if resolved.is_empty() {
                tracing::warn!("could not resolve --remote target: {r}");
            }
            targets.extend(resolved);
        }
        for c in &self.cidr {
            targets.extend(scan::expand_cidr(c)?);
        }
        if self.interface {
            targets.extend(scan::local_subnet_hosts());
        }
        if self.k8s_auto_discover_nodes {
            targets.extend(scan::kubeconfig_nodes(self.kubeconfig.as_deref()).await);
        }

        // --quick: cap cloud subnet scanning to a /24.
        if self.quick && targets.len() > 256 {
            tracing::info!("--quick: capping {} targets to 256 (/24)", targets.len());
            targets.truncate(256);
        }

        let in_cluster = scan::detect_in_cluster();

        // Token precedence: explicit flag, else the mounted in-cluster token.
        let sa_token = self.service_account_token.clone()
            .or_else(|| in_cluster.as_ref().map(|(_, _, t)| t.clone()));

        Ok(ScanConfig {
            targets,
            interface:    self.interface,
            active:       self.active,
            sa_token,
            custom:       self.custom.clone(),
            ports:        self.custom_ports(),
            port_timeout: Duration::from_millis(self.port_timeout),
            in_cluster,
        })
    }
}

/// Headless CLI entry point.
pub async fn run(cli: Cli) -> anyhow::Result<()> {
    if cli.list {
        print_list(&cli);
        return Ok(());
    }
    if cli.self_test {
        return crate::selftest::run();
    }

    crate::banner(cli.active);

    let cfg = cli.build_config().await?;
    if cfg.targets.is_empty() && cfg.in_cluster.is_none() {
        eprintln!("[!] No scan target specified. Use --remote, --cidr, --interface, --pod, or --k8s-auto-discover-nodes.");
        eprintln!("    Run with --help for usage, --list for available tests, or omit args to open the GUI.");
        std::process::exit(1);
    }

    println!("[*] Starting scan ({} target host(s))…\n", cfg.targets.len());
    let findings = scan::run_scan(cfg).await?;

    if cli.mapping {
        print_mapping(&findings);
        return Ok(());
    }

    crate::report::dispatch(
        &findings,
        cli.report_format(),
        cli.dispatch_method(),
        cli.report_url.as_deref(),
    )
    .await?;

    Ok(())
}

/// `--list` — enumerate every registered test and the full KHV catalog.
fn print_list(cli: &Cli) {
    let mut hunters = crate::discovery::all_hunters();
    hunters.extend(crate::hunting::all_hunters());

    println!("\n=== Available hunters ===");
    for h in &hunters {
        let active = h.mode() == crate::types::Mode::Active;
        if active && !cli.active {
            continue; // active tests only shown with --active
        }
        if cli.raw_hunter_names {
            println!("{}", h.name());
        } else {
            let tag = if active { " [active]" } else { "" };
            println!("  - {}{}\n      {}", h.name(), tag, h.description());
        }
    }

    if !cli.raw_hunter_names {
        println!("\n=== KHV knowledge base ({} entries) ===", crate::knowledge_base::count());
        for m in crate::knowledge_base::CATALOG {
            println!("  {} [{}] {} — {}", m.vid, m.severity, m.category.as_str(), m.title);
        }
    }
}

/// `--mapping` — print the discovered node/service map only.
fn print_mapping(findings: &[crate::types::Finding]) {
    use std::collections::BTreeSet;
    let mut nodes: BTreeSet<&str> = BTreeSet::new();
    let mut services: BTreeSet<String> = BTreeSet::new();
    for f in findings {
        nodes.insert(f.host.as_str());
        if let Some(p) = f.port {
            services.insert(format!("{}:{}", f.host, p));
        }
    }
    println!("\n=== Discovered nodes ===");
    for n in &nodes {
        println!("  {n}");
    }
    println!("\n=== Discovered services ===");
    for s in &services {
        println!("  {s}");
    }
}
