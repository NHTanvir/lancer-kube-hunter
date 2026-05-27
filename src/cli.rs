use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name    = "lancer-kube-hunter",
    version,
    about   = "Kubernetes attack-surface scanner — Rust clone of kube-hunter"
)]
pub struct Cli {
    /// Scan a single remote IP or hostname
    #[arg(long, value_name = "HOST")]
    pub remote: Option<String>,

    /// Scan a CIDR range (e.g. 10.0.0.0/24)
    #[arg(long, value_name = "CIDR")]
    pub cidr: Option<String>,

    /// Scan local network interfaces
    #[arg(long, default_value_t = false)]
    pub internal: bool,

    /// Enable active (write/exploit) hunters — use only with explicit permission
    #[arg(long, default_value_t = false)]
    pub active: bool,

    /// Output format: table | json | yaml
    #[arg(long, default_value = "table", value_name = "FORMAT")]
    pub output: String,

    /// HTTP URL to POST results JSON (optional collector)
    #[arg(long, value_name = "URL")]
    pub report_url: Option<String>,

    /// Comma-separated list of ports to scan (overrides built-in list)
    #[arg(long, value_name = "PORTS")]
    pub ports: Option<String>,

    /// Port scan timeout in milliseconds
    #[arg(long, default_value_t = 1500, value_name = "MS")]
    pub port_timeout: u64,
}

impl Cli {
    pub fn custom_ports(&self) -> Option<Vec<u16>> {
        self.ports.as_ref().map(|s| {
            s.split(',')
                .filter_map(|p| p.trim().parse().ok())
                .collect()
        })
    }
}
