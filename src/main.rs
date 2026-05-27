mod cli;
mod discovery;
mod hunter;
mod hunting;
mod report;
mod runner;
mod types;
mod version;

use std::net::IpAddr;
use clap::Parser;
use colored::Colorize;

use cli::Cli;
use types::{Event, Mode};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Init tracing — silence by default, enable via RUST_LOG env var
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .without_time()
        .with_target(false)
        .init();

    let mode = if cli.active { Mode::Active } else { Mode::Passive };

    println!(
        "{}",
        "╔══════════════════════════════════════════╗".cyan()
    );
    println!(
        "{}",
        "║   lancer-kube-hunter  —  Lancer toolkit  ║".cyan().bold()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════╝".cyan()
    );

    let mode_str = if cli.active { "ACTIVE" } else { "passive" };
    println!("[*] Mode: {}", mode_str.bold());

    // ── Build initial events from CLI mode ────────────────────────────────────
    let mut initial_events: Vec<Event> = Vec::new();

    // In-pod auto-detection
    if let Some((host, port, token)) = detect_in_cluster() {
        println!("[*] In-cluster environment detected — pod mode");
        initial_events.push(Event::InCluster { host, port, token });
    }

    if let Some(remote) = &cli.remote {
        let ip: IpAddr = remote.parse().map_err(|_| {
            anyhow::anyhow!("Invalid IP address: {}", remote)
        })?;
        println!("[*] Scanning remote host: {}", ip);
        initial_events.push(Event::NewHost { host: ip });
    }

    if let Some(cidr) = &cli.cidr {
        let net: ipnet::IpNet = cidr.parse().map_err(|_| {
            anyhow::anyhow!("Invalid CIDR: {}", cidr)
        })?;
        let hosts: Vec<_> = net.hosts().collect();
        println!("[*] Scanning CIDR {} ({} hosts)", cidr, hosts.len());
        for ip in hosts {
            initial_events.push(Event::NewHost { host: ip });
        }
    }

    if cli.internal {
        println!("[*] Internal mode — scanning local subnet");
        if let Ok(local_ip) = get_primary_local_ip() {
            // Scan the /24 around the local IP
            if let Ok(net) = format!("{}/24", local_ip)
                .parse::<ipnet::IpNet>()
                .map(|n| n.trunc())
            {
                for ip in net.hosts() {
                    initial_events.push(Event::NewHost { host: ip });
                }
            }
        }
    }

    if initial_events.is_empty() {
        eprintln!("{}", "[!] No scan target specified. Use --remote, --cidr, or --internal.".yellow());
        eprintln!("    Run with --help for usage.");
        std::process::exit(1);
    }

    // ── Build hunter registry ─────────────────────────────────────────────────
    let mut hunters = discovery::all_hunters();
    hunters.extend(hunting::all_hunters());

    // ── Run ───────────────────────────────────────────────────────────────────
    let port_timeout = std::time::Duration::from_millis(cli.port_timeout);
    let runner = runner::Runner::new(mode, hunters, port_timeout, cli.custom_ports())?;
    println!("[*] Starting scan…\n");
    let findings = runner.run(initial_events).await;

    // ── Report ────────────────────────────────────────────────────────────────
    report::dispatch(
        &findings,
        &cli.output,
        cli.report_url.as_deref(),
    )
    .await?;

    Ok(())
}

/// Detect in-cluster environment from standard K8s env vars and SA token file.
fn detect_in_cluster() -> Option<(String, String, String)> {
    let host  = std::env::var("KUBERNETES_SERVICE_HOST").ok()?;
    let port  = std::env::var("KUBERNETES_SERVICE_PORT")
        .unwrap_or_else(|_| "443".to_string());
    let token = std::fs::read_to_string(
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
    ).ok()?;
    Some((host, port, token))
}

/// Get the primary outbound local IP via UDP connect trick (no packets sent).
fn get_primary_local_ip() -> anyhow::Result<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    Ok(socket.local_addr()?.ip())
}
