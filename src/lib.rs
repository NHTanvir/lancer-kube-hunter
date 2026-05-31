//! lancer-kube-hunter — a Rust clone of Aqua Security's kube-hunter with full
//! upstream feature parity plus a native egui GUI. Part of the Lancer toolkit.
//!
//! The library exposes the scan engine and all hunters so both the CLI binary
//! and the parity test-suite (`tests/upstream_parity/`) can share the code.

pub mod cli;
pub mod discovery;
pub mod gui;
pub mod hunter;
pub mod hunting;
pub mod knowledge_base;
pub mod report;
pub mod runner;
pub mod scan;
pub mod selftest;
pub mod types;
pub mod version;

use colored::Colorize;

/// Initialise the tracing logger at the level requested via `--log`.
pub fn init_logging(level: &str) {
    let lvl = match level.to_ascii_uppercase().as_str() {
        "DEBUG"            => tracing::Level::DEBUG,
        "WARNING" | "WARN" => tracing::Level::WARN,
        _                  => tracing::Level::INFO,
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive(lvl.into()),
        )
        .without_time()
        .with_target(false)
        .try_init();
}

/// Print the run banner (shared by CLI and GUI status output).
pub fn banner(active: bool) {
    println!("{}", "╔══════════════════════════════════════════╗".cyan());
    println!("{}", "║   lancer-kube-hunter  —  Lancer toolkit  ║".cyan().bold());
    println!("{}", "╚══════════════════════════════════════════╝".cyan());
    let mode = if active { "ACTIVE".red().bold() } else { "passive".green() };
    println!("[*] Mode: {mode}");
}
