//! lancer-kube-hunter
//! Rust clone of kube-hunter. See plan.md (local, gitignored) for the spec.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lancer-kube-hunter", version, about = "Rust clone of kube-hunter")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-kube-hunter - scaffold ready. Implement per plan.md.");
    Ok(())
}
