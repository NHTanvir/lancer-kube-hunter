use clap::Parser;

use lancer_kube_hunter::cli::{self, Cli};
use lancer_kube_hunter::{gui, init_logging};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logging(&cli.log);

    // One multi-threaded Tokio runtime drives async work for both frontends.
    // eframe needs the OS main thread, so we do not use #[tokio::main].
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    if cli.wants_gui() {
        gui::run(rt, cli)
    } else {
        rt.block_on(cli::run(cli))
    }
}
