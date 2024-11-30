use std::path::PathBuf;

use clap::Parser;
use log::{info, warn};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Sets a custom config file
    #[arg(short, long, default_value = "config")]
    config: PathBuf,
}

fn main() -> anyhow::Result<()> {
    log4rs::init_file("log4rs.yaml", Default::default())?;
    let _cli = Cli::parse();

    info!("Cli Options: {_cli:#?}");
    info!("test");
    warn!("test");
    Ok(())
}
