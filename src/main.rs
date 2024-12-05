mod config;
mod controller;

use std::{fs, path::PathBuf};

use clap::Parser;
use log::debug;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Sets a custom config file
    #[arg(short, long, default_value = "config.ron")]
    config: PathBuf,
}

fn main() -> anyhow::Result<()> {
    log4rs::init_file("log4rs.yaml", Default::default())?;
    let cli = Cli::parse();

    let cfg =
        ron::from_str::<Vec<config::Server>>(&fs::read_to_string(&cli.config).unwrap()).unwrap();

    debug!("Loaded CLI config {cli:#?}");
    debug!("Loaded config file {}, {cfg:#?}", cli.config.display());

    Ok(())
}
