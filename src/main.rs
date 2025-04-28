use async_std::prelude::*;
use async_std::sync::Arc;
use async_std::task::spawn;
use clap::Parser;
use fluxgate::config::Config;
use fluxgate::controller::client_handler;
use fluxgate::logger::create_logger;
use log::{debug, error};
use std::path::PathBuf;

/// Command-line interface structure for parsing arguments.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Sets a custom config file
    #[arg(short, long, default_value = "config.ron")]
    config: PathBuf,
    /// Enables verbose logging
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

/// Main entry point of the application.
///
/// # Returns
/// An `anyhow::Result` indicating the success or failure of the operation.
#[async_std::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    create_logger(cli.verbose, false)?;

    let cfg = Config::<()>::read_from_file(&cli.config).await?;
    debug!("Loaded CLI config {cli:#?}");
    debug!("Loaded config file {}, {cfg:#?}", cli.config.display());

    let tls_cfg = Arc::new(cfg.build_tls_config()?);
    let cfg = Arc::new(cfg);

    let listener = async_std::net::TcpListener::bind("127.0.0.1:4000").await?;
    let mut incoming = listener.incoming();
    debug!("Listening on {}", listener.local_addr()?);

    while let Some(socket) = incoming.next().await {
        let socket = socket?;
        let cfg = cfg.clone();
        let tls_cfg = tls_cfg.clone();
        spawn(async {
            if let Err(e) = client_handler(socket, tls_cfg, cfg).await {
                error!("Error handling client: {e}");
            }
        });
    }

    Ok(())
}
