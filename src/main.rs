use async_std::prelude::*;
use async_std::sync::{Arc, Mutex};
use clap::Parser;
use fluxgate::config::SSLConfig;
use fluxgate::controller::client_handler;
use fluxgate::logger::create_logger;
use fluxgate::{cert_resolver, config};
use log::{debug, error};
use std::{fs, path::PathBuf};
use tls::config::ServerConfig;
use tls::pki_types::pem::PemObject;
use tls::pki_types::{CertificateDer, PrivateKeyDer};

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

    let cfg = ron::from_str::<config::Config>(&fs::read_to_string(&cli.config)?)?;
    debug!("Loaded CLI config {cli:#?}");
    debug!("Loaded config file {}, {cfg:#?}", cli.config.display());

    let tls_cfg = Arc::new(build_tls_config(cfg.tls_enabled_servers())?);
    let cfg = Arc::new(Mutex::new(cfg));

    let listener = async_std::net::TcpListener::bind("127.0.0.1:4000").await?;
    let mut incoming = listener.incoming();
    debug!("Listening on {}", listener.local_addr()?);

    while let Some(socket) = incoming.next().await {
        let socket = socket?;
        let cfg = cfg.clone();
        let tls_cfg = tls_cfg.clone();
        async_std::task::spawn(async {
            match client_handler(socket, tls_cfg, cfg).await {
                Ok(_) => {}
                Err(e) => error!("Client handler failed: {e}"),
            }
        });
    }

    Ok(())
}

/// Builds the TLS configuration.
///
/// # Arguments
/// * `iter` - An iterator over tuples of DNS names and SSL configurations.
///
/// # Returns
/// An `anyhow::Result` containing the `ServerConfig`.
fn build_tls_config<'a>(
    iter: impl Iterator<Item = (&'a String, &'a SSLConfig)>,
) -> anyhow::Result<ServerConfig> {
    let mut resolver = cert_resolver::CertificateResolver::new();
    let tls_cfg = ServerConfig::builder();
    for (dns, certificate_pair) in iter {
        let certs = CertificateDer::pem_file_iter(&certificate_pair.ssl_certificate)?
            .map(|cert| cert.unwrap())
            .collect();
        let key = PrivateKeyDer::from_pem_file(&certificate_pair.ssl_certificate_key)?;

        let cert = Arc::new(tls::config::CertifiedKey::from_der(
            certs,
            key,
            tls_cfg.provider(),
        )?);

        resolver.add_certificate(dns.clone(), cert);
    }

    Ok(tls_cfg.with_cert_resolver(Arc::new(resolver)))
}
