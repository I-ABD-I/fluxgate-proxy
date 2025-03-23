mod config;
mod controller;
mod logger;

use clap::Parser;
use std::sync::Arc;
use std::{fs, path::PathBuf};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Sets a custom config file
    #[arg(short, long, default_value = "config.ron")]
    config: PathBuf,
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

use crate::logger::create_logger;
use async_std::prelude::*;
use log::{debug, info};
use tls::config::ServerConfig;
use tls::futures::LazyAcceptor;
use tls::pki_types::pem::PemObject;
use tls::pki_types::{CertificateDer, PrivateKeyDer};
use tls::server::Acceptor;

#[async_std::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    create_logger(cli.verbose, false)?;

    // panics, cannot run without proper config
    let cfg = ron::from_str::<Vec<config::Server>>(&fs::read_to_string(&cli.config)?)?;

    debug!("Loaded CLI config {cli:#?}");
    debug!("Loaded config file {}, {cfg:#?}", cli.config.display());

    let listener = async_std::net::TcpListener::bind("127.0.0.1:4000").await?;
    let certs = CertificateDer::pem_file_iter("certificate.crt")?
        .map(|cert| cert.unwrap())
        .collect();
    let key = PrivateKeyDer::from_pem_file("key.pem")?;

    let _cfg = ServerConfig::builder().with_single_certificate(certs, key)?;
    let _cfg = Arc::new(_cfg);

    let mut incoming = listener.incoming();

    while let Some(socket) = incoming.next().await {
        let socket = socket?;

        let acceptor = LazyAcceptor::new(Acceptor::default(), socket);
        let sh = acceptor.await?;
        debug!("Accepted connection, SNI is {:?}", sh.client_hello().sni());
        let mut stream = match sh.into_stream(_cfg.clone()).await {
            Ok(stream) => stream,
            Err(_) => continue,
        };

        let mut buf = [0u8; 2048];
        let len = stream.read(&mut buf).await?;
        info!("{}", String::from_utf8(buf[..len].to_vec())?);

        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 1313\r\nConnection: close\r\n\r\n").await?;

        stream
            .write(
                br#"<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Hello World Test</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f9;
                    margin: 0;
                    padding: 0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    text-align: center;
                }
                .container {
                    background-color: #fff;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                }
                h1 {
                    color: #4CAF50;
                    font-size: 3em;
                }
                p {
                    color: #555;
                    font-size: 1.2em;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Hello, World!</h1>
                <p>Welcome to your test page.</p>
            </div>
        </body>
        </html>"#,
            )
            .await?;
    }

    Ok(())
}
