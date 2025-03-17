mod config;
mod controller;
mod logger;

use crate::logger::create_logger;
use clap::Parser;
use log::{debug, info};
use std::io::Write;
use std::{fs, io::Read, net::TcpListener, path::PathBuf};
use std::sync::Arc;
use tls::config::ServerConfig;
use tls::pki_types::{CertificateDer, PrivateKeyDer};
use tls::pki_types::pem::PemObject;
use tls::server::Connection;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Sets a custom config file
    #[arg(short, long, default_value = "config.ron")]
    config: PathBuf,
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    create_logger(cli.verbose)?;

    // panics, cannot run without proper config
    let cfg = ron::from_str::<Vec<config::Server>>(&fs::read_to_string(&cli.config)?)?;

    debug!("Loaded CLI config {cli:#?}");
    debug!("Loaded config file {}, {cfg:#?}", cli.config.display());

    let listener = TcpListener::bind("127.0.0.1:4000")?;


    let certs = CertificateDer::pem_file_iter("certificate.crt")?
        .map(|cert| cert.unwrap())
        .collect();
    let key = PrivateKeyDer::from_pem_file("key.pem")?;

    let _cfg = ServerConfig::builder().with_single_certificate(certs, key)?;
    let _cfg = Arc::new(_cfg);

    for socket in listener.incoming() {
        let mut stream = tls::stream::StreamOwned::new(Connection::new(_cfg.clone()), socket?);
        let mut buf = [0u8; 2048];
        let len = match stream.read(&mut buf) {
            Ok(len) => len,
            Err(_) => continue,
        };
        info!("{}", String::from_utf8(buf[..len].to_vec())?);

        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 993\r\nConnection: close\r\n\r\n")?;

        let len = stream.write(
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
</html>"#
        )?;
        debug!("{:?}", len);
    }

    Ok(())
}
