mod config;
mod controller;
mod logger;

use crate::logger::create_logger;
use clap::Parser;
use log::{debug, error, info};
use std::io::Write;
use std::sync::Arc;
use std::{fs, io::Read, net::TcpListener, path::PathBuf};
use tls::config::ServerConfig;
use tls::pki_types::pem::PemObject;
use tls::pki_types::{CertificateDer, PrivateKeyDer};
use tls::server::Acceptor;
use tls::stream::StreamOwned;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Sets a custom config file
    #[arg(short, long, default_value = "config.ron")]
    config: PathBuf,
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

struct ReadAndLog<T: Read> {
    inner: T,
    buffer: Vec<u8>,
}

impl<T: Read> ReadAndLog<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            buffer: Vec::with_capacity(4096),
        }
    }
}

impl<T: Read> Read for ReadAndLog<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = self.inner.read(buf)?;
        self.buffer.extend_from_slice(&buf[..len]);
        Ok(len)
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    create_logger(cli.verbose, false)?;

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

    'accept_loop: for socket in listener.incoming() {
        let mut socket = socket?;
        let mut acceptor = Acceptor::default();

        let mut transport = ReadAndLog::new(&mut socket);
        let accepted = loop {
            acceptor.read_tls(&mut transport)?;
            match acceptor.accept() {
                Ok(Some(accepted)) => break accepted,
                Ok(None) => continue,
                Err((e, mut alert)) => {
                    alert.write_all(&mut socket)?;
                    error!("Failed Accepting Connection: {:?}", e);
                    continue 'accept_loop;
                }
            }
        };

        debug!("Transport Buffer {:?}", transport.buffer);
        info!("sni is {:?}", accepted.sni());

        let connection = match accepted.into_connection(_cfg.clone()) {
            Ok(connection) => connection,
            Err((e, mut alert)) => {
                alert.write_all(&mut socket)?;
                error!("Failed Creating Connection: {:?}", e);
                continue;
            }
        };

        let mut stream = StreamOwned::new(connection, socket);
        // let mut stream = tls::stream::StreamOwned::new(Connection::new(_cfg.clone()), socket?);

        let mut buf = [0u8; 2048];
        let len = match stream.read(&mut buf) {
            Ok(len) => len,
            Err(_) => continue,
        };
        info!("{}", String::from_utf8(buf[..len].to_vec())?);

        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 993\r\nConnection: close\r\n\r\n")?;

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
</html>"#,
        )?;
        debug!("{:?}", len);
    }

    Ok(())
}
