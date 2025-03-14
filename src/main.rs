mod config;
mod controller;
mod logger;

use crate::logger::create_logger;
use clap::Parser;
use log::{debug, info};
use std::io::Write;
use std::{fs, io::Read, net::TcpListener, path::PathBuf};
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

    for socket in listener.incoming() {
        let mut stream = tls::stream::StreamOwned::new(Connection::new(), socket?);
        let mut buf = [0u8; 2048];
        let len = match stream.read(&mut buf) {
            Ok(len) => len,
            Err(_) => continue,
        };
        info!("{}", String::from_utf8(buf[..len].to_vec())?);
        let len = stream.write(
            b"
HTTP/1.1 200 OK
Date: Wed, 14 Mar 2025 12:00:00 GMT
Server: MyServer/1.0
Content-Type: text/html; charset=UTF-8
Content-Length: 13

Hello, world!
",
        )?;
        debug!("{:?}", len);
    }

    Ok(())
}
