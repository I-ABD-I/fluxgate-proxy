mod config;
mod controller;

use std::{fs, io::Read, net::TcpListener, path::PathBuf};

use clap::Parser;
use log::debug;
use tls::server::Connection;

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

    // panics, cannot run without proper config
    let cfg = ron::from_str::<Vec<config::Server>>(&fs::read_to_string(&cli.config)?)?;

    debug!("Loaded CLI config {cli:#?}");
    debug!("Loaded config file {}, {cfg:#?}", cli.config.display());

    let listener = TcpListener::bind("127.0.0.1:4000").unwrap();

    for socket in listener.incoming() {
        let mut stream = tls::stream::StreamOwned::new(Connection::new(), socket.unwrap());
        let mut buf = [0u8; 2048];
        stream.read(&mut buf).unwrap();
    }

    Ok(())
}
