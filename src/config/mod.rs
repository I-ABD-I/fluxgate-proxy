use std::{net::SocketAddr, path::PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Server {
    pub listen: u16,
    pub server_name: String,
    pub ssl: Option<SSLConfig>,
    pub upstreams: Vec<Upstream>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SSLConfig {
    ssl_certificate: PathBuf,
    ssl_certificate_key: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Upstream {
    pub addr: SocketAddr,
}
