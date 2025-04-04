use crate::load_balancers;
use crate::load_balancers::{LeastConnections, RoundRobin};
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Debug)]
pub struct Config(HashMap<String, Server>);

impl Deref for Config {
    type Target = HashMap<String, Server>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Config {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Config {
    // pub fn get_server_from_sni(&mut self, sni: Option<&DnsName>) -> Option<&mut Server> {
    //     let Some(sni) = sni else {
    //         return None;
    //     };
    //     self.0
    //         .iter_mut()
    //         .find(|server| &server.server_name == sni.as_ref())
    // }

    pub fn tls_enabled_servers(&self) -> impl Iterator<Item = (&String, &SSLConfig)> {
        self.0
            .iter()
            .filter_map(|(server_name, server)| Some((server_name, server.ssl.as_ref()?)))
    }
}

#[derive(Debug)]
pub struct Server {
    pub ssl: Option<SSLConfig>,
    pub load_balancer: Box<dyn load_balancers::LoadBalancer>,
}

impl Server {
    pub fn should_decrypt(&self) -> bool {
        self.ssl.is_some()
    }
}

#[derive(Debug, Deserialize)]
pub struct SSLConfig {
    pub ssl_certificate: PathBuf,
    pub ssl_certificate_key: PathBuf,
}

#[derive(Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct Upstream {
    pub addr: SocketAddr,
}

#[derive(Debug, Deserialize)]
enum LoadBalancer {
    RoundRobin,
    LeastConnections,
}

impl Default for LoadBalancer {
    fn default() -> Self {
        Self::RoundRobin
    }
}
//region Deserialize Impls
impl<'de> Deserialize<'de> for Config {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let servers: Vec<NamedServer> = Deserialize::deserialize(deserializer)?;
        let map = servers
            .into_iter()
            .map(|s| (s.0, s.1))
            .collect::<HashMap<_, _>>();

        Ok(Self(map))
    }
}

impl<'de> Deserialize<'de> for Upstream {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Upstream {
            addr: SocketAddr::deserialize(deserializer)?,
        })
    }
}

struct NamedServer(String, Server);
impl<'de> Deserialize<'de> for NamedServer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let server = helper::Server::deserialize(deserializer)?;
        let load_balancer: Box<dyn load_balancers::LoadBalancer> = match server.load_balancer {
            LoadBalancer::RoundRobin => Box::new(RoundRobin::from(server.upstreams)),
            LoadBalancer::LeastConnections => Box::new(LeastConnections::from(server.upstreams)),
        };

        Ok(NamedServer(
            server.server_name,
            Server {
                ssl: server.ssl,
                load_balancer,
            },
        ))
    }
}
mod helper {
    use super::*;
    #[derive(Debug, Deserialize)]
    pub struct Server {
        pub server_name: String,
        pub ssl: Option<SSLConfig>,
        pub upstreams: Vec<Upstream>,
        #[serde(default = "LoadBalancer::default")]
        pub load_balancer: LoadBalancer,
    }
}
//endregion
