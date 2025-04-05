use crate::load_balancers;
use crate::load_balancers::{LeastConnections, RoundRobin};
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::{net::SocketAddr, path::PathBuf};

/// Configuration for the server, represented as a map of server names to server configurations.
#[derive(Debug)]
pub struct Config(HashMap<String, Server>);

impl Deref for Config {
    type Target = HashMap<String, Server>;

    /// Dereferences the `Config` to access the underlying `HashMap`.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Config {
    /// Dereferences the `Config` to access the underlying `HashMap` mutably.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Config {
    /// Returns an iterator over servers that have TLS enabled.
    ///
    /// # Returns
    /// An iterator over tuples of server names and their corresponding `SSLConfig`.
    pub fn tls_enabled_servers(&self) -> impl Iterator<Item = (&String, &SSLConfig)> {
        self.0
            .iter()
            .filter_map(|(server_name, server)| Some((server_name, server.ssl.as_ref()?)))
    }
}

/// Configuration for an individual server.
#[derive(Debug)]
pub struct Server {
    /// Optional SSL configuration for the server.
    pub ssl: Option<SSLConfig>,
    /// Load balancer used by the server.
    pub load_balancer: Box<dyn load_balancers::LoadBalancer>,
}

impl Server {
    /// Checks if the server should decrypt incoming connections.
    ///
    /// # Returns
    /// `true` if the server has SSL configuration, `false` otherwise.
    pub fn should_decrypt(&self) -> bool {
        self.ssl.is_some()
    }
}

/// SSL configuration for a server.
#[derive(Debug, Deserialize)]
pub struct SSLConfig {
    /// Path to the SSL certificate file.
    pub ssl_certificate: PathBuf,
    /// Path to the SSL certificate key file.
    pub ssl_certificate_key: PathBuf,
}

/// Represents an upstream server with its socket address.
#[derive(Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct Upstream {
    /// Socket address of the upstream server.
    pub addr: SocketAddr,
}

/// Enumeration of available load balancers.
#[derive(Debug, Deserialize)]
enum LoadBalancer {
    RoundRobin,
    LeastConnections,
}

impl Default for LoadBalancer {
    /// Provides the default load balancer, which is `RoundRobin`.
    fn default() -> Self {
        Self::RoundRobin
    }
}

// region Deserialize Impls
impl<'de> Deserialize<'de> for Config {
    /// Deserializes a `Config` from a deserializer.
    ///
    /// # Arguments
    /// * `deserializer` - The deserializer to read the `Config` from.
    ///
    /// # Returns
    /// A `Result` containing the deserialized `Config` or an error.
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
    /// Deserializes an `Upstream` from a deserializer.
    ///
    /// # Arguments
    /// * `deserializer` - The deserializer to read the `Upstream` from.
    ///
    /// # Returns
    /// A `Result` containing the deserialized `Upstream` or an error.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Upstream {
            addr: SocketAddr::deserialize(deserializer)?,
        })
    }
}

/// Helper struct for deserializing named servers.
struct NamedServer(String, Server);

impl<'de> Deserialize<'de> for NamedServer {
    /// Deserializes a `NamedServer` from a deserializer.
    ///
    /// # Arguments
    /// * `deserializer` - The deserializer to read the `NamedServer` from.
    ///
    /// # Returns
    /// A `Result` containing the deserialized `NamedServer` or an error.
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

    /// Helper struct for deserializing server configurations.
    #[derive(Debug, Deserialize)]
    pub struct Server {
        /// Name of the server.
        pub server_name: String,
        /// Optional SSL configuration for the server.
        pub ssl: Option<SSLConfig>,
        /// List of upstream servers.
        pub upstreams: Vec<Upstream>,
        /// Load balancer used by the server.
        #[serde(default = "LoadBalancer::default")]
        pub load_balancer: LoadBalancer,
    }
}
// endregion
