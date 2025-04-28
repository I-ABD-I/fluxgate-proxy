use crate::cert_resolver::CertificateResolver;
use crate::controller::middleware::analytics;
use crate::error::MiddlewareError;
use crate::load_balancers;
use crate::load_balancers::{LeastConnections, ResourceBased, RoundRobin};
use layered::service::Service;
use layered::ServiceBuilder;
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::Arc;
use std::{fmt, net::SocketAddr, path::PathBuf};
use tls::config::ServerConfig;
use tls::pki_types::pem::PemObject;
use tls::pki_types::{CertificateDer, PrivateKeyDer};

/// Configuration for the server, represented as a map of server names to server configurations.
pub struct Config<Middleware>(HashMap<String, Server<Middleware>>);

impl<T> Debug for Config<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.0.iter()).finish()
    }
}

impl<Middleware> Deref for Config<Middleware> {
    type Target = HashMap<String, Server<Middleware>>;

    /// Dereferences the `Config` to access the underlying `HashMap`.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Middleware> DerefMut for Config<Middleware> {
    /// Dereferences the `Config` to access the underlying `HashMap` mutably.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

fn build_middleware(
) -> impl for<'a> Service<&'a [u8], Error = MiddlewareError, Response = ()> + Clone + Send {
    ServiceBuilder::new()
        .layer(analytics())
        .build::<MiddlewareError>()
}

impl Config<()> {
    pub async fn read_from_file(
        path: &Path,
    ) -> anyhow::Result<
        Config<
            impl for<'a> Service<&'a [u8], Error = MiddlewareError, Response = ()> + Clone + Send,
        >,
    > {
        let servers: Vec<helper::Server> =
            ron::from_str(&async_std::fs::read_to_string(path).await?)?;

        let mut map = HashMap::new();

        // DEFAULT MIDDLEWARE TODO: CHANGE THIS
        let middleware = build_middleware();

        for server in servers {
            let load_balancer: Box<dyn load_balancers::LoadBalancer> = match server.load_balancer {
                LoadBalancer::RoundRobin => Box::new(RoundRobin::from(server.upstreams)),
                LoadBalancer::LeastConnections => {
                    Box::new(LeastConnections::from(server.upstreams))
                }
                LoadBalancer::ResourceBased => Box::new(ResourceBased::from(server.upstreams)),
            };

            map.insert(
                server.server_name,
                Server {
                    ssl: server.ssl,
                    load_balancer,
                    middleware: middleware.clone(),
                },
            );
        }

        Ok(Config(map))
    }
}
impl<Middleware> Config<Middleware> {
    /// Returns an iterator over servers that have TLS enabled.
    ///
    /// # Returns
    /// An iterator over tuples of server names and their corresponding `SSLConfig`.
    pub fn build_tls_config(&self) -> anyhow::Result<ServerConfig> {
        let mut resolver = CertificateResolver::new();
        let tls_cfg = ServerConfig::builder();
        for (name, server) in self.iter() {
            if let Some(certificate_pair) = &server.ssl {
                let certs = CertificateDer::pem_file_iter(&certificate_pair.ssl_certificate)?
                    .map(|cert| cert.unwrap())
                    .collect();
                let key = PrivateKeyDer::from_pem_file(&certificate_pair.ssl_certificate_key)?;

                let cert = Arc::new(tls::config::CertifiedKey::from_der(
                    certs,
                    key,
                    tls_cfg.provider(),
                )?);
                resolver.add_certificate(name.to_lowercase(), cert);
            }
        }

        Ok(tls_cfg.with_cert_resolver(Arc::new(resolver)))
    }
}

/// Configuration for an individual server.
pub struct Server<Middleware> {
    /// Optional SSL configuration for the server.
    pub ssl: Option<SSLConfig>,
    /// Load balancer used by the server.
    pub load_balancer: Box<dyn load_balancers::LoadBalancer>,
    pub middleware: Middleware,
}

impl<Middleware> Debug for Server<Middleware> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("ssl", &self.ssl)
            .field("load_balancer", &self.load_balancer)
            .finish()
    }
}

impl<Middleware> Server<Middleware> {
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
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct Upstream {
    /// Socket address of the upstream server.
    pub addr: SocketAddr,
}

/// Enumeration of available load balancers.
#[derive(Debug, Deserialize, Eq, PartialEq)]
enum LoadBalancer {
    RoundRobin,
    LeastConnections,
    ResourceBased,
}

impl Default for LoadBalancer {
    /// Provides the default load balancer, which is `RoundRobin`.
    fn default() -> Self {
        Self::RoundRobin
    }
}

// region Deserialize Impls

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
