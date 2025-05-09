#[cfg(not(feature = "config"))]
use crate::cert_resolver::CertificateResolver;
#[cfg(not(feature = "config"))]
use crate::controller::middleware::analytics;
#[cfg(not(feature = "config"))]
use crate::error::MiddlewareError;
#[cfg(not(feature = "config"))]
use crate::load_balancers;
#[cfg(not(feature = "config"))]
use crate::load_balancers::{LeastConnections, ResourceBased, RoundRobin};
#[cfg(not(feature = "config"))]
use async_std::sync::Mutex;
#[cfg(not(feature = "config"))]
use layered::service::Service;
#[cfg(not(feature = "config"))]
use layered::ServiceBuilder;
#[cfg(not(feature = "config"))]
use log::error;
use serde::{Deserialize, Deserializer, Serialize};
#[cfg(not(feature = "config"))]
use std::collections::HashMap;
#[cfg(not(feature = "config"))]
use std::fmt;
use std::fmt::Debug;
use std::net::SocketAddr;
#[cfg(not(feature = "config"))]
use std::ops::{Deref, DerefMut};
#[cfg(not(feature = "config"))]
use std::path::Path;
use std::path::PathBuf;
#[cfg(not(feature = "config"))]
use std::sync::Arc;
#[cfg(not(feature = "config"))]
use tls::config::ServerConfig;
#[cfg(not(feature = "config"))]
use tls::pki_types::pem::PemObject;
#[cfg(not(feature = "config"))]
use tls::pki_types::{CertificateDer, PrivateKeyDer};

/// Configuration for the server, represented as a map of server names to server configurations.
#[cfg(not(feature = "config"))]
pub struct Config<Middleware>(HashMap<Arc<str>, Server<Middleware>>);

#[cfg(not(feature = "config"))]
impl<T> Debug for Config<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.0.iter()).finish()
    }
}

#[cfg(not(feature = "config"))]
impl<Middleware> Deref for Config<Middleware> {
    type Target = HashMap<Arc<str>, Server<Middleware>>;

    /// Dereferences the `Config` to access the underlying `HashMap`.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(not(feature = "config"))]
impl<Middleware> DerefMut for Config<Middleware> {
    /// Dereferences the `Config` to access the underlying `HashMap` mutably.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(not(feature = "config"))]
fn build_middleware<'b>(
    analytics_channel: Option<Arc<Mutex<async_std::process::ChildStdin>>>,
    server_name: Arc<str>,
) -> impl for<'a> Service<&'a [u8], Error = MiddlewareError, Response = ()> + Clone + Send + use<'b>
{
    ServiceBuilder::new()
        .option_layer(analytics_channel.map(|channel| analytics(channel, server_name)))
        .build::<MiddlewareError>()
}

#[cfg(not(feature = "config"))]
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

        let python_exe = std::env::var("PYTHON").ok();
        let python = python_exe.as_deref().unwrap_or("python");
        let child = async_std::process::Command::new(python)
            .arg("db_writer.py")
            .stdin(async_std::process::Stdio::piped())
            .stdout(async_std::process::Stdio::null())
            .stderr(async_std::process::Stdio::null())
            .spawn();

        let analytics_channel = match child {
            Ok(mut child) => child.stdin.take(),
            Err(r) => {
                error!("Failed to spawn child process: {r}");
                None
            }
        };

        let analytics_channel = analytics_channel.map(|channel| Arc::new(Mutex::new(channel)));

        for server in servers {
            let helper::Server {
                server_name,
                ssl,
                load_balancer,
                upstreams,
            } = server;

            let server_name: Arc<str> = Arc::from(server_name.to_lowercase());

            let load_balancer: Box<dyn load_balancers::LoadBalancer> = match load_balancer {
                LoadBalancer::RoundRobin => Box::new(RoundRobin::from(upstreams)),
                LoadBalancer::LeastConnections => Box::new(LeastConnections::from(upstreams)),
                LoadBalancer::ResourceBased => Box::new(ResourceBased::from(upstreams)),
            };

            let middleware = build_middleware(analytics_channel.clone(), server_name.clone());

            map.insert(
                server_name,
                Server {
                    ssl,
                    load_balancer,
                    middleware,
                },
            );
        }

        Ok(Config(map))
    }
}

#[cfg(not(feature = "config"))]
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
#[cfg(not(feature = "config"))]
pub struct Server<Middleware> {
    /// Optional SSL configuration for the server.
    pub ssl: Option<SSLConfig>,
    /// Load balancer used by the server.
    pub load_balancer: Box<dyn load_balancers::LoadBalancer>,
    pub middleware: Middleware,
}

#[cfg(not(feature = "config"))]
impl<Middleware> Debug for Server<Middleware> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("ssl", &self.ssl)
            .field("load_balancer", &self.load_balancer)
            .finish()
    }
}

#[cfg(not(feature = "config"))]
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
#[derive(Debug, Deserialize, Serialize)]
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
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum LoadBalancer {
    RoundRobin,
    LeastConnections,
    ResourceBased,
}

impl ToString for LoadBalancer {
    fn to_string(&self) -> String {
        match self {
            LoadBalancer::RoundRobin => "RoundRobin",
            LoadBalancer::LeastConnections => "LeastConnections",
            LoadBalancer::ResourceBased => "ResouceBased",
        }
        .to_string()
    }
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

impl Serialize for Upstream {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Ok(self.addr.serialize(serializer)?)
    }
}

pub mod helper {
    use super::*;

    /// Helper struct for deserializing server configurations.
    #[derive(Debug, Deserialize, Serialize, Default)]
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
