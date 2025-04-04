use crate::crypto;
use crate::crypto::provider::{default_provider, CryptoProvider};
use crate::crypto::sign::SigningKey;
use crate::error::Error;
use crate::state::ClientHello;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fmt::Debug;
use std::sync::Arc;

/// Represents a certified key with a certificate and a signing key.
#[derive(Debug)]
pub struct CertifiedKey {
    /// The certificate chain.
    pub cert: Vec<CertificateDer<'static>>,
    /// The signing key.
    pub key: Arc<dyn crypto::sign::SigningKey>,
}

impl CertifiedKey {
    /// Creates a `CertifiedKey` from DER-encoded certificate and private key.
    ///
    /// # Arguments
    /// * `certificate_chain` - The certificate chain.
    /// * `private_key_der` - The DER-encoded private key.
    /// * `provider` - The cryptographic provider.
    ///
    /// # Returns
    /// * `Result<Self, Error>` - The created `CertifiedKey` or an error.
    ///
    /// # Note
    /// This function does not notify about mismatched keys.
    pub fn from_der(
        certificate_chain: Vec<CertificateDer<'static>>,
        private_key_der: PrivateKeyDer<'static>,
        provider: &CryptoProvider,
    ) -> Result<Self, Error> {
        let private_key = provider.key_provider.load_pk(private_key_der)?;
        let certified_key = CertifiedKey {
            key: private_key,
            cert: certificate_chain,
        };

        Ok(certified_key)
    }

    /// Creates a new `CertifiedKey` with the given certificate and signing key.
    ///
    /// # Arguments
    /// * `cert` - The certificate chain.
    /// * `key` - The signing key.
    ///
    /// # Returns
    /// * `Self` - The new `CertifiedKey` instance.
    pub fn new(cert: Vec<CertificateDer<'static>>, key: Arc<dyn SigningKey>) -> Self {
        Self { cert, key }
    }
}

/// Trait for resolving server certificates.
pub trait ServerCertificateResolver: Send + Sync {
    /// Resolves a server certificate for the given client hello message.
    ///
    /// # Arguments
    /// * `client_hello` - The client hello message.
    ///
    /// # Returns
    /// * `Option<Arc<CertifiedKey>>` - The resolved certified key or `None`.
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>>;
}

/// Represents a resolver for a single certificate.
#[derive(Debug)]
struct SingleCertificateResolver(Arc<CertifiedKey>);

impl ServerCertificateResolver for SingleCertificateResolver {
    /// Resolves the single certificate for any client hello message.
    ///
    /// # Arguments
    /// * `client_hello` - The client hello message.
    ///
    /// # Returns
    /// * `Option<Arc<CertifiedKey>>` - The resolved certified key.
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

impl From<CertifiedKey> for SingleCertificateResolver {
    /// Creates a `SingleCertificateResolver` from a `CertifiedKey`.
    ///
    /// # Arguments
    /// * `c` - The certified key.
    ///
    /// # Returns
    /// * `Self` - The new `SingleCertificateResolver` instance.
    fn from(c: CertifiedKey) -> Self {
        Self(Arc::new(c))
    }
}

/// Represents the server configuration.
pub struct ServerConfig {
    /// The cryptographic provider.
    pub provider: Arc<CryptoProvider>,
    /// The certificate resolver.
    pub cert_resolver: Arc<dyn ServerCertificateResolver>,
}

impl ServerConfig {
    /// Creates a new `ConfigBuilder` with the default provider.
    ///
    /// # Returns
    /// * `ConfigBuilder<WantsServerCertificateResolver>` - The new `ConfigBuilder` instance.
    pub fn builder() -> ConfigBuilder<WantsServerCertificateResolver> {
        ConfigBuilder {
            state: WantsServerCertificateResolver,
            provider: Arc::new(default_provider()),
        }
    }
}

/// Represents a builder for server configuration.
pub struct ConfigBuilder<State> {
    state: State,
    provider: Arc<CryptoProvider>,
}

impl<State> ConfigBuilder<State> {
    /// Returns the cryptographic provider.
    ///
    /// # Returns
    /// * `&Arc<CryptoProvider>` - The cryptographic provider.
    pub fn provider(&self) -> &Arc<CryptoProvider> {
        &self.provider
    }
}

/// Represents the state where the server certificate resolver is needed.
pub struct WantsServerCertificateResolver;

impl ConfigBuilder<WantsServerCertificateResolver> {
    /// Adds a single certificate to the server configuration.
    ///
    /// # Arguments
    /// * `certificate_chain` - The certificate chain.
    /// * `private_key_der` - The DER-encoded private key.
    ///
    /// # Returns
    /// * `Result<ServerConfig, Error>` - The server configuration or an error.
    pub fn with_single_certificate(
        self,
        certificate_chain: Vec<CertificateDer<'static>>,
        private_key_der: PrivateKeyDer<'static>,
    ) -> Result<ServerConfig, Error> {
        let certified_key =
            CertifiedKey::from_der(certificate_chain, private_key_der, &self.provider)?;
        Ok(self.with_cert_resolver(Arc::new(SingleCertificateResolver::from(certified_key))))
    }

    /// Adds a certificate resolver to the server configuration.
    ///
    /// # Arguments
    /// * `cert_resolver` - The certificate resolver.
    ///
    /// # Returns
    /// * `ServerConfig` - The server configuration.
    pub fn with_cert_resolver(
        self,
        cert_resolver: Arc<dyn ServerCertificateResolver>,
    ) -> ServerConfig {
        ServerConfig {
            provider: self.provider,
            cert_resolver,
        }
    }
}