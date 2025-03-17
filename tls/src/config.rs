use crate::crypto;
use crate::crypto::provider::{default_provider, CryptoProvider};
use crate::crypto::sign::SigningKey;
use crate::error::Error;
use crate::state::ClientHello;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Debug)]
pub struct CertifiedKey {
    pub cert: Vec<CertificateDer<'static>>,
    pub key: Arc<dyn crypto::sign::SigningKey>,
}

impl CertifiedKey {
    /// does not notify about mismatched keys!!!
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

    pub fn new(cert: Vec<CertificateDer<'static>>, key: Arc<dyn SigningKey>) -> Self {
        Self { cert, key }
    }
}

pub trait ServerCertificateResolver: Debug {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>>;
}
#[derive(Debug)]
struct SingleCertificateResolver(Arc<CertifiedKey>);

impl ServerCertificateResolver for SingleCertificateResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

impl From<CertifiedKey> for SingleCertificateResolver {
    fn from(c: CertifiedKey) -> Self {
        Self(Arc::new(c))
    }
}

#[derive(Debug)]

pub struct ServerConfig {
    pub provider: Arc<CryptoProvider>,
    pub cert_resolver: Arc<dyn ServerCertificateResolver>,
}

impl ServerConfig {
    // uses default provider
    pub fn builder() -> ConfigBuilder<WantsServerCertificateResolver> {
        ConfigBuilder {
            state: WantsServerCertificateResolver,
            provider: Arc::new(default_provider()),
        }
    }
}

pub struct ConfigBuilder<State> {
    state: State,
    provider: Arc<CryptoProvider>,
}

pub struct WantsServerCertificateResolver;

impl ConfigBuilder<WantsServerCertificateResolver> {
    pub fn with_single_certificate(
        self,
        certificate_chain: Vec<CertificateDer<'static>>,
        private_key_der: PrivateKeyDer<'static>,
    ) -> Result<ServerConfig, Error> {
        let certified_key =
            CertifiedKey::from_der(certificate_chain, private_key_der, &self.provider)?;
        Ok(self.with_cert_resolver(Arc::new(SingleCertificateResolver::from(certified_key))))
    }

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
