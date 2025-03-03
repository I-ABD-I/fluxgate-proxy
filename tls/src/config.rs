use crate::crypto;
use crate::crypto::provider::{default_provider, CryptoProvider};
use crate::state::ClientHello;
use log::debug;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

pub struct CertifiedKey {
    pub cert: Vec<CertificateDer<'static>>,
    pub key: Arc<dyn crypto::sign::SigningKey>,
}

impl ServerCertificateResolver for (Arc<CertifiedKey>,) {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}
pub trait ServerCertificateResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>>;
}
pub struct ServerConfig {
    pub provider: Arc<CryptoProvider>,
    pub cert_resolver: Arc<dyn ServerCertificateResolver>,
}

impl ServerConfig {
    // function only for testing will be removed,
    // so its fine cert resolver always resolves into a static certificate
    pub fn new() -> Self {
        let certs = CertificateDer::pem_file_iter("certificate.crt")
            .unwrap()
            .map(|cert| cert.unwrap())
            .collect();
        let key = PrivateKeyDer::from_pem_file("key.pem").unwrap();

        let key = crypto::sign::any_supported_type(&key).unwrap();

        Self {
            provider: Arc::new(default_provider()),
            cert_resolver: Arc::new((Arc::new(CertifiedKey { cert: certs, key }),)),
        }
    }
}
