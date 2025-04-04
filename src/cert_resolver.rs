use std::collections::HashMap;
use std::sync::Arc;
use tls::config::{CertifiedKey, ServerCertificateResolver};
use tls::state::ClientHello;

pub struct CertificateResolver {
    certificates: HashMap<String, Arc<CertifiedKey>>,
}

impl ServerCertificateResolver for CertificateResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let key = self
            .certificates
            .get(client_hello.sni().as_ref()?.as_ref())?;
        Some(key.clone())
    }
}

impl CertificateResolver {
    pub fn new() -> Self {
        Self {
            certificates: HashMap::new(),
        }
    }

    pub fn add_certificate(&mut self, name: String, cert: Arc<CertifiedKey>) {
        self.certificates.insert(name.to_lowercase(), cert);
    }
}
