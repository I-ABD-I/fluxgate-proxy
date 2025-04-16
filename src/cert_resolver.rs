use std::collections::HashMap;
use std::sync::Arc;
use tls::config::{CertifiedKey, ServerCertificateResolver};
use tls::state::ClientHello;

/// A resolver for server certificates based on the SNI (Server Name Indication).
///
/// # Fields
/// * `certificates` - A map of domain names to their corresponding certified keys.
pub struct CertificateResolver {
    certificates: HashMap<String, Arc<CertifiedKey>>,
}

impl ServerCertificateResolver for CertificateResolver {
    /// Resolves the server certificate for a given client hello message.
    ///
    /// # Arguments
    /// * `client_hello` - The client hello message containing the SNI.
    ///
    /// # Returns
    /// An optional `Arc<CertifiedKey>` if a matching certificate is found.
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let key = self
            .certificates
            .get(client_hello.sni().as_ref()?.as_ref())?;
        Some(key.clone())
    }
}

impl Default for CertificateResolver {
    /// Creates a default instance of `CertificateResolver`.
    ///
    /// # Returns
    /// A new instance of `CertificateResolver` with an empty certificate map.
    fn default() -> Self {
        Self::new()
    }
}
impl CertificateResolver {
    /// Creates a new `CertificateResolver`.
    ///
    /// # Returns
    /// A new instance of `CertificateResolver`.
    pub fn new() -> Self {
        Self {
            certificates: HashMap::new(),
        }
    }

    /// Adds a certificate to the resolver.
    ///
    /// # Arguments
    /// * `name` - The domain name for the certificate.
    /// * `cert` - The certified key for the domain.
    pub fn add_certificate(&mut self, name: String, cert: Arc<CertifiedKey>) {
        self.certificates.insert(name.to_lowercase(), cert);
    }
}
