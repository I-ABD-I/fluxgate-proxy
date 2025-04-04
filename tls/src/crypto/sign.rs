use crate::crypto::provider::RSA_SCHEMES;
use crate::error::Error;
use crate::message::enums::{SignatureAlgorithm, SignatureScheme};
use ring::signature::{RsaEncoding, RsaKeyPair};
use rustls_pki_types::PrivateKeyDer;
use std::fmt::Debug;
use std::sync::Arc;

/// A trait representing a signing key.
///
/// This trait provides methods to choose a signature scheme and to get the algorithm.
pub trait SigningKey: Debug + Send + Sync {
    /// Chooses a signature scheme from the offered schemes.
    ///
    /// # Arguments
    ///
    /// * `offered` - A slice of offered `SignatureScheme`s.
    ///
    /// # Returns
    ///
    /// An optional boxed `Signer`.
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>>;

    /// Returns the signature algorithm.
    ///
    /// # Returns
    ///
    /// The `SignatureAlgorithm` used.
    fn algorithm(&self) -> SignatureAlgorithm;
}

/// A trait representing a signer.
///
/// This trait provides methods to sign a message and to get the signature scheme.
pub trait Signer {
    /// Signs the provided message.
    ///
    /// # Arguments
    ///
    /// * `message` - A slice of bytes representing the message to sign.
    ///
    /// # Returns
    ///
    /// A result containing a vector of bytes or an error.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;

    /// Returns the signature scheme.
    ///
    /// # Returns
    ///
    /// The `SignatureScheme` used.
    fn scheme(&self) -> SignatureScheme;
}

/// Attempts to create a signing key from the provided DER-encoded private key.
///
/// # Arguments
///
/// * `der` - A reference to a `PrivateKeyDer`.
///
/// # Returns
///
/// A result containing an `Arc` to a `SigningKey` or an error.
pub fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    if let Ok(rsa) = RSASigningKey::new(der) {
        return Ok(Arc::new(rsa));
    }

    Err(Error::General("Unsupported key type"))
}

/// A structure representing an RSA signing key.
///
/// This structure provides methods to create a new RSA signing key and to implement the `SigningKey` trait.
#[derive(Debug)]
pub struct RSASigningKey {
    key: Arc<RsaKeyPair>,
}

impl RSASigningKey {
    /// Creates a new `RSASigningKey` from the provided DER-encoded private key.
    ///
    /// # Arguments
    ///
    /// * `der` - A reference to a `PrivateKeyDer`.
    ///
    /// # Returns
    ///
    /// A result containing an `RSASigningKey` or an error.
    pub fn new(der: &PrivateKeyDer<'_>) -> Result<Self, Error> {
        let pair = match der {
            PrivateKeyDer::Pkcs1(pkcs1) => RsaKeyPair::from_der(pkcs1.secret_pkcs1_der()),
            PrivateKeyDer::Pkcs8(pkcs8) => RsaKeyPair::from_pkcs8(pkcs8.secret_pkcs8_der()),
            _ => return Err(Error::General("Invalid RSA key")),
        }
        .map_err(|_| Error::General("Invalid RSA key"))?;

        Ok(Self {
            key: Arc::new(pair),
        })
    }
}

impl SigningKey for RSASigningKey {
    /// Chooses a signature scheme from the offered schemes.
    ///
    /// # Arguments
    ///
    /// * `offered` - A slice of offered `SignatureScheme`s.
    ///
    /// # Returns
    ///
    /// An optional boxed `Signer`.
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        RSA_SCHEMES
            .iter()
            .find(|scheme| offered.contains(scheme))
            .map(|scheme| Box::new(RSASigner::new(self.key.clone(), *scheme)) as Box<dyn Signer>)
    }

    /// Returns the signature algorithm.
    ///
    /// # Returns
    ///
    /// The `SignatureAlgorithm` used.
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::rsa
    }
}

/// A structure representing an RSA signer.
///
/// This structure provides methods to create a new RSA signer and to implement the `Signer` trait.
pub struct RSASigner {
    key: Arc<RsaKeyPair>,
    scheme: SignatureScheme,
    encoding: &'static dyn RsaEncoding,
}

impl RSASigner {
    /// Creates a new `RSASigner` with the provided key and scheme.
    ///
    /// # Arguments
    ///
    /// * `key` - An `Arc` to an `RsaKeyPair`.
    /// * `scheme` - The `SignatureScheme` to use.
    ///
    /// # Returns
    ///
    /// A new `RSASigner` instance.
    fn new(key: Arc<RsaKeyPair>, scheme: SignatureScheme) -> Self {
        use ring::signature;

        let encoding: &dyn signature::RsaEncoding = match scheme {
            SignatureScheme::RSA_PKCS1_SHA256 => &signature::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384 => &signature::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512 => &signature::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256 => &signature::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384 => &signature::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512 => &signature::RSA_PSS_SHA512,
            _ => unreachable!(),
        };

        Self {
            key,
            scheme,
            encoding,
        }
    }
}

impl Signer for RSASigner {
    /// Signs the provided message.
    ///
    /// # Arguments
    ///
    /// * `message` - A slice of bytes representing the message to sign.
    ///
    /// # Returns
    ///
    /// A result containing a vector of bytes or an error.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut sig = vec![0; self.key.public().modulus_len()];
        let rng = ring::rand::SystemRandom::new();
        self.key
            .sign(self.encoding, &rng, message, &mut sig)
            .map(|_| sig)
            .map_err(|_| Error::General("Signing failed"))
    }

    /// Returns the signature scheme.
    ///
    /// # Returns
    ///
    /// The `SignatureScheme` used.
    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
