use crate::crypto::provider::RSA_SCHEMES;
use crate::error::Error;
use crate::message::enums::{SignatureAlgorithm, SignatureScheme};
use ring::signature::{RsaEncoding, RsaKeyPair};
use rustls_pki_types::PrivateKeyDer;
use std::fmt::Debug;
use std::sync::Arc;

pub trait SigningKey: Debug + Send + Sync {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>>;
    fn algorithm(&self) -> SignatureAlgorithm;
}

pub trait Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;
    fn scheme(&self) -> SignatureScheme;
}

pub fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    if let Ok(rsa) = RSASigningKey::new(der) {
        return Ok(Arc::new(rsa));
    }

    Err(Error::General("Unsupported key type"))
}

#[derive(Debug)]
pub struct RSASigningKey {
    key: Arc<RsaKeyPair>,
}

impl RSASigningKey {
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
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        RSA_SCHEMES
            .iter()
            .find(|scheme| offered.contains(scheme))
            .map(|scheme| Box::new(RSASigner::new(self.key.clone(), *scheme)) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::rsa
    }
}

pub struct RSASigner {
    key: Arc<RsaKeyPair>,
    scheme: SignatureScheme,
    encoding: &'static dyn RsaEncoding,
}
impl RSASigner {
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
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut sig = vec![0; self.key.public().modulus_len()];
        let rng = ring::rand::SystemRandom::new();
        self.key
            .sign(self.encoding, &rng, message, &mut sig)
            .map(|_| sig)
            .map_err(|_| Error::General("Signing failed"))
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
