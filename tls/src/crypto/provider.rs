use crate::crypto::cipher::AES128_GCM;
use crate::crypto::hash::SHA256;
use crate::crypto::kx::{KeyExchangeAlgorithm, SupportedKxGroup, X25519};
use crate::crypto::sign::SigningKey;
use crate::crypto::SecureRandom;
use crate::error::{Error, GetRandomFailed};
use crate::message::enums::SignatureAlgorithm;
use crate::message::hs::SignatureAndHashAlgorithm;
use crate::{crypto, message};
use std::sync::Arc;

#[derive(Copy, Clone, Debug)]
pub struct SupportedCipherSuite(pub(crate) &'static crypto::CipherSuite);
pub struct CryptoProvider {
    pub cipher_suites: Vec<SupportedCipherSuite>,
    pub kx_groups: Vec<&'static dyn SupportedKxGroup>,
    pub random: &'static dyn SecureRandom,
    pub key_provider: &'static dyn crypto::KeyProvider,
}

pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: DEFAULT_CIPHER_SUITES.to_vec(),
        kx_groups: DEFAULT_KX_GROUPS.to_vec(),
        random: &Ring,
        key_provider: &Ring,
    }
}

struct Ring;

impl SecureRandom for Ring {
    fn fill(&self, dest: &mut [u8]) -> Result<(), GetRandomFailed> {
        use ring::rand::SecureRandom;

        ring::rand::SystemRandom::new()
            .fill(dest)
            .map_err(|_| GetRandomFailed)
    }
}

impl crypto::KeyProvider for Ring {
    fn load_pk(&self) -> Result<Arc<dyn SigningKey>, Error> {
        todo!()
    }
}

pub static RSA_SCHEMES: &[SignatureAndHashAlgorithm] = &[SignatureAndHashAlgorithm {
    hash: message::enums::HashAlgorithm::sha256,
    signature: SignatureAlgorithm::rsa,
}];

static DEFAULT_CIPHER_SUITES: &[crypto::SupportedCipherSuite] =
    &[SupportedCipherSuite(&crypto::CipherSuite {
        suite: message::enums::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        hash_provider: &SHA256,
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: RSA_SCHEMES,
        aead_algo: &AES128_GCM,
    })];

static DEFAULT_KX_GROUPS: &[&'static dyn SupportedKxGroup] = &[&X25519];
