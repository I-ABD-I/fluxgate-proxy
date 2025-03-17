use crate::crypto::cipher::AES128_GCM;
use crate::crypto::hash::SHA256;
use crate::crypto::hmac::PrfUsingHmac;
use crate::crypto::kx::{KeyExchangeAlgorithm, SupportedKxGroup, X25519};
use crate::crypto::sign::{any_supported_type, SigningKey};
use crate::crypto::SecureRandom;
use crate::error::{Error, GetRandomFailed};
use crate::message::enums::{SignatureAlgorithm, SignatureScheme};
use crate::message::hs::SignatureAndHashAlgorithm;
use crate::{crypto, message};
use ring::hkdf::KeyType;
use std::fmt::Debug;
use std::sync::Arc;
use rustls_pki_types::PrivateKeyDer;

#[derive(Copy, Clone, Debug)]
pub struct SupportedCipherSuite(pub(crate) &'static crypto::CipherSuite);
#[derive(Debug)]

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
#[derive(Copy, Clone, Debug)]
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
    fn load_pk(&self, private_key_der: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        any_supported_type(&private_key_der)
    }
}

pub static RSA_SCHEMES: &[SignatureScheme] = &[SignatureScheme::RSA_PSS_SHA512];

static DEFAULT_CIPHER_SUITES: &[crypto::SupportedCipherSuite] =
    &[SupportedCipherSuite(&crypto::CipherSuite {
        suite: message::enums::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        hash_provider: &SHA256,
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: RSA_SCHEMES,
        aead_algo: &AES128_GCM,
        prf_provider: &PrfUsingHmac(&Hmac(ring::hmac::HMAC_SHA256)),
    })];

#[derive(Debug)]
struct Hmac(ring::hmac::Algorithm);

impl crypto::hmac::Hmac for Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(Key(ring::hmac::Key::new(self.0, key)))
    }
}

struct Key(ring::hmac::Key);
impl crypto::hmac::Key for Key {
    fn sign(&self, data: &[&[u8]]) -> crypto::hmac::Tag {
        let mut cx = ring::hmac::Context::with_key(&self.0);
        data.iter().for_each(|slice| cx.update(slice));
        crypto::hmac::Tag::new(cx.sign().as_ref())
    }

    fn tag_len(&self) -> usize {
        self.0.algorithm().len()
    }
}

static DEFAULT_KX_GROUPS: &[&'static dyn SupportedKxGroup] = &[&X25519];
