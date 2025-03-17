pub mod cipher;
pub mod hash;
pub mod hmac;
pub mod kx;
pub mod provider;
pub mod sign;

use self::message::enums::SignatureAlgorithm;
use crate::crypto::cipher::Prf;
use crate::crypto::provider::SupportedCipherSuite;
use crate::error::{Error, GetRandomFailed};
use crate::message;
use crate::message::enums::SignatureScheme;
use cipher::AeadAlgorithm;
use hash::Hash;
use rustls_pki_types::PrivateKeyDer;
use std::fmt::Debug;
use std::sync::Arc;

pub trait SecureRandom: Send + Sync {
    fn fill(&self, dest: &mut [u8]) -> Result<(), GetRandomFailed>;
}

pub trait KeyProvider: Send + Sync {
    fn load_pk(&self, key_der: PrivateKeyDer<'static>) -> Result<Arc<dyn sign::SigningKey>, Error>;
}
#[derive(Clone, Copy, Debug)]
pub struct CipherSuite {
    pub suite: message::enums::CipherSuite,
    pub hash_provider: &'static dyn Hash,
    pub kx: kx::KeyExchangeAlgorithm,
    pub sign: &'static [SignatureScheme],
    pub aead_algo: &'static dyn AeadAlgorithm,
    pub prf_provider: &'static dyn Prf,
}

impl CipherSuite {
    pub fn usable_for_signature_algorithm(&self, sigalg: SignatureAlgorithm) -> bool {
        self.sign.iter().any(|scheme| scheme.algorithm() == sigalg)
    }

    pub fn usable_for_kx_algorithm(&self, kxalg: &kx::KeyExchangeAlgorithm) -> bool {
        self.kx == *kxalg
    }

    pub fn resolve_sig_schemes(&self, offered: &[SignatureScheme]) -> Vec<SignatureScheme> {
        self.sign
            .iter()
            .filter(|pref| offered.contains(pref))
            .cloned()
            .collect()
    }
}

pub(crate) fn compatible_sigscheme_for_suites(
    sigscheme: SignatureScheme,
    common_suites: &[SupportedCipherSuite],
) -> bool {
    let sigalg = sigscheme.algorithm();
    common_suites
        .iter()
        .any(|&suite| suite.0.usable_for_signature_algorithm(sigalg))
}
