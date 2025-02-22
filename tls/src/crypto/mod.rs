mod cipher;
pub mod hash;
pub mod kx;
pub mod provider;
pub mod sign;

use self::message::{enums::SignatureAlgorithm, hs::SignatureAndHashAlgorithm};
use crate::crypto::provider::SupportedCipherSuite;
use crate::error::{Error, GetRandomFailed};
use crate::message;
use cipher::AeadAlgorithm;
use hash::Hash;
use std::sync::Arc;
use crate::crypto::cipher::Prf;

pub trait SecureRandom {
    fn fill(&self, dest: &mut [u8]) -> Result<(), GetRandomFailed>;
}

pub trait KeyProvider {
    fn load_pk(&self) -> Result<Arc<dyn sign::SigningKey>, Error>;
}
#[derive(Clone, Copy, Debug)]
pub struct CipherSuite {
    pub suite: message::enums::CipherSuite,
    pub hash_provider: &'static dyn Hash,
    pub kx: kx::KeyExchangeAlgorithm,
    pub sign: &'static [SignatureAndHashAlgorithm],
    pub aead_algo: &'static dyn AeadAlgorithm,
    pub prf_provider: &'static dyn Prf,
}

impl CipherSuite {
    pub fn usable_for_signature_algorithm(&self, sigalg: SignatureAlgorithm) -> bool {
        self.sign.iter().any(|scheme| scheme.signature == sigalg)
    }

    pub fn usable_for_kx_algorithm(&self, kxalg: &kx::KeyExchangeAlgorithm) -> bool {
        self.kx == *kxalg
    }

    pub fn resolve_sig_schemes(
        &self,
        offered: &[SignatureAndHashAlgorithm],
    ) -> Vec<SignatureAndHashAlgorithm> {
        self.sign
            .iter()
            .filter(|pref| offered.contains(pref))
            .cloned()
            .collect()
    }
}

pub(crate) fn compatible_sigscheme_for_suites(
    sigscheme: SignatureAndHashAlgorithm,
    common_suites: &[SupportedCipherSuite],
) -> bool {
    let sigalg = sigscheme.signature;
    common_suites
        .iter()
        .any(|&suite| suite.0.usable_for_signature_algorithm(sigalg))
}
