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

/// A trait representing a secure random number generator.
///
/// This trait is used to fill a destination buffer with random bytes.
/// It is required to be thread-safe (`Send` and `Sync`).
pub trait SecureRandom: Send + Sync {
    /// Fills the provided destination buffer with random bytes.
    ///
    /// # Arguments
    ///
    /// * `dest` - A mutable slice where the random bytes will be written.
    ///
    /// # Errors
    ///
    /// Returns a `GetRandomFailed` error if the random number generation fails.
    fn fill(&self, dest: &mut [u8]) -> Result<(), GetRandomFailed>;
}

/// A trait for providing cryptographic keys.
///
/// This trait is used to load a private key from its DER-encoded form.
pub trait KeyProvider: Send + Sync {
    /// Loads a private key.
    ///
    /// # Arguments
    ///
    /// * `key_der` - A DER-encoded private key.
    ///
    /// # Errors
    ///
    /// Returns an `Error` if the key loading fails.
    fn load_pk(&self, key_der: PrivateKeyDer<'static>) -> Result<Arc<dyn sign::SigningKey>, Error>;
}

/// A structure representing a cipher suite.
///
/// This structure contains various cryptographic algorithms and parameters
/// used in a cipher suite.
#[derive(Clone, Copy, Debug)]
pub struct CipherSuite {
    /// The cipher suite identifier.
    pub suite: message::enums::CipherSuite,
    /// The hash provider.
    pub hash_provider: &'static dyn Hash,
    /// The key exchange algorithm.
    pub kx: kx::KeyExchangeAlgorithm,
    /// The supported signature schemes.
    pub sign: &'static [SignatureScheme],
    /// The AEAD algorithm.
    pub aead_algo: &'static dyn AeadAlgorithm,
    /// The PRF provider.
    pub prf_provider: &'static dyn Prf,
}

impl CipherSuite {
    /// Checks if the cipher suite is usable for a given signature algorithm.
    ///
    /// # Arguments
    ///
    /// * `sigalg` - The signature algorithm to check.
    ///
    /// # Returns
    ///
    /// `true` if the cipher suite is usable for the given signature algorithm, `false` otherwise.
    pub fn usable_for_signature_algorithm(&self, sigalg: SignatureAlgorithm) -> bool {
        self.sign.iter().any(|scheme| scheme.algorithm() == sigalg)
    }

    /// Checks if the cipher suite is usable for a given key exchange algorithm.
    ///
    /// # Arguments
    ///
    /// * `kxalg` - The key exchange algorithm to check.
    ///
    /// # Returns
    ///
    /// `true` if the cipher suite is usable for the given key exchange algorithm, `false` otherwise.
    pub fn usable_for_kx_algorithm(&self, kxalg: &kx::KeyExchangeAlgorithm) -> bool {
        self.kx == *kxalg
    }

    /// Resolves the supported signature schemes from the offered ones.
    ///
    /// # Arguments
    ///
    /// * `offered` - A slice of offered signature schemes.
    ///
    /// # Returns
    ///
    /// A vector of supported signature schemes.
    pub fn resolve_sig_schemes(&self, offered: &[SignatureScheme]) -> Vec<SignatureScheme> {
        self.sign
            .iter()
            .filter(|pref| offered.contains(pref))
            .cloned()
            .collect()
    }
}

/// Checks if a signature scheme is compatible with the given cipher suites.
///
/// # Arguments
///
/// * `sigscheme` - The signature scheme to check.
/// * `common_suites` - A slice of supported cipher suites.
///
/// # Returns
///
/// `true` if the signature scheme is compatible with any of the given cipher suites, `false` otherwise.
pub(crate) fn compatible_sigscheme_for_suites(
    sigscheme: SignatureScheme,
    common_suites: &[SupportedCipherSuite],
) -> bool {
    let sigalg = sigscheme.algorithm();
    common_suites
        .iter()
        .any(|&suite| suite.0.usable_for_signature_algorithm(sigalg))
}
