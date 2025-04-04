use crate::crypto::cipher::AES128_GCM;
use crate::crypto::hash::SHA256;
use crate::crypto::hmac::PrfUsingHmac;
use crate::crypto::kx::{KeyExchangeAlgorithm, SupportedKxGroup, X25519};
use crate::crypto::sign::{any_supported_type, SigningKey};
use crate::crypto::SecureRandom;
use crate::error::{Error, GetRandomFailed};
use crate::message::enums::SignatureScheme;
use crate::{crypto, message};
use ring::hkdf::KeyType;
use rustls_pki_types::PrivateKeyDer;
use std::fmt::Debug;
use std::sync::Arc;

/// A structure representing a supported cipher suite.
///
/// This structure contains a reference to a `CipherSuite`.
#[derive(Copy, Clone, Debug)]
pub struct SupportedCipherSuite(pub(crate) &'static crypto::CipherSuite);

/// A structure representing a cryptographic provider.
///
/// This structure contains vectors of supported cipher suites and key exchange groups,
/// and references to a secure random number generator and a key provider.
pub struct CryptoProvider {
    /// A vector of supported cipher suites.
    pub cipher_suites: Vec<SupportedCipherSuite>,
    /// A vector of supported key exchange groups.
    pub kx_groups: Vec<&'static dyn SupportedKxGroup>,
    /// A reference to a secure random number generator.
    pub random: &'static dyn SecureRandom,
    /// A reference to a key provider.
    pub key_provider: &'static dyn crypto::KeyProvider,
}

/// Returns the default cryptographic provider.
///
/// This function initializes and returns a `CryptoProvider` with default cipher suites,
/// key exchange groups, a secure random number generator, and a key provider.
///
/// # Returns
///
/// A `CryptoProvider` instance.
pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: DEFAULT_CIPHER_SUITES.to_vec(),
        kx_groups: DEFAULT_KX_GROUPS.to_vec(),
        random: &Ring,
        key_provider: &Ring,
    }
}

/// A structure representing the Ring cryptographic provider.
///
/// This structure implements the `SecureRandom` and `KeyProvider` traits.
#[derive(Copy, Clone, Debug)]
struct Ring;

impl SecureRandom for Ring {
    /// Fills the provided destination buffer with random bytes.
    ///
    /// # Arguments
    ///
    /// * `dest` - A mutable slice where the random bytes will be written.
    ///
    /// # Errors
    ///
    /// Returns a `GetRandomFailed` error if the random number generation fails.
    fn fill(&self, dest: &mut [u8]) -> Result<(), GetRandomFailed> {
        use ring::rand::SecureRandom;

        ring::rand::SystemRandom::new()
            .fill(dest)
            .map_err(|_| GetRandomFailed)
    }
}

impl crypto::KeyProvider for Ring {
    /// Loads a private key.
    ///
    /// # Arguments
    ///
    /// * `private_key_der` - A DER-encoded private key.
    ///
    /// # Errors
    ///
    /// Returns an `Error` if the key loading fails.
    fn load_pk(
        &self,
        private_key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        any_supported_type(&private_key_der)
    }
}

/// A static array of supported RSA signature schemes.
pub static RSA_SCHEMES: &[SignatureScheme] = &[SignatureScheme::RSA_PSS_SHA512];

/// A static array of default supported cipher suites.
static DEFAULT_CIPHER_SUITES: &[crypto::SupportedCipherSuite] =
    &[SupportedCipherSuite(&crypto::CipherSuite {
        suite: message::enums::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        hash_provider: &SHA256,
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: RSA_SCHEMES,
        aead_algo: &AES128_GCM,
        prf_provider: &PrfUsingHmac(&Hmac(ring::hmac::HMAC_SHA256)),
    })];

/// A structure representing an HMAC algorithm.
///
/// This structure provides a method to create a keyed HMAC instance.
#[derive(Debug)]
struct Hmac(ring::hmac::Algorithm);

impl crypto::hmac::Hmac for Hmac {
    /// Creates a keyed HMAC instance.
    ///
    /// # Arguments
    ///
    /// * `key` - A slice of bytes representing the key.
    ///
    /// # Returns
    ///
    /// A boxed `Key` instance.
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(Key(ring::hmac::Key::new(self.0, key)))
    }
}

/// A structure representing a keyed HMAC instance.
///
/// This structure provides methods to sign data and to get the tag length.
struct Key(ring::hmac::Key);

impl crypto::hmac::Key for Key {
    /// Signs the provided data.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of byte slices representing the data to sign.
    ///
    /// # Returns
    ///
    /// A `Tag` containing the HMAC result.
    fn sign(&self, data: &[&[u8]]) -> crypto::hmac::Tag {
        let mut cx = ring::hmac::Context::with_key(&self.0);
        data.iter().for_each(|slice| cx.update(slice));
        crypto::hmac::Tag::new(cx.sign().as_ref())
    }

    /// Returns the length of the tag.
    ///
    /// # Returns
    ///
    /// The length of the tag in bytes.
    fn tag_len(&self) -> usize {
        self.0.algorithm().len()
    }
}

/// A static array of default supported key exchange groups.
static DEFAULT_KX_GROUPS: &[&'static dyn SupportedKxGroup] = &[&X25519];
