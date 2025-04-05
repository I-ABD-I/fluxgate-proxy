use crate::crypto::cipher::{AeadKey, Prf};
use crate::crypto::kx::ActiveKx;
use crate::error::Error;
use std::fmt::Debug;
use std::thread::current;

/// A trait representing an HMAC (Hash-based Message Authentication Code) algorithm.
///
/// This trait provides a method to create a keyed HMAC instance.
pub trait Hmac: Sync + Debug {
    /// Creates a keyed HMAC instance.
    ///
    /// # Arguments
    ///
    /// * `key` - A slice of bytes representing the key.
    ///
    /// # Returns
    ///
    /// A boxed `Key` instance.
    fn with_key(&self, key: &[u8]) -> Box<dyn Key>;
}

/// A structure representing an HMAC tag.
///
/// This structure provides methods to create a new tag and to get the tag as a slice.
pub struct Tag {
    buf: [u8; Tag::MAX_SIZE],
    used: usize,
}

impl Tag {
    /// The maximum size of the tag buffer (64 bytes).
    const MAX_SIZE: usize = 64;

    /// Creates a new `Tag` from the given bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A slice of bytes representing the tag.
    ///
    /// # Returns
    ///
    /// A new `Tag` instance.
    pub fn new(bytes: &[u8]) -> Self {
        let mut tag = Self {
            buf: [0; Self::MAX_SIZE],
            used: bytes.len(),
        };

        tag.buf[..tag.used].copy_from_slice(bytes);
        tag
    }
}

impl Drop for Tag {
    /// Clears the tag buffer when the `Tag` is dropped.
    fn drop(&mut self) {
        unsafe {
            std::ptr::write_volatile(&mut self.buf, [0u8; Tag::MAX_SIZE]);
        }
    }
}

impl AsRef<[u8]> for Tag {
    /// Returns the tag as a slice of bytes.
    ///
    /// # Returns
    ///
    /// A slice of bytes representing the tag.
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

/// A trait representing a keyed HMAC instance.
///
/// This trait provides methods to sign data and to get the tag length.
pub trait Key: Sync {
    /// Signs the provided data.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of byte slices representing the data to sign.
    ///
    /// # Returns
    ///
    /// A `Tag` containing the HMAC result.
    fn sign(&self, data: &[&[u8]]) -> Tag;

    /// Returns the length of the tag.
    ///
    /// # Returns
    ///
    /// The length of the tag in bytes.
    fn tag_len(&self) -> usize;
}

/// A structure representing a PRF (Pseudo-Random Function) using HMAC.
///
/// This structure provides methods to generate keys for key exchange and secrets.
#[derive(Debug)]
pub struct PrfUsingHmac<'a>(pub &'a dyn Hmac);

impl Prf for PrfUsingHmac<'_> {
    /// Generates a key for key exchange.
    ///
    /// # Arguments
    ///
    /// * `output` - The output buffer.
    /// * `kx` - The active key exchange.
    /// * `peer_pub` - The peer's public key.
    /// * `label` - The label.
    /// * `seed` - The seed.
    ///
    /// # Returns
    ///
    /// A result indicating success or failure.
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKx>,
        peer_pub: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), Error> {
        prf(
            output,
            &*self.0.with_key(&kx.complete(peer_pub)?),
            label,
            seed,
        );
        Ok(())
    }

    /// Generates a secret.
    ///
    /// # Arguments
    ///
    /// * `output` - The output buffer.
    /// * `secret` - The secret.
    /// * `label` - The label.
    /// * `seed` - The seed.
    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
        prf(output, &*self.0.with_key(secret), label, seed);
    }
}

/// A function to perform the PRF (Pseudo-Random Function) using HMAC.
///
/// # Arguments
///
/// * `output` - The output buffer.
/// * `hmac` - The keyed HMAC instance.
/// * `label` - The label.
/// * `seed` - The seed.
fn prf(output: &mut [u8], hmac: &dyn Key, label: &[u8], seed: &[u8]) {
    let mut current_a = hmac.sign(&[label, seed]);
    for chunk in output.chunks_mut(hmac.tag_len()) {
        let p = hmac.sign(&[current_a.as_ref(), label, seed]);
        chunk.copy_from_slice(&p.as_ref()[..chunk.len()]);
        current_a = hmac.sign(&[current_a.as_ref()]);
    }
}
