use super::message::enums::HashAlgorithm;
use std::fmt::Debug;

/// A trait representing a hash function.
///
/// This trait provides methods to start a new hash context, hash data, get the hash algorithm,
/// and get the output length of the hash.
pub trait Hash: Sync + Debug {
    /// Starts a new hash context.
    ///
    /// # Returns
    ///
    /// A boxed `Context` for the hash.
    fn start(&self) -> Box<dyn Context>;

    /// Hashes the provided data.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of data to hash.
    ///
    /// # Returns
    ///
    /// An `Output` containing the hash result.
    fn hash(&self, data: &[u8]) -> Output;

    /// Returns the hash algorithm.
    ///
    /// # Returns
    ///
    /// The `HashAlgorithm` used.
    fn algorithm(&self) -> HashAlgorithm;

    /// Returns the output length of the hash.
    ///
    /// # Returns
    ///
    /// The length of the hash output in bytes.
    fn output_length(&self) -> usize;
}

/// A structure representing the output of a hash function.
///
/// This structure contains a buffer for the hash result and the number of bytes used.
pub struct Output {
    buf: [u8; Output::MAX_SIZE],
    used: usize,
}

impl Output {
    /// Creates a new `Output` from the given buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - A slice of bytes containing the hash result.
    ///
    /// # Returns
    ///
    /// A new `Output` instance.
    pub fn new(buf: &[u8]) -> Self {
        let mut output = Self {
            buf: [0u8; Self::MAX_SIZE],
            used: buf.len(),
        };
        output.buf[..buf.len()].copy_from_slice(buf);
        output
    }

    /// The maximum size of the output buffer (64 bytes for SHA-512).
    const MAX_SIZE: usize = 64;
}

impl AsRef<[u8]> for Output {
    /// Returns the output as a slice of bytes.
    ///
    /// # Returns
    ///
    /// A slice of bytes containing the hash result.
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

/// A trait representing a hash context.
///
/// This trait provides methods to finish the hash, update the hash with data, and fork the hash context.
pub trait Context: Send + Sync {
    /// Finishes the hash and returns the result.
    ///
    /// # Returns
    ///
    /// An `Output` containing the hash result.
    fn finish(self: Box<Self>) -> Output;

    /// Updates the hash with the provided data.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of data to update the hash with.
    fn update(&mut self, data: &[u8]);

    /// Forks the hash context and finishes the forked context.
    ///
    /// # Returns
    ///
    /// An `Output` containing the hash result of the forked context.
    fn fork_finish(&self) -> Output;
}

impl Context for ring::digest::Context {
    /// Finishes the hash and returns the result.
    ///
    /// # Returns
    ///
    /// An `Output` containing the hash result.
    fn finish(self: Box<Self>) -> Output {
        let digest = ring::digest::Context::finish(*self);
        Output::new(digest.as_ref())
    }

    /// Updates the hash with the provided data.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of data to update the hash with.
    fn update(&mut self, data: &[u8]) {
        ring::digest::Context::update(self, data);
    }

    /// Forks the hash context and finishes the forked context.
    ///
    /// # Returns
    ///
    /// An `Output` containing the hash result of the forked context.
    fn fork_finish(&self) -> Output {
        Output::new(self.clone().finish().as_ref())
    }
}

/// A structure representing a SHA hash algorithm.
///
/// This structure provides methods to start a new hash context, hash data, get the hash algorithm,
/// and get the output length of the hash.
#[derive(Debug)]
pub(crate) struct Sha(&'static ring::digest::Algorithm, HashAlgorithm);

impl Hash for Sha {
    /// Starts a new hash context.
    ///
    /// # Returns
    ///
    /// A boxed `Context` for the hash.
    fn start(&self) -> Box<dyn Context> {
        Box::new(ring::digest::Context::new(self.0))
    }

    /// Hashes the provided data.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of data to hash.
    ///
    /// # Returns
    ///
    /// An `Output` containing the hash result.
    fn hash(&self, data: &[u8]) -> Output {
        let mut cx = ring::digest::Context::new(self.0);
        cx.update(data);
        Output::new(cx.finish().as_ref())
    }

    /// Returns the hash algorithm.
    ///
    /// # Returns
    ///
    /// The `HashAlgorithm` used.
    fn algorithm(&self) -> HashAlgorithm {
        self.1
    }

    /// Returns the output length of the hash.
    ///
    /// # Returns
    ///
    /// The length of the hash output in bytes.
    fn output_length(&self) -> usize {
        self.0.output_len()
    }
}

/// A static instance of the SHA-256 hash algorithm.
pub(crate) static SHA256: Sha = Sha(&ring::digest::SHA256, HashAlgorithm::sha256);