use crate::codec::Codec;
use crate::crypto::hash;
use crate::crypto::hash::Output;
use crate::message::{Message, MessagePayload};

/// Represents the hash of a TLS handshake.
pub struct HandshakeHash {
    /// The hash provider.
    pub provider: &'static dyn hash::Hash,
    /// The hash context.
    pub ctx: Box<dyn hash::Context>,
}

impl HandshakeHash {
    /// Starts a new handshake hash with the given provider.
    ///
    /// # Arguments
    /// * `provider` - The hash provider.
    ///
    /// # Returns
    /// A new `HandshakeHash` instance.
    pub(crate) fn start_hash(provider: &'static dyn hash::Hash) -> Self {
        let ctx = provider.start();
        Self { provider, ctx }
    }

    /// Adds a message to the handshake hash.
    ///
    /// # Arguments
    /// * `m` - The message to add.
    ///
    /// # Returns
    /// A mutable reference to the `HandshakeHash`.
    pub(crate) fn add_message(&mut self, m: &Message<'_>) -> &mut Self {
        match &m.payload {
            MessagePayload::HandshakePayload(payload) => self.add_raw(&payload.get_encoding()),
            _ => self,
        }
    }

    /// Adds raw data to the handshake hash.
    ///
    /// # Arguments
    /// * `buffer` - The data to add.
    ///
    /// # Returns
    /// A mutable reference to the `HandshakeHash`.
    pub(crate) fn add(&mut self, buffer: &[u8]) -> &mut Self {
        self.ctx.update(buffer);
        self
    }

    /// Adds raw data to the handshake hash.
    ///
    /// # Arguments
    /// * `data` - The raw data to add.
    ///
    /// # Returns
    /// A mutable reference to the `HandshakeHash`.
    fn add_raw(&mut self, data: &[u8]) -> &mut Self {
        self.ctx.update(data);
        self
    }

    /// Returns the current hash output.
    ///
    /// # Returns
    /// The current hash output.
    pub(crate) fn current_hash(&self) -> Output {
        self.ctx.fork_finish()
    }
}
