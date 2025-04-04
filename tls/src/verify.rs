use crate::message::enums::SignatureScheme;
use crate::{
    codec::Codec,
    message::base::PayloadU16,
};

/// Represents a digitally signed message.
#[derive(Debug)]
pub struct DigitallySinged {
    /// The signature scheme used for signing.
    algo: SignatureScheme,
    /// The signature payload.
    signature: PayloadU16,
}

impl DigitallySinged {
    /// Creates a new `DigitallySigned` instance.
    ///
    /// # Arguments
    /// * `algo` - The signature scheme used for signing.
    /// * `signature` - The signature as a vector of bytes.
    ///
    /// # Returns
    /// A new `DigitallySigned` instance.
    pub fn new(algo: SignatureScheme, signature: Vec<u8>) -> Self {
        Self {
            algo,
            signature: PayloadU16::new(signature),
        }
    }
}

impl Codec<'_> for DigitallySinged {
    /// Encodes the `DigitallySigned` instance into the provided byte vector.
    ///
    /// # Arguments
    /// * `bytes` - The byte vector to encode into.
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.algo.encode(bytes);
        self.signature.encode(bytes);
    }

    /// Reads a `DigitallySigned` instance from the provided reader.
    ///
    /// # Arguments
    /// * `r` - The reader to read from.
    ///
    /// # Returns
    /// A result containing the `DigitallySigned` instance or an error.
    fn read(r: &mut crate::codec::Reader<'_>) -> Result<Self, crate::error::InvalidMessage> {
        let algo = SignatureScheme::read(r)?;
        let signature = PayloadU16::read(r)?;
        Ok(Self { algo, signature })
    }
}