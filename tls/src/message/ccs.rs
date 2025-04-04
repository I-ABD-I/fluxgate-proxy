use crate::{codec::Codec, error::InvalidMessage};

/// Represents the payload for a Change Cipher Spec message in TLS.
#[derive(Debug)]
pub struct ChangeCipherSpecPayload;

impl Codec<'_> for ChangeCipherSpecPayload {
    /// Encodes the Change Cipher Spec payload into a byte vector.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A mutable reference to a byte vector where the encoded payload will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        1u8.encode(bytes);
    }

    /// Reads a Change Cipher Spec payload from a byte reader.
    ///
    /// # Arguments
    ///
    /// * `r` - A mutable reference to a byte reader.
    ///
    /// # Returns
    ///
    /// A result containing the Change Cipher Spec payload or an invalid message error.
    fn read(r: &mut crate::codec::Reader<'_>) -> Result<Self, crate::error::InvalidMessage> {
        let ccs = u8::read(r)?;
        if ccs != 1 {
            return Err(InvalidMessage::InvalidCCS);
        }
        r.expect_empty("ChangeCipherSpecPayload").map(|_| Self)
    }
}