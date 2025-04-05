use crate::message::enums::{ContentType, ProtocolVersion};
use crate::message::HEADER_SIZE;

/// Represents a payload with a prefixed header.
#[derive(Clone, Debug)]
pub struct PrefixedPayload(Vec<u8>);

/// Represents an outbound opaque message in the TLS protocol.
#[derive(Clone, Debug)]
pub struct OutboundOpaqueMessage {
    /// The content type of the message.
    pub typ: ContentType,
    /// The protocol version of the message.
    pub version: ProtocolVersion,
    /// The payload of the message.
    pub payload: PrefixedPayload,
}

/// Represents an outbound plain message in the TLS protocol.
#[derive(Clone, Debug, Copy)]
pub struct OutboundPlainMessage<'a> {
    /// The content type of the message.
    pub typ: ContentType,
    /// The protocol version of the message.
    pub version: ProtocolVersion,
    /// The payload of the message.
    pub payload: &'a [u8],
}

impl PrefixedPayload {
    /// Creates a new `PrefixedPayload` with the specified capacity.
    ///
    /// # Arguments
    /// * `capacity` - The capacity of the payload.
    ///
    /// # Returns
    /// * `Self` - The new `PrefixedPayload` instance.
    pub fn with_capacity(capacity: usize) -> Self {
        let mut prefixed = Vec::with_capacity(HEADER_SIZE + capacity);
        prefixed.resize(HEADER_SIZE, 0);
        Self(prefixed)
    }

    /// Extends the payload with the specified slice.
    ///
    /// # Arguments
    /// * `slice` - The slice to extend the payload with.
    pub fn extend(&mut self, slice: &[u8]) {
        self.0.extend_from_slice(slice);
    }

    /// Returns the length of the payload.
    ///
    /// # Returns
    /// * `usize` - The length of the payload.
    pub fn len(&self) -> usize {
        self.0.len() - HEADER_SIZE
    }
}

impl AsMut<[u8]> for PrefixedPayload {
    /// Returns a mutable reference to the payload.
    ///
    /// # Returns
    /// * `&mut [u8]` - A mutable reference to the payload.
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[HEADER_SIZE..]
    }
}

impl OutboundOpaqueMessage {
    /// Encodes the `OutboundOpaqueMessage` into a byte vector.
    ///
    /// # Returns
    /// * `Vec<u8>` - The encoded byte vector.
    pub fn encode(self) -> Vec<u8> {
        let length = self.payload.len() as u16;
        let mut payload = self.payload.0;
        payload[0] = self.typ.into();
        payload[1..3].copy_from_slice(&self.version.to_array());
        payload[3..5].copy_from_slice(&length.to_be_bytes());
        payload
    }
}

impl OutboundPlainMessage<'_> {
    /// Converts the `OutboundPlainMessage` into an `OutboundOpaqueMessage`.
    ///
    /// # Returns
    /// * `OutboundOpaqueMessage` - The converted `OutboundOpaqueMessage`.
    pub fn to_unencrypted_opaque(self) -> OutboundOpaqueMessage {
        let mut payload = PrefixedPayload::with_capacity(self.payload.len());
        payload.extend(self.payload);
        OutboundOpaqueMessage {
            typ: self.typ,
            version: self.version,
            payload,
        }
    }
}
