use crate::message::enums::{ContentType, ProtocolVersion};
use crate::message::HEADER_SIZE;

#[derive(Clone, Debug)]
pub struct PrefixedPayload(Vec<u8>);

#[derive(Clone, Debug)]
pub struct OutboundOpaqueMessage {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: PrefixedPayload,
}
#[derive(Clone, Debug, Copy)]
pub struct OutboundPlainMessage<'a> {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: &'a [u8],
}

impl PrefixedPayload {
    pub fn with_capacity(capacity: usize) -> Self {
        let mut prefixed = Vec::with_capacity(HEADER_SIZE + capacity);
        prefixed.resize(HEADER_SIZE, 0);
        Self(prefixed)
    }

    pub fn extend(&mut self, slice: &[u8]) {
        self.0.extend_from_slice(slice);
    }
    pub fn len(&self) -> usize {
        self.0.len() - HEADER_SIZE
    }
}
impl AsMut<[u8]> for PrefixedPayload {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[HEADER_SIZE..]
    }
}

impl OutboundOpaqueMessage {
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
