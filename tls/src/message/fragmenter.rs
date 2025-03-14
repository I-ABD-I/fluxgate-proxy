use crate::message::enums::{ContentType, ProtocolVersion};
use crate::message::outbound::OutboundPlainMessage;
use crate::message::PlainMessage;

pub const MAX_FRAGMENT_LENGTH: usize = 0x4000;

pub struct MessageFragmenter;

impl MessageFragmenter {
    pub fn fragment_message<'a>(
        &self,
        msg: &'a PlainMessage,
    ) -> impl Iterator<Item = OutboundPlainMessage<'a>> {
        self.fragment_payload(msg.typ, msg.version, msg.payload.bytes())
    }

    pub fn fragment_payload<'a>(
        &self,
        typ: ContentType,
        version: ProtocolVersion,
        payload: &'a [u8],
    ) -> impl Iterator<Item = OutboundPlainMessage<'a>> {
        Chunker::new(payload).map(move |payload| OutboundPlainMessage {
            typ,
            version,
            payload,
        })
    }
}

struct Chunker<'a> {
    payload: &'a [u8],

    /// represents the max chunk allowed
    limit: usize,
}

impl Chunker<'_> {
    fn new(payload: &[u8]) -> Chunker {
        Chunker {
            payload,
            limit: MAX_FRAGMENT_LENGTH,
        }
    }
}

impl<'a> Iterator for Chunker<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.payload.is_empty() {
            return None;
        }

        let (b4, after) = self
            .payload
            .split_at(Ord::min(self.limit, self.payload.len()));
        self.payload = after;
        Some(b4)
    }
}

impl ExactSizeIterator for Chunker<'_> {
    fn len(&self) -> usize {
        self.payload.len().div_ceil(self.limit) // ceil(self.payload.len() / self.limit)
    }
}
