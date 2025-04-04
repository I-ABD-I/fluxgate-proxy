use crate::message::enums::{ContentType, ProtocolVersion};
use crate::message::outbound::OutboundPlainMessage;
use crate::message::PlainMessage;

/// The maximum length of a fragment.
pub const MAX_FRAGMENT_LENGTH: usize = 0x4000;

/// A struct responsible for fragmenting messages.
pub struct MessageFragmenter;

impl MessageFragmenter {
    /// Fragments a given message into smaller chunks.
    ///
    /// # Arguments
    ///
    /// * `msg` - A reference to the `PlainMessage` to be fragmented.
    ///
    /// # Returns
    ///
    /// An iterator over `OutboundPlainMessage` chunks.
    pub fn fragment_message<'a>(
        &self,
        msg: &'a PlainMessage,
    ) -> impl Iterator<Item = OutboundPlainMessage<'a>> {
        self.fragment_payload(msg.typ, msg.version, msg.payload.bytes())
    }

    /// Fragments a given payload into smaller chunks.
    ///
    /// # Arguments
    ///
    /// * `typ` - The content type of the message.
    /// * `version` - The protocol version of the message.
    /// * `payload` - A reference to the payload bytes to be fragmented.
    ///
    /// # Returns
    ///
    /// An iterator over `OutboundPlainMessage` chunks.
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

/// A struct that chunks a payload into smaller pieces.
struct Chunker<'a> {
    /// The payload to be chunked.
    payload: &'a [u8],

    /// Represents the max chunk allowed.
    limit: usize,
}

impl Chunker<'_> {
    /// Creates a new `Chunker` with the given payload.
    ///
    /// # Arguments
    ///
    /// * `payload` - A reference to the payload bytes to be chunked.
    ///
    /// # Returns
    ///
    /// A new instance of `Chunker`.
    fn new(payload: &[u8]) -> Chunker {
        Chunker {
            payload,
            limit: MAX_FRAGMENT_LENGTH,
        }
    }
}

impl<'a> Iterator for Chunker<'a> {
    type Item = &'a [u8];

    /// Returns the next chunk of the payload.
    ///
    /// # Returns
    ///
    /// An option containing the next chunk of the payload, or `None` if the payload is empty.
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
    /// Returns the number of chunks remaining.
    ///
    /// # Returns
    ///
    /// The number of chunks remaining.
    fn len(&self) -> usize {
        self.payload.len().div_ceil(self.limit) // ceil(self.payload.len() / self.limit)
    }
}
