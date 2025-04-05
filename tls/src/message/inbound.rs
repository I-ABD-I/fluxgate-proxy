use crate::{
    codec::{Codec, Reader},
    error::{Error, InvalidMessage, MessageError},
};
use std::mem;
use std::ops::{Deref, DerefMut};

use super::{
    enums::{ContentType, ProtocolVersion},
    Message, MessagePayload, HEADER_SIZE, MAX_PAYLOAD,
};

/// Represents a borrowed payload in the TLS protocol.
pub struct BorrowedPayload<'a>(&'a mut [u8]);

impl BorrowedPayload<'_> {
    /// Returns the length of the payload.
    ///
    /// # Returns
    /// * `usize` - The length of the payload.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Truncates the payload to the specified length.
    ///
    /// # Arguments
    /// * `len` - The length to truncate the payload to.
    pub fn truncate(&mut self, len: usize) {
        if len >= self.len() {
            return;
        }

        self.0 = core::mem::take(&mut self.0).split_at_mut(len).0;
    }
}

impl Deref for BorrowedPayload<'_> {
    type Target = [u8];

    /// Returns a reference to the payload.
    ///
    /// # Returns
    /// * `&[u8]` - A reference to the payload.
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl DerefMut for BorrowedPayload<'_> {
    /// Returns a mutable reference to the payload.
    ///
    /// # Returns
    /// * `&mut [u8]` - A mutable reference to the payload.
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

/// Represents an inbound opaque message in the TLS protocol.
pub struct InboundOpaqueMessage<'a> {
    /// The content type of the message.
    pub(crate) typ: ContentType,
    /// The protocol version of the message.
    pub(crate) version: ProtocolVersion,
    /// The payload of the message.
    pub(crate) payload: BorrowedPayload<'a>,
}

/// Iterator for deframing inbound messages.
pub struct DeframerIter<'a> {
    /// The buffer containing the message data.
    buffer: &'a mut [u8],
    /// The number of bytes consumed from the buffer.
    consumed: usize,
}

impl<'a> DeframerIter<'a> {
    /// Creates a new `DeframerIter` instance.
    ///
    /// # Arguments
    /// * `buffer` - A mutable reference to a buffer containing the message data.
    ///
    /// # Returns
    /// * `Self` - The new `DeframerIter` instance.
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            consumed: 0,
        }
    }

    /// Returns the number of bytes consumed from the buffer.
    ///
    /// # Returns
    /// * `usize` - The number of bytes consumed.
    pub(crate) fn consumed(&self) -> usize {
        self.consumed
    }
}

/// Reads the header of an opaque message.
///
/// # Arguments
/// * `r` - A mutable reference to a `Reader` that provides the byte slice to read from.
///
/// # Returns
/// * `Result<(ContentType, ProtocolVersion, usize), MessageError>` - The content type, protocol version, and length of the message, or an error if reading fails.
fn read_opaque_message_header(
    r: &mut Reader<'_>,
) -> Result<(ContentType, ProtocolVersion, usize), MessageError> {
    let typ = ContentType::read(r).map_err(|_| MessageError::TooShortForHeader)?;

    if let ContentType::Unknown(_) = typ {
        return Err(MessageError::InvalidContentType);
    }

    let version = ProtocolVersion::read(r).map_err(|_| MessageError::TooShortForHeader)?;

    if let ProtocolVersion::Unknown(_) = version {
        return Err(MessageError::UnknownProtocolVersion);
    }

    let len = u16::read(r).map_err(|_| MessageError::TooShortForLength)?;
    if typ != ContentType::ApplicationData && len == 0 {
        return Err(MessageError::InvalidEmptyPayload);
    }

    if len >= MAX_PAYLOAD {
        return Err(MessageError::MessageTooLarge);
    }

    Ok((typ, version, len as usize))
}

impl<'a> Iterator for DeframerIter<'a> {
    type Item = Result<InboundOpaqueMessage<'a>, Error>;

    /// Returns the next inbound opaque message.
    ///
    /// # Returns
    /// * `Option<Result<InboundOpaqueMessage<'a>, Error>>` - The next inbound opaque message or an error if reading fails.
    fn next(&mut self) -> Option<Self::Item> {
        let (typ, version, length) = match read_opaque_message_header(&mut Reader::new(self.buffer))
        {
            Ok(header) => header,
            Err(err) => {
                let err = match err {
                    MessageError::TooShortForHeader | MessageError::TooShortForLength => {
                        return None
                    }
                    MessageError::InvalidEmptyPayload => InvalidMessage::InvalidEmptyPayload,
                    MessageError::MessageTooLarge => InvalidMessage::MessageTooLarge,
                    MessageError::InvalidContentType => InvalidMessage::InvalidContentType,
                    MessageError::UnknownProtocolVersion => InvalidMessage::UnknownProtocolVersion,
                };
                return Some(Err(err.into()));
            }
        };

        let end = HEADER_SIZE + length;

        self.buffer.get(HEADER_SIZE..end)?;

        let (consumed, reminder) = mem::take(&mut self.buffer).split_at_mut(end);
        self.buffer = reminder;
        self.consumed += end;

        Some(Ok(InboundOpaqueMessage {
            typ,
            version,
            payload: BorrowedPayload(&mut consumed[HEADER_SIZE..]),
        }))
    }
}

/// Represents an inbound plain message in the TLS protocol.
#[derive(Debug)]
pub struct InboundPlainMessage<'a> {
    /// The content type of the message.
    pub(crate) typ: ContentType,
    /// The protocol version of the message.
    pub(crate) version: ProtocolVersion,
    /// The payload of the message.
    pub(crate) payload: &'a [u8],
}

impl<'a> From<InboundOpaqueMessage<'a>> for InboundPlainMessage<'a> {
    /// Converts an `InboundOpaqueMessage` into an `InboundPlainMessage`.
    ///
    /// # Arguments
    /// * `value` - The `InboundOpaqueMessage` instance to convert.
    ///
    /// # Returns
    /// * `Self` - The converted `InboundPlainMessage`.
    fn from(value: InboundOpaqueMessage<'a>) -> Self {
        InboundPlainMessage {
            typ: value.typ,
            version: value.version,
            payload: value.payload.0,
        }
    }
}

impl<'a> TryFrom<InboundPlainMessage<'a>> for Message<'a> {
    type Error = InvalidMessage;

    /// Tries to convert an `InboundPlainMessage` into a `Message`.
    ///
    /// # Arguments
    /// * `value` - The `InboundPlainMessage` instance to convert.
    ///
    /// # Returns
    /// * `Result<Self, Self::Error>` - The converted `Message` or an error if conversion fails.
    fn try_from(value: InboundPlainMessage<'a>) -> Result<Self, Self::Error> {
        Ok(Message {
            version: value.version,
            payload: MessagePayload::new(value.typ, value.payload)?,
        })
    }
}
