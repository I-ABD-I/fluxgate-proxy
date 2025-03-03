use std::mem;
use std::ops::{Deref, DerefMut};
use crate::{
    codec::{Codec, Reader},
    error::{Error, InvalidMessage, MessageError},
};

use super::{
    enums::{ContentType, ProtocolVersion},
    Message, MessagePayload, HEADER_SIZE, MAX_PAYLOAD,
};

pub struct BorrowedPayload<'a>(&'a mut [u8]);
impl BorrowedPayload<'_> {
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn truncate(&mut self, len: usize) {
        if len >= self.len() {
            return;
        }

        self.0 = core::mem::take(&mut self.0)
            .split_at_mut(len)
            .0;
    }

}


impl Deref for BorrowedPayload<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}


impl DerefMut for BorrowedPayload<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

pub struct InboundOpaqueMessage<'a> {
    pub(crate) typ: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) payload: BorrowedPayload<'a>,
}

pub struct DeframerIter<'a> {
    buffer: &'a mut [u8],
    consumed: usize,
}
impl<'a> DeframerIter<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            consumed: 0,
        }
    }

    pub(crate) fn consumed(&self) -> usize {
        self.consumed
    }
}

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

    fn next(&mut self) -> Option<Self::Item> {
        let (typ, version, length) =
            match read_opaque_message_header(&mut Reader::new(&self.buffer)) {
                Ok(header) => header,
                Err(err) => {
                    let err = match err {
                        MessageError::TooShortForHeader | MessageError::TooShortForLength => {
                            return None
                        }
                        MessageError::InvalidEmptyPayload => InvalidMessage::InvalidEmptyPayload,
                        MessageError::MessageTooLarge => InvalidMessage::MessageTooLarge,
                        MessageError::InvalidContentType => InvalidMessage::InvalidContentType,
                        MessageError::UnknownProtocolVersion => {
                            InvalidMessage::UnknownProtocolVersion
                        }
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

pub struct InboundPlainMessage<'a> {
    pub(crate) typ: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) payload: &'a [u8],
}

impl<'a> From<InboundOpaqueMessage<'a>> for InboundPlainMessage<'a> {
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

    fn try_from(value: InboundPlainMessage<'a>) -> Result<Self, Self::Error> {
        Ok(Message {
            version: value.version,
            payload: MessagePayload::new(value.typ, value.payload)?,
        })
    }
}
