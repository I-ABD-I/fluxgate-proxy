use alert::AlertPayload;
use base::Payload;
use ccs::ChangeCipherSpecPayload;
use enums::{ContentType, ProtocolVersion};
use hs::HandshakePayload;

use crate::message::alert::{AlertDescription, AlertLevel};
use crate::message::enums::ProtocolVersion::TLSv1_2;
use crate::{
    codec::{Codec, Reader},
    error::InvalidMessage,
};

#[macro_use]
mod macros;

pub(crate) mod alert;
pub(crate) mod base;
pub(crate) mod ccs;
pub(crate) mod deframer;
pub(crate) mod enums;
pub(crate) mod fragmenter;
pub(crate) mod hs;
pub(crate) mod inbound;
pub(crate) mod outbound;

/// Represents the payload of a TLS message.
#[derive(Debug)]
pub enum MessagePayload<'a> {
    /// Change Cipher Spec payload.
    ChangeCipherSpec(ChangeCipherSpecPayload),
    /// Alert payload.
    Alert(AlertPayload),
    /// Handshake payload.
    HandshakePayload(HandshakePayload<'a>),
    /// Handshake flight payload.
    HandshakeFlight(Payload<'a>),
    /// Application data payload.
    ApplicationData(Payload<'a>),
}

impl<'a> MessagePayload<'a> {
    /// Encodes the message payload into a byte vector.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A mutable reference to a byte vector where the encoded payload will be stored.
    pub fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            MessagePayload::ChangeCipherSpec(change_cipher_spec_payload) => {
                change_cipher_spec_payload.encode(bytes)
            }
            MessagePayload::Alert(alert_payload) => alert_payload.encode(bytes),
            MessagePayload::HandshakePayload(handshake_payload) => handshake_payload.encode(bytes),
            MessagePayload::HandshakeFlight(payload) => bytes.extend(payload.bytes()),
            MessagePayload::ApplicationData(payload) => bytes.extend(payload.bytes()),
        }
    }

    /// Creates a new message payload from the given content type and byte slice.
    ///
    /// # Arguments
    ///
    /// * `typ` - The content type of the message.
    /// * `payload` - A byte slice containing the payload data.
    ///
    /// # Returns
    ///
    /// A result containing the new message payload or an invalid message error.
    pub fn new(typ: ContentType, payload: &'a [u8]) -> Result<Self, InvalidMessage> {
        let mut r = Reader::new(payload);
        match typ {
            ContentType::ChangeCipherSpec => {
                ChangeCipherSpecPayload::read(&mut r).map(MessagePayload::ChangeCipherSpec)
            }
            ContentType::Alert => AlertPayload::read(&mut r).map(MessagePayload::Alert),
            ContentType::Handshake => {
                HandshakePayload::read(&mut r).map(MessagePayload::HandshakePayload)
            }
            ContentType::ApplicationData => {
                Ok(MessagePayload::ApplicationData(Payload::read(&mut r)))
            }
            ContentType::Unknown(_) => todo!(),
        }
    }

    /// Returns the content type of the message payload.
    ///
    /// # Returns
    ///
    /// The content type of the message payload.
    pub fn content_type(&self) -> ContentType {
        match self {
            MessagePayload::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
            MessagePayload::Alert(_) => ContentType::Alert,
            MessagePayload::HandshakePayload(_) | MessagePayload::HandshakeFlight(_) => {
                ContentType::Handshake
            }
            MessagePayload::ApplicationData(_) => ContentType::ApplicationData,
        }
    }

    /// Converts the message payload into an owned version.
    ///
    /// # Returns
    ///
    /// An owned version of the message payload.
    pub fn into_owned(self) -> MessagePayload<'static> {
        use MessagePayload::*;

        match self {
            ChangeCipherSpec(x) => ChangeCipherSpec(x),
            Alert(x) => Alert(x),
            HandshakePayload(x) => HandshakePayload(x.into_owned()),
            HandshakeFlight(x) => HandshakeFlight(x.into_owned()),
            ApplicationData(x) => ApplicationData(x.into_owned()),
        }
    }
}

/// Represents a TLS message.
#[derive(Debug)]
pub struct Message<'a> {
    /// The protocol version of the message.
    pub(crate) version: ProtocolVersion,
    /// The payload of the message.
    pub(crate) payload: MessagePayload<'a>,
}

impl Message<'_> {
    /// Builds an alert message with the given level and description.
    ///
    /// # Arguments
    ///
    /// * `level` - The alert level.
    /// * `description` - The alert description.
    ///
    /// # Returns
    ///
    /// A new alert message.
    pub fn build_alert(level: AlertLevel, description: AlertDescription) -> Self {
        Self {
            version: TLSv1_2,
            payload: MessagePayload::Alert(AlertPayload { level, description }),
        }
    }

    /// Converts the message into an owned version.
    ///
    /// # Returns
    ///
    /// An owned version of the message.
    pub(crate) fn into_owned(self) -> Message<'static> {
        let Self { version, payload } = self;
        Message {
            version,
            payload: payload.into_owned(),
        }
    }
}

impl From<Message<'_>> for PlainMessage {
    /// Converts a `Message` into a `PlainMessage`.
    ///
    /// # Arguments
    ///
    /// * `value` - The message to convert.
    ///
    /// # Returns
    ///
    /// The converted plain message.
    fn from(value: Message<'_>) -> Self {
        let payload = {
            let mut buf = Vec::new();
            value.payload.encode(&mut buf);
            Payload::Owned(buf)
        };

        Self {
            typ: value.payload.content_type(),
            version: value.version,
            payload,
        }
    }
}

/// Represents a plain TLS message.
pub struct PlainMessage {
    /// The content type of the message.
    typ: ContentType,
    /// The protocol version of the message.
    version: ProtocolVersion,
    /// The payload of the message.
    payload: Payload<'static>,
}

/// The maximum payload size.
const MAX_PAYLOAD: u16 = 0x4800;
/// The size of the header.
const HEADER_SIZE: usize = 1 + 2 + 2;

/// The maximum wire size.
const MAX_WIRE_SIZE: usize = MAX_PAYLOAD as usize + HEADER_SIZE;
