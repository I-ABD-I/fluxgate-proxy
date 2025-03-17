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

#[derive(Debug)]
pub enum MessagePayload<'a> {
    ChangeCipherSpec(ChangeCipherSpecPayload),
    Alert(AlertPayload),
    HandshakePayload(HandshakePayload<'a>),
    HandshakeFlight(Payload<'a>),
    ApplicationData(Payload<'a>),
}

impl<'a> MessagePayload<'a> {
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

#[derive(Debug)]
pub struct Message<'a> {
    pub(crate) version: ProtocolVersion,
    pub(crate) payload: MessagePayload<'a>,
}

impl Message<'_> {
    pub fn build_alert(level: AlertLevel, description: AlertDescription) -> Self {
        Self {
            version: TLSv1_2,
            payload: MessagePayload::Alert(AlertPayload { level, description }),
        }
    }

    pub(crate) fn into_owned(self) -> Message<'static> {
        let Self { version, payload } = self;
        Message {
            version,
            payload: payload.into_owned(),
        }
    }
}

impl From<Message<'_>> for PlainMessage {
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

pub struct PlainMessage {
    typ: ContentType,
    version: ProtocolVersion,
    payload: Payload<'static>,
}

const MAX_PAYLOAD: u16 = 0x4800;
const HEADER_SIZE: usize = 1 + 2 + 2;

const MAX_WIRE_SIZE: usize = MAX_PAYLOAD as usize + HEADER_SIZE;
