use alert::AlertPayload;
use base::Payload;
use ccs::ChangeCipherSpecPayload;
use enums::{ContentType, ProtocolVersion};
use hs::HandshakePayload;

use crate::{
    codec::{Codec, Reader},
    error::InvalidMessage,
};

#[macro_use]
mod macros;

mod alert;
pub(crate) mod base;
pub(crate) mod ccs;
pub(crate) mod enums;
pub(crate) mod hs;
pub(crate) mod inbound;
pub(crate) mod deframer;
pub(crate) mod outbound;
pub(crate) mod fragmenter;

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
            MessagePayload::ApplicationData(payload) => bytes.extend(payload.bytes())
        }
    }

    pub fn new(typ: ContentType, payload: &'a [u8]) -> Result<Self, InvalidMessage> {
        let mut r = Reader::new(&payload);
        match typ {
            ContentType::ChangeCipherSpec => {
                ChangeCipherSpecPayload::read(&mut r).map(MessagePayload::ChangeCipherSpec)
            }
            ContentType::Alert => AlertPayload::read(&mut r).map(MessagePayload::Alert),
            ContentType::Handshake => {
                HandshakePayload::read(&mut r).map(MessagePayload::HandshakePayload)
            }
            ContentType::ApplicationData => Ok(MessagePayload::ApplicationData(Payload::read(&mut r))),
            ContentType::Unknown(_) => todo!(),
        }
    }

    pub fn content_type(&self) -> ContentType {
        match self {
            MessagePayload::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
            MessagePayload::Alert(_) => ContentType::Alert,
            MessagePayload::HandshakePayload(_) | MessagePayload::HandshakeFlight(_) => ContentType::Handshake,
            MessagePayload::ApplicationData(_) => ContentType::ApplicationData,
        }
    }
}

#[derive(Debug)]
pub struct Message<'a> {
    pub(crate) version: ProtocolVersion,
    pub(crate) payload: MessagePayload<'a>,
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
            payload
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