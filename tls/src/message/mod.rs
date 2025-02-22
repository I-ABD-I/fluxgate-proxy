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
mod ccs;
pub(crate) mod enums;
pub(crate) mod hs;
pub(crate) mod inbound;
pub(crate) mod deframer;

pub enum MessagePayload<'a> {
    ChangeCipherSpec(ChangeCipherSpecPayload),
    Alert(AlertPayload),
    HandshakePayload(HandshakePayload<'a>),
}

impl<'a> MessagePayload<'a> {
    pub fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            MessagePayload::ChangeCipherSpec(change_cipher_spec_payload) => {
                change_cipher_spec_payload.encode(bytes)
            }
            MessagePayload::Alert(alert_payload) => alert_payload.encode(bytes),
            MessagePayload::HandshakePayload(handshake_payload) => handshake_payload.encode(bytes),
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
            ContentType::ApplicationData => todo!(),
            ContentType::Unknown(_) => todo!(),
        }
    }
}

pub struct Message<'a> {
    version: ProtocolVersion,
    pub(crate) payload: MessagePayload<'a>,
}

pub struct PlainMessage {
    typ: ContentType,
    version: ProtocolVersion,
    payload: Payload<'static>,
}

const MAX_PAYLOAD: u16 = 0x4800;
const HEADER_SIZE: usize = 1 + 2 + 2;

const MAX_WIRE_SIZE: usize = MAX_PAYLOAD as usize + HEADER_SIZE;