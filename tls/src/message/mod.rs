use alert::AlertPayload;
use base::Payload;
use ccs::ChangeCipherSpecPayload;
use enums::{ContentType, ProtocolVersion};

#[macro_use]
mod macros;

mod alert;
pub(crate) mod base;
mod ccs;
pub(crate) mod enums;
pub(crate) mod hs;

pub enum MessagePayload {
    ChangeCipherSpec(ChangeCipherSpecPayload),
    Alert(AlertPayload),
}

pub struct PlainMessage {
    typ: ContentType,
    version: ProtocolVersion,
    payload: Payload<'static>,
}
