use crate::{codec::Codec, error::InvalidMessage};

pub struct ChangeCipherSpecPayload;

impl Codec<'_> for ChangeCipherSpecPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        1u8.encode(bytes);
    }

    fn read(r: &mut crate::codec::Reader<'_>) -> Result<Self, crate::error::InvalidMessage> {
        let ccs = u8::read(r)?;
        if ccs != 1 {
            return Err(InvalidMessage::InvalidCCS);
        }
        r.expect_empty("ChangeCipherSpecPayload").map(|_| Self)
    }
}
