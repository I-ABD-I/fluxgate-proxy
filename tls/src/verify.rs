use crate::message::enums::SignatureScheme;
use crate::{
    codec::Codec,
    message::base::PayloadU16,
};

#[derive(Debug)]
pub struct DigitalySinged {
    algo: SignatureScheme,
    signature: PayloadU16,
}

impl DigitalySinged {
    pub fn new(algo: SignatureScheme, signature: Vec<u8>) -> Self {
        Self {
            algo,
            signature: PayloadU16::new(signature),
        }
    }
}
impl Codec<'_> for DigitalySinged {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.algo.encode(bytes);
        self.signature.encode(bytes);
    }

    fn read(r: &mut crate::codec::Reader<'_>) -> Result<Self, crate::error::InvalidMessage> {
        let algo = SignatureScheme::read(r)?;
        let signature = PayloadU16::read(r)?;
        Ok(Self { algo, signature })
    }
}
