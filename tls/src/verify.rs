use crate::{
    codec::Codec,
    message::{base::PayloadU16, hs::SignatureAndHashAlgorithm},
};

pub struct DigitalySinged {
    algo: SignatureAndHashAlgorithm,
    signature: PayloadU16,
}

impl Codec<'_> for DigitalySinged {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.algo.encode(bytes);
        self.signature.encode(bytes);
    }

    fn read(r: &mut crate::codec::Reader<'_>) -> Result<Self, crate::error::InvalidMessage> {
        let algo = SignatureAndHashAlgorithm::read(r)?;
        let signature = PayloadU16::read(r)?;
        Ok(Self { algo, signature })
    }
}
