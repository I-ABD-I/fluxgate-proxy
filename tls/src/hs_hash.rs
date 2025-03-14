use crate::codec::Codec;
use crate::crypto::hash;
use crate::crypto::hash::Output;
use crate::message::{Message, MessagePayload};

pub struct HandshakeHash {
    pub provider: &'static dyn hash::Hash,
    pub ctx: Box<dyn hash::Context>,
}

impl HandshakeHash {
    pub(crate) fn start_hash(provider: &'static dyn hash::Hash) -> Self {
        let ctx = provider.start();
        Self { provider, ctx }
    }
    pub(crate) fn add_message(&mut self, m: &Message<'_>) -> &mut Self {
        match &m.payload {
            MessagePayload::HandshakePayload(payload) => self.add_raw(&payload.get_encoding()),
            _ => self,
        }
    }
    pub(crate) fn add(&mut self, buffer: &[u8]) -> &mut Self {
        self.ctx.update(buffer);
        self
    }

    fn add_raw(&mut self, data: &[u8]) -> &mut Self {
        self.ctx.update(data);
        self
    }

    pub(crate) fn current_hash(&self) -> Output {
        self.ctx.fork_finish()
    }
}
