use crate::crypto::cipher::{AeadKey, Prf};
use crate::crypto::kx::ActiveKx;
use crate::error::Error;
use std::fmt::Debug;
use std::thread::current;

pub trait Hmac: Sync + Debug {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key>;
}

pub struct Tag {
    buf: [u8; Tag::MAX_SIZE],
    used: usize,
}

impl Tag {
    const MAX_SIZE: usize = 64;

    pub fn new(bytes: &[u8]) -> Self {
        let mut tag = Self {
            buf: [0; Self::MAX_SIZE],
            used: bytes.len(),
        };

        tag.buf[..tag.used].copy_from_slice(bytes);
        tag
    }
}

impl Drop for Tag {
    fn drop(&mut self) {
        unsafe {
            std::ptr::write_volatile(&mut self.buf, [0u8; Tag::MAX_SIZE]);
        }
    }
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

pub trait Key: Sync {
    fn sign(&self, data: &[&[u8]]) -> Tag;
    fn tag_len(&self) -> usize;
}

#[derive(Debug)]
pub struct PrfUsingHmac<'a>(pub &'a dyn Hmac);

impl Prf for PrfUsingHmac<'_> {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKx>,
        peer_pub: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), Error> {
        prf(
            output,
            &*self.0.with_key(&kx.complete(peer_pub)?),
            label,
            seed,
        );
        Ok(())
    }

    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
        prf(output, &*self.0.with_key(secret), label, seed);
    }
}

fn prf(output: &mut [u8], hmac: &dyn Key, label: &[u8], seed: &[u8]) {
    let mut current_a = hmac.sign(&[label, seed]);
    for chunk in output.chunks_mut(hmac.tag_len()) {
        let p = hmac.sign(&[current_a.as_ref(), label, seed]);
        chunk.copy_from_slice(&p.as_ref()[..chunk.len()]);
        current_a = hmac.sign(&[current_a.as_ref()]);
    }
}
