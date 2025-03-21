use super::message::enums::HashAlgorithm;
use std::fmt::Debug;
pub trait Hash: Sync + Debug {
    fn start(&self) -> Box<dyn Context>;
    fn hash(&self, data: &[u8]) -> Output;
    fn algorithm(&self) -> HashAlgorithm;
    fn output_length(&self) -> usize;
}

pub struct Output {
    buf: [u8; Output::MAX_SIZE],
    used: usize,
}

impl Output {
    pub fn new(buf: &[u8]) -> Self {
        let mut output = Self {
            buf: [0u8; Self::MAX_SIZE],
            used: buf.len(),
        };
        output.buf[..buf.len()].copy_from_slice(buf);
        output
    }

    const MAX_SIZE: usize = 64; // max is 64 bytes for sha512
}

impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

pub trait Context {
    fn finish(self: Box<Self>) -> Output;
    fn update(&mut self, data: &[u8]);

    fn fork_finish(&self) -> Output;
}

impl Context for ring::digest::Context {
    fn finish(self: Box<Self>) -> Output {
        let digest = ring::digest::Context::finish(*self);
        Output::new(digest.as_ref())
    }

    fn update(&mut self, data: &[u8]) {
        ring::digest::Context::update(self, data);
    }

    fn fork_finish(&self) -> Output {
        Output::new(self.clone().finish().as_ref())
    }
}

#[derive(Debug)]
pub(crate) struct Sha(&'static ring::digest::Algorithm, HashAlgorithm);

impl Hash for Sha {
    fn start(&self) -> Box<dyn Context> {
        Box::new(ring::digest::Context::new(self.0))
    }

    fn hash(&self, data: &[u8]) -> Output {
        let mut cx = ring::digest::Context::new(self.0);
        cx.update(data);
        Output::new(cx.finish().as_ref())
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.1
    }

    fn output_length(&self) -> usize {
        self.0.output_len()
    }
}

pub(crate) static SHA256: Sha = Sha(&ring::digest::SHA256, HashAlgorithm::sha256);
