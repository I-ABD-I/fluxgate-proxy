use core::slice;

use crate::codec::{self, Codec, Reader, TLSListElement};

#[derive(Debug)]
pub enum Payload<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl<'a> Codec<'a> for Payload<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let slice = match self {
            Payload::Borrowed(s) => *s,
            Payload::Owned(vec) => &vec,
        };
        bytes.extend_from_slice(slice);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, crate::error::InvalidMessage> {
        Ok(Self::read(r))
    }
}

impl<'a> Payload<'a> {
    pub fn read(r: &mut Reader<'a>) -> Self {
        Self::Borrowed(r.rest())
    }

    pub fn into_owned(self) -> Payload<'static> {
        Payload::Owned(self.into_vec())
    }

    fn into_vec(self) -> Vec<u8> {
        match self {
            Payload::Borrowed(slice) => slice.into(),
            Payload::Owned(vec) => vec,
        }
    }
    
    pub(crate) fn bytes(&self) -> &[u8] {
        match Self {
            Payload::Borrowed(slice) => slice,
            Payload::Owned(vec) => vec.as_slice(),
        }
    }
}

impl Payload<'static> {
    fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Owned(bytes.into())
    }
}

pub struct PayloadU8(pub Vec<u8>);

impl PayloadU8 {
    pub fn new(body: Vec<u8>) -> Self {
        Self(body)
    }

    pub fn new_empty() -> Self {
        Self(Vec::new())
    }

    fn encode_slice(slice: &[u8], bytes: &mut Vec<u8>) {
        (slice.len() as u8).encode(bytes);
        bytes.extend_from_slice(slice);
    }
}

impl TLSListElement for PayloadU8 {
    const LENGHT_SIZE: crate::codec::ListLength = crate::codec::ListLength::u8;
}

impl Codec<'_> for PayloadU8 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        Self::encode_slice(&self.0, bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, crate::error::InvalidMessage> {
        let length = u8::read(r)?;
        let mut sub = r.slice(length as usize)?;
        let body = sub.rest().to_vec();
        Ok(Self::new(body))
    }
}

pub struct PayloadU16(pub Vec<u8>);

impl PayloadU16 {
    pub fn new(body: Vec<u8>) -> Self {
        Self(body)
    }

    pub fn new_empty() -> Self {
        Self(Vec::new())
    }

    fn encode_slice(slice: &[u8], bytes: &mut Vec<u8>) {
        (slice.len() as u16).encode(bytes);
        bytes.extend_from_slice(slice);
    }
}

impl TLSListElement for PayloadU16 {
    const LENGHT_SIZE: crate::codec::ListLength = crate::codec::ListLength::u16;
}

impl Codec<'_> for PayloadU16 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        Self::encode_slice(&self.0, bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, crate::error::InvalidMessage> {
        let length = u16::read(r)?;
        let mut sub = r.slice(length as usize)?;
        let body = sub.rest().to_vec();
        Ok(Self::new(body))
    }
}


