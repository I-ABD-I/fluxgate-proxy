use crate::error::InvalidMessage;
use std::fmt;
pub struct Reader<'a> {
    buffer: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Reader { buffer, cursor: 0 }
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let rest = &self.buffer[self.cursor..];
        self.cursor = self.buffer.len();
        rest
    }

    pub fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        if self.left() < length {
            return None;
        }
        let curr = self.cursor;
        self.cursor += length;
        Some(&self.buffer[curr..self.cursor])
    }

    pub fn used(&self) -> usize {
        self.cursor
    }

    pub fn left(&self) -> usize {
        self.buffer.len() - self.cursor
    }

    pub fn expect_empty(&self, name: &'static str) -> Result<(), InvalidMessage> {
        if self.left() == 0 {
            Ok(())
        } else {
            Err(InvalidMessage::TrailingData(name))
        }
    }

    pub fn slice(&mut self, length: usize) -> Result<Self, InvalidMessage> {
        match self.take(length) {
            Some(buf) => Ok(Self::new(buf)),
            None => Err(InvalidMessage::MessageTooShort),
        }
    }
}

pub trait Codec<'a>: Sized {
    fn encode(&self, bytes: &mut Vec<u8>);
    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage>;
    fn get_encoding(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.encode(&mut bytes);
        bytes
    }
}

impl<'a> Codec<'a> for u8 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.push(*self);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        r.take(1)
            .map(|b| b[0])
            .ok_or(InvalidMessage::MissingData("u8"))
    }
}

impl<'a> Codec<'a> for u16 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.to_be_bytes());
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        r.take(2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .ok_or(InvalidMessage::MissingData("u16"))
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug)]
pub struct u24(pub u32);

impl From<u24> for usize {
    #[inline]
    fn from(value: u24) -> Self {
        value.0 as Self
    }
}

impl Codec<'_> for u24 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let be_bytes = self.0.to_be_bytes();
        bytes.extend_from_slice(&be_bytes[1..]);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        match r.take(3) {
            Some(&[a, b, c]) => Ok(Self(u32::from_be_bytes([0, a, b, c]))),
            _ => Err(InvalidMessage::MissingData("u24")),
        }
    }
}

impl<'a> Codec<'a> for u32 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.to_be_bytes());
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        r.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or(InvalidMessage::MissingData("u32"))
    }
}

impl<'a> Codec<'a> for u64 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.to_be_bytes());
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        r.take(8)
            .map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
            .ok_or(InvalidMessage::MissingData("u64"))
    }
}

#[allow(non_camel_case_types)]
pub enum ListLength {
    u8,
    u16,
    u24 { max: usize, error: InvalidMessage },
}
pub trait TLSListElement {
    const LENGHT_SIZE: ListLength;
}

impl<'a, T> Codec<'a> for Vec<T>
where
    T: Codec<'a> + TLSListElement + fmt::Debug,
{
    fn encode(&self, bytes: &mut Vec<u8>) {
        // length is the byte slice length and not the vec length
        let dummy_length = match T::LENGHT_SIZE {
            ListLength::u8 => &[0xff][..],
            ListLength::u16 => &[0xff, 0xff],
            ListLength::u24 { .. } => &[0xff, 0xff, 0xff],
        };
        let length_offset = bytes.len();

        bytes.extend_from_slice(dummy_length);
        for i in self {
            i.encode(bytes);
        }

        match T::LENGHT_SIZE {
            ListLength::u8 => {
                let length = (bytes.len() - length_offset - 1) as u8;
                debug_assert!(length <= u8::MAX);
                bytes[length_offset] = length;
            }

            ListLength::u16 => {
                let length = (bytes.len() - length_offset - 2) as u16;
                debug_assert!(length <= u16::MAX);
                bytes[length_offset..=length_offset + 1].copy_from_slice(&length.to_be_bytes());
            }
            ListLength::u24 { max, error: _ } => {
                let length = (bytes.len() - length_offset - 3) as u32;
                debug_assert!(length <= max as u32);
                bytes[length_offset..=length_offset + 2]
                    .copy_from_slice(&length.to_be_bytes()[1..]);
            }
        }
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let length = match T::LENGHT_SIZE {
            ListLength::u8 => u8::read(r)? as usize,
            ListLength::u16 => u16::read(r)? as usize,
            ListLength::u24 { max, error } => match usize::from(u24::read(r)?) {
                length if length > max => return Err(error),
                length => length,
            },
        };

        let mut sub = r.slice(length)?;
        let mut ret = Vec::with_capacity(length);
        while sub.left() > 0 {
            ret.push(T::read(&mut sub)?);
        }

        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use crate::enum_builder;

    use super::*;

    enum_builder! {
        #[repr(u16)]
        enum Foo {
            A => 1,
            B => 2
        }
    }

    impl TLSListElement for Foo {
        const LENGHT_SIZE: ListLength = ListLength::u24 {
            max: 100,
            error: InvalidMessage::InvalidCCS, // temp dosent matter
        };
    }

    #[test]
    fn test_vec_encode() {
        let vec = vec![Foo::A, Foo::B, Foo::Unknown(0xabd0)];
        let mut bytes = Vec::new();
        vec.encode(&mut bytes);
        assert_eq!(
            bytes.as_slice(),
            &[0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x02, 0xab, 0xd0]
        )
    }

    #[test]
    fn test_vec_read() {
        let mut reader = Reader::new(&[0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x02, 0xab, 0xd0]);
        assert_eq!(
            Vec::<Foo>::read(&mut reader).unwrap(),
            vec![Foo::A, Foo::B, Foo::Unknown(0xabd0)]
        )
    }
}
