use crate::codec::{Codec, Reader, TLSListElement};

/// Represents a payload in a TLS message.
#[derive(Debug)]
pub enum Payload<'a> {
    /// A borrowed slice of bytes.
    Borrowed(&'a [u8]),
    /// An owned vector of bytes.
    Owned(Vec<u8>),
}

impl<'a> Codec<'a> for Payload<'a> {
    /// Encodes the payload into a byte vector.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A mutable reference to a byte vector where the encoded payload will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        let slice = match self {
            Payload::Borrowed(s) => *s,
            Payload::Owned(vec) => vec,
        };
        bytes.extend_from_slice(slice);
    }

    /// Reads a payload from a byte reader.
    ///
    /// # Arguments
    ///
    /// * `r` - A mutable reference to a byte reader.
    ///
    /// # Returns
    ///
    /// A result containing the payload or an invalid message error.
    fn read(r: &mut Reader<'a>) -> Result<Self, crate::error::InvalidMessage> {
        Ok(Self::read(r))
    }
}

impl<'a> Payload<'a> {
    /// Reads the remaining bytes from the reader as a borrowed payload.
    ///
    /// # Arguments
    ///
    /// * `r` - A mutable reference to a byte reader.
    ///
    /// # Returns
    ///
    /// A borrowed payload.
    pub fn read(r: &mut Reader<'a>) -> Self {
        Self::Borrowed(r.rest())
    }

    /// Converts the payload into an owned version.
    ///
    /// # Returns
    ///
    /// An owned payload.
    pub fn into_owned(self) -> Payload<'static> {
        Payload::Owned(self.into_vec())
    }

    /// Converts the payload into a vector of bytes.
    ///
    /// # Returns
    ///
    /// A vector of bytes.
    pub fn into_vec(self) -> Vec<u8> {
        match self {
            Payload::Borrowed(slice) => slice.into(),
            Payload::Owned(vec) => vec,
        }
    }

    /// Returns a slice of bytes representing the payload.
    ///
    /// # Returns
    ///
    /// A slice of bytes.
    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            Payload::Borrowed(slice) => slice,
            Payload::Owned(vec) => vec.as_slice(),
        }
    }
}

impl Payload<'static> {
    /// Creates a new owned payload from a vector of bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A vector of bytes.
    ///
    /// # Returns
    ///
    /// An owned payload.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Owned(bytes.into())
    }
}

/// Represents a payload with a length prefix of 1 byte.
#[derive(Debug)]
pub struct PayloadU8(pub Vec<u8>);

impl PayloadU8 {
    /// Creates a new payload with the given body.
    ///
    /// # Arguments
    ///
    /// * `body` - A vector of bytes.
    ///
    /// # Returns
    ///
    /// A new payload with a length prefix of 1 byte.
    pub fn new(body: Vec<u8>) -> Self {
        Self(body)
    }

    /// Creates a new empty payload.
    ///
    /// # Returns
    ///
    /// An empty payload with a length prefix of 1 byte.
    pub fn new_empty() -> Self {
        Self(Vec::new())
    }

    /// Encodes a slice of bytes with a length prefix of 1 byte.
    ///
    /// # Arguments
    ///
    /// * `slice` - A slice of bytes to encode.
    /// * `bytes` - A mutable reference to a byte vector where the encoded slice will be stored.
    fn encode_slice(slice: &[u8], bytes: &mut Vec<u8>) {
        (slice.len() as u8).encode(bytes);
        bytes.extend_from_slice(slice);
    }
}

impl TLSListElement for PayloadU8 {
    const LENGHT_SIZE: crate::codec::ListLength = crate::codec::ListLength::u8;
}

impl Codec<'_> for PayloadU8 {
    /// Encodes the payload into a byte vector.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A mutable reference to a byte vector where the encoded payload will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        Self::encode_slice(&self.0, bytes);
    }

    /// Reads a payload from a byte reader.
    ///
    /// # Arguments
    ///
    /// * `r` - A mutable reference to a byte reader.
    ///
    /// # Returns
    ///
    /// A result containing the payload or an invalid message error.
    fn read(r: &mut Reader<'_>) -> Result<Self, crate::error::InvalidMessage> {
        let length = u8::read(r)?;
        let mut sub = r.slice(length as usize)?;
        let body = sub.rest().to_vec();
        Ok(Self::new(body))
    }
}

/// Represents a payload with a length prefix of 2 bytes.
#[derive(Debug)]
pub struct PayloadU16(pub Vec<u8>);

impl PayloadU16 {
    /// Creates a new payload with the given body.
    ///
    /// # Arguments
    ///
    /// * `body` - A vector of bytes.
    ///
    /// # Returns
    ///
    /// A new payload with a length prefix of 2 bytes.
    pub fn new(body: Vec<u8>) -> Self {
        Self(body)
    }

    /// Creates a new empty payload.
    ///
    /// # Returns
    ///
    /// An empty payload with a length prefix of 2 bytes.
    pub fn new_empty() -> Self {
        Self(Vec::new())
    }

    /// Encodes a slice of bytes with a length prefix of 2 bytes.
    ///
    /// # Arguments
    ///
    /// * `slice` - A slice of bytes to encode.
    /// * `bytes` - A mutable reference to a byte vector where the encoded slice will be stored.
    fn encode_slice(slice: &[u8], bytes: &mut Vec<u8>) {
        (slice.len() as u16).encode(bytes);
        bytes.extend_from_slice(slice);
    }
}

impl TLSListElement for PayloadU16 {
    const LENGHT_SIZE: crate::codec::ListLength = crate::codec::ListLength::u16;
}

impl Codec<'_> for PayloadU16 {
    /// Encodes the payload into a byte vector.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A mutable reference to a byte vector where the encoded payload will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        Self::encode_slice(&self.0, bytes);
    }

    /// Reads a payload from a byte reader.
    ///
    /// # Arguments
    ///
    /// * `r` - A mutable reference to a byte reader.
    ///
    /// # Returns
    ///
    /// A result containing the payload or an invalid message error.
    fn read(r: &mut Reader<'_>) -> Result<Self, crate::error::InvalidMessage> {
        let length = u16::read(r)?;
        let mut sub = r.slice(length as usize)?;
        let body = sub.rest().to_vec();
        Ok(Self::new(body))
    }
}