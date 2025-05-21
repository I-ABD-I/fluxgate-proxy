/// Represents a type that can be encoded into and decoded from a byte stream.
///
/// This trait is generic over a lifetime `'a`, which is typically associated
/// with the input buffer when decoding.
///
/// # Type Parameters
///
/// * `'a`: The lifetime associated with the input data, primarily for the `Reader`
///   in the `read` method.
pub trait Codec<'a>: Sized {
    fn encode(&self, bytes: &mut Vec<u8>);

    /// Reads from a `Reader` and attempts to decode into an instance of `Self`.
    ///
    /// # Arguments
    ///
    /// * `r`: A mutable reference to a `Reader` from which bytes will be read.
    ///
    /// # Returns
    ///
    /// * `Result<Self, InvalidMessage>`:
    ///   - `Ok(Self)` if decoding is successful, containing the decoded instance.
    ///   - `Err(InvalidMessage)` if the input data is malformed or cannot be
    ///     decoded into `Self`.
    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage>;
}

/// A struct for reading data from a byte slice.
///
/// `Reader` provides a way to read data sequentially from an underlying byte buffer.
/// It keeps track of the current position within the buffer using a cursor.
pub struct Reader<'a> {
    buffer: &'a [u8],
    cursor: usize,
}

impl<'a> From<&'a [u8]> for Reader<'a> {
    fn from(buffer: &'a [u8]) -> Self {
        Self { buffer, cursor: 0 }
    }
}

/// Implements methods for a `Reader` struct, which is designed to read data from a byte buffer.
///
/// The `Reader` keeps track of the current position within the buffer, allowing for sequential
/// consumption of data.
impl<'a> Reader<'a> {
    /// Attempts to take a slice of `length` bytes from the current cursor position.
    ///
    /// If the remaining number of bytes in the buffer is less than `length`,
    /// this method returns `None`. Otherwise, it returns `Some` containing a slice
    /// of the requested `length` and advances the internal cursor by `length`.
    ///
    /// # Arguments
    ///
    /// * `length`: The number of bytes to take from the buffer.
    ///
    /// # Returns
    ///
    /// * `Some(&'a [u8])`: A slice of the buffer of the specified `length` if successful.
    /// * `None`: If `length` is greater than the number of bytes remaining in the buffer.
    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        if self.left() < length {
            return None;
        }
        let curr = self.cursor;
        self.cursor += length;
        Some(&self.buffer[curr..self.cursor])
    }

    /// Returns the number of bytes remaining in the buffer from the current cursor position.
    ///
    /// # Returns
    ///
    /// * `usize`: The number of bytes left in the buffer.
    pub fn left(&self) -> usize {
        self.buffer.len() - self.cursor
    }
}

#[repr(u8)]
/// Represents the type of message being sent or received.
pub enum MessageType {
    /// Represents a connection request.
    Connect,
    /// Represents a disconnection request.
    Disconnect,
    /// Represents an acknowledgment message.
    Ack,

    /// Represents a metrics message.
    Metrics,
    /// Represents an unknown message type.
    Unknown(u8),
}

impl Codec<'_> for MessageType {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Connect => bytes.push(0x00),
            Self::Disconnect => bytes.push(0x01),
            Self::Ack => bytes.push(0x02),
            Self::Metrics => bytes.push(0x03),
            Self::Unknown(b) => bytes.push(*b),
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(match r.take(1).ok_or(InvalidMessage)?[0] {
            0x00 => Self::Connect,
            0x01 => Self::Disconnect,
            0x02 => Self::Ack,
            0x03 => Self::Metrics,
            b => Self::Unknown(b),
        })
    }
}

impl Codec<'_> for f32 {
    fn encode(&self, bytse: &mut Vec<u8>) {
        bytse.extend_from_slice(&self.to_be_bytes());
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        r.take(4)
            .map(|b| f32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or(InvalidMessage)
    }
}

#[derive(Debug)]
/// Represents system metrics.
///
/// This struct holds various performance and usage metrics collected from the system.
pub struct Metrics {
    /// The CPU usage as a percentage.
    pub cpu: f32,
}

impl Codec<'_> for Metrics {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.cpu.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let cpu = f32::read(r)?;
        Ok(Self { cpu })
    }
}

/// Represents a message that can be sent or received.
pub enum Message {
    /// Represents a connection request.
    Connect,
    /// Represents a disconnection request.
    Disconnect,
    /// Represents an acknowledgment message.
    Ack,
    /// Represents a metrics message.
    Metrics(Metrics),
}

impl Message {
    /// Returns the [`MessageType`] corresponding to this `Message` variant.
    ///
    /// # Examples
    ///
    /// ```
    /// // Assuming Message and MessageType enums are defined elsewhere
    /// // and Message::Connect and MessageType::Connect exist.
    /// let message = Message::Connect;
    /// assert_eq!(message.typ(), MessageType::Connect);
    ///
    /// let metrics_message = Message::Metrics(Vec::new()); // Assuming Metrics takes some data
    /// assert_eq!(metrics_message.typ(), MessageType::Metrics);
    /// ```
    pub fn typ(&self) -> MessageType {
        match self {
            Self::Connect => MessageType::Connect,
            Self::Disconnect => MessageType::Disconnect,
            Self::Ack => MessageType::Ack,
            Self::Metrics(_) => MessageType::Metrics,
        }
    }
}

impl Codec<'_> for Message {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.typ().encode(bytes);
        if let Self::Metrics(m) = self {
            m.encode(bytes);
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let typ = MessageType::read(r)?;
        match typ {
            MessageType::Connect => Ok(Self::Connect),
            MessageType::Disconnect => Ok(Self::Disconnect),
            MessageType::Ack => Ok(Self::Ack),
            MessageType::Metrics => Ok(Self::Metrics(Metrics::read(r)?)),
            _ => Err(InvalidMessage),
        }
    }
}

/// Represents an error that occurs when decoding a message.
pub struct InvalidMessage;
