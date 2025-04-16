pub trait Codec<'a>: Sized {
    fn encode(&self, bytes: &mut Vec<u8>);
    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage>;
}
pub struct Reader<'a> {
    buffer: &'a [u8],
    cursor: usize,
}

impl<'a> From<&'a [u8]> for Reader<'a> {
    fn from(buffer: &'a [u8]) -> Self {
        Self { buffer, cursor: 0 }
    }
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        if self.left() < length {
            return None;
        }
        let curr = self.cursor;
        self.cursor += length;
        Some(&self.buffer[curr..self.cursor])
    }

    pub fn left(&self) -> usize {
        self.buffer.len() - self.cursor
    }
}

#[repr(u8)]
pub enum MessageType {
    Connect,
    Disconnect,
    Ack,

    Metrics,
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
pub struct Metrics {
    pub cpu: f32,
}

impl Codec<'_> for Metrics {
    fn encode(&self, bytse: &mut Vec<u8>) {
        self.cpu.encode(bytse);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let cpu = f32::read(r)?;
        Ok(Self { cpu })
    }
}

pub enum Message {
    Connect,
    Disconnect,
    Ack,

    Metrics(Metrics),
}

impl Message {
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
pub struct InvalidMessage;
