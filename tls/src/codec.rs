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
}

pub trait Codec<'a>: Sized {
    fn encode(&self, bytes: &mut Vec<u8>);
    fn read(r: &Reader<'_>) -> Result<Self, ()>;
    fn get_encoding(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.encode(&mut bytes);
        bytes
    }
}
