use crate::message::MAX_WIRE_SIZE;
use core::ops::Range;
use std::io;

/// A buffer for deframing TLS messages.
pub struct VecDeframerBuffer {
    /// The internal buffer storing the data.
    pub(super) buffer: Vec<u8>,
    /// The number of bytes used in the buffer.
    used: usize,
}

impl VecDeframerBuffer {
    /// Creates a new `VecDeframerBuffer`.
    ///
    /// # Returns
    ///
    /// A new instance of `VecDeframerBuffer`.
    pub fn new() -> VecDeframerBuffer {
        VecDeframerBuffer {
            buffer: Vec::new(),
            used: 0,
        }
    }

    /// Discards the specified number of bytes from the buffer.
    ///
    /// # Arguments
    ///
    /// * `taken` - The number of bytes to discard.
    pub(crate) fn discard(&mut self, taken: usize) {
        #[allow(clippy::comparison_chain)]
        /* Before:
         * +----------+----------+----------+
         * | taken    | pending  |xxxxxxxxxx|
         * +----------+----------+----------+
         * 0          ^ taken    ^ self.used
         *
         * After:
         * +----------+----------+----------+
         * | pending  |xxxxxxxxxxxxxxxxxxxxx|
         * +----------+----------+----------+
         * 0          ^ self.used
         */
        if taken < self.used {
            self.buffer.copy_within(taken..self.used, 0);
            self.used -= taken;
        } else if taken >= self.used {
            self.used = 0;
        }
    }

    /// Returns a mutable slice of the filled portion of the buffer.
    ///
    /// # Returns
    ///
    /// A mutable slice of the filled portion of the buffer.
    pub(crate) fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[..self.used]
    }

    /// Returns a slice of the filled portion of the buffer.
    ///
    /// # Returns
    ///
    /// A slice of the filled portion of the buffer.
    pub(crate) fn filled(&self) -> &[u8] {
        &self.buffer[..self.used]
    }

    /// Reads data from the given reader into the buffer.
    ///
    /// # Arguments
    ///
    /// * `rd` - A mutable reference to a reader.
    /// * `in_handshake` - A boolean indicating if the read is during a handshake.
    ///
    /// # Returns
    ///
    /// The number of bytes read.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if reading fails.
    pub(crate) fn read(&mut self, rd: &mut dyn io::Read, in_handshake: bool) -> io::Result<usize> {
        if let Err(err) = self.prepare_read(in_handshake) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, err));
        }

        // Try to do the largest reads possible. Note that if
        // we get a message with a length field out of range here,
        // we do a zero length read.  That looks like an EOF to
        // the next layer up, which is fine.
        let new_bytes = rd.read(&mut self.buffer[self.used..])?;
        self.used += new_bytes;
        Ok(new_bytes)
    }

    /// Resizes the internal buffer if necessary for reading more bytes.
    ///
    /// # Arguments
    ///
    /// * `is_joining_hs` - A boolean indicating if the read is during a handshake.
    ///
    /// # Returns
    ///
    /// An `Ok` result if resizing is successful, or an error message if the buffer is full.
    fn prepare_read(&mut self, is_joining_hs: bool) -> Result<(), &'static str> {
        /// TLS allows for handshake messages of up to 16MB.  We
        /// restrict that to 64KB to limit potential for denial-of-
        /// service.
        const MAX_HANDSHAKE_SIZE: u32 = 0xffff;

        const READ_SIZE: usize = 4096;

        // We allow a maximum of 64k of buffered data for handshake messages only. Enforce this
        // by varying the maximum allowed buffer size here based on whether a prefix of a
        // handshake payload is currently being buffered. Given that the first read of such a
        // payload will only ever be 4k bytes, the next time we come around here we allow a
        // larger buffer size. Once the large message and any following handshake messages in
        // the same flight have been consumed, `pop()` will call `discard()` to reset `used`.
        // At this point, the buffer resizing logic below should reduce the buffer size.
        let allow_max = match is_joining_hs {
            true => MAX_HANDSHAKE_SIZE as usize,
            false => MAX_WIRE_SIZE,
        };

        if self.used >= allow_max {
            return Err("message buffer full");
        }

        // If we can and need to increase the buffer size to allow a 4k read, do so. After
        // dealing with a large handshake message (exceeding `OutboundOpaqueMessage::MAX_WIRE_SIZE`),
        // make sure to reduce the buffer size again (large messages should be rare).
        // Also, reduce the buffer size if there are neither full nor partial messages in it,
        // which usually means that the other side suspended sending data.
        let need_capacity = Ord::min(allow_max, self.used + READ_SIZE);
        if need_capacity > self.buffer.len() {
            self.buffer.resize(need_capacity, 0);
        } else if self.used == 0 || self.buffer.len() > allow_max {
            self.buffer.resize(need_capacity, 0);
            self.buffer.shrink_to(need_capacity);
        }

        Ok(())
    }

    /// Appends bytes to the end of the buffer.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A slice of bytes to append.
    ///
    /// # Returns
    ///
    /// A `Range` indicating where the bytes were appended.
    pub(crate) fn extend(&mut self, bytes: &[u8]) -> Range<usize> {
        let len = bytes.len();
        let start = self.used;
        let end = start + len;
        if self.buffer.len() < end {
            self.buffer.resize(end, 0);
        }
        self.buffer[start..end].copy_from_slice(bytes);
        self.used += len;
        Range { start, end }
    }
}
