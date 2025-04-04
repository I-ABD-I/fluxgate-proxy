use std::io;

use crate::connection::Connection;

/// Represents an owned stream with a connection and a socket.
pub struct StreamOwned<T>
where
    T: io::Read + io::Write,
{
    /// The connection associated with the stream.
    conn: Connection,
    /// The socket associated with the stream.
    sock: T,
}

impl<T: io::Read + io::Write> StreamOwned<T> {
    /// Creates a new `StreamOwned` instance.
    ///
    /// # Arguments
    /// * `conn` - The connection to associate with the stream.
    /// * `sock` - The socket to associate with the stream.
    ///
    /// # Returns
    /// A new `StreamOwned` instance.
    pub fn new(conn: Connection, sock: T) -> Self {
        Self { conn, sock }
    }
}

impl<'a, T: io::Read + io::Write> StreamOwned<T> {
    /// Converts the owned stream into a borrowed stream.
    ///
    /// # Returns
    /// A borrowed `Stream` instance.
    fn as_stream(&'a mut self) -> Stream<'a, T> {
        Stream {
            conn: &mut self.conn,
            sock: &mut self.sock,
        }
    }
}

/// Represents a borrowed stream with a connection and a socket.
pub struct Stream<'a, T> {
    /// The connection associated with the stream.
    conn: &'a mut Connection,
    /// The socket associated with the stream.
    sock: &'a mut T,
}

impl<'a, T: io::Read + io::Write> Stream<'a, T> {
    /// Creates a new `Stream` instance.
    ///
    /// # Arguments
    /// * `conn` - The connection to associate with the stream.
    /// * `sock` - The socket to associate with the stream.
    ///
    /// # Returns
    /// A new `Stream` instance.
    pub fn new(conn: &'a mut Connection, sock: &'a mut T) -> Self {
        Self { conn, sock }
    }

    /// Completes the I/O operations for the stream.
    ///
    /// # Returns
    /// An `io::Result` indicating the success or failure of the operation.
    fn complete_io(&mut self) -> io::Result<()> {
        if self.conn.is_handshaking() {
            self.conn.complete_io(self.sock)?;
        }

        if self.conn.wants_write() {
            self.conn.complete_io(self.sock)?;
        }
        Ok(())
    }
}

impl<T> io::Read for Stream<'_, T>
where
    T: io::Read + io::Write,
{
    /// Reads data from the stream into the provided buffer.
    ///
    /// # Arguments
    /// * `buf` - The buffer to read data into.
    ///
    /// # Returns
    /// The number of bytes read, or an `io::Result` indicating an error.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.complete_io()?;

        while self.conn.wants_read() {
            if self.conn.complete_io(self.sock)?.0 == 0 {
                break;
            }
        }

        let used = (&self.conn.received_plaintext[..]).read(buf)?;
        self.conn.received_plaintext.drain(0..used);
        Ok(used)
    }
}

impl<T> io::Write for Stream<'_, T>
where
    T: io::Read + io::Write,
{
    /// Writes data to the stream from the provided buffer.
    ///
    /// # Arguments
    /// * `buf` - The buffer containing the data to write.
    ///
    /// # Returns
    /// The number of bytes written, or an `io::Result` indicating an error.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.complete_io()?;

        let len = self.conn.send_plain(buf);
        let _ = self.conn.complete_io(self.sock)?;
        Ok(len)
    }

    /// Flushes the stream, ensuring all data is written.
    ///
    /// # Returns
    /// An `io::Result` indicating the success or failure of the operation.
    fn flush(&mut self) -> io::Result<()> {
        self.complete_io()?;

        if self.conn.wants_write() {
            self.conn.complete_io(self.sock)?;
        }

        Ok(())
    }
}

impl<T> io::Read for StreamOwned<T>
where
    T: io::Read + io::Write,
{
    /// Reads data from the owned stream into the provided buffer.
    ///
    /// # Arguments
    /// * `buf` - The buffer to read data into.
    ///
    /// # Returns
    /// The number of bytes read, or an `io::Result` indicating an error.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.as_stream().read(buf)
    }
}

impl<T> io::Write for StreamOwned<T>
where
    T: io::Read + io::Write,
{
    /// Writes data to the owned stream from the provided buffer.
    ///
    /// # Arguments
    /// * `buf` - The buffer containing the data to write.
    ///
    /// # Returns
    /// The number of bytes written, or an `io::Result` indicating an error.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.as_stream().write(buf)
    }

    /// Flushes the owned stream, ensuring all data is written.
    ///
    /// # Returns
    /// An `io::Result` indicating the success or failure of the operation.
    fn flush(&mut self) -> io::Result<()> {
        self.as_stream().flush()
    }
}
