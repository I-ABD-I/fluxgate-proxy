use std::io;

use crate::connection::Connection;

pub struct StreamOwned<T>
where
    T: io::Read + io::Write,
{
    conn: Connection,
    sock: T,
}

impl<T: io::Read + io::Write> StreamOwned<T> {
    pub fn new(conn: Connection, sock: T) -> Self {
        Self { conn, sock }
    }
}

impl<'a, T: io::Read + io::Write> StreamOwned<T> {
    fn as_stream(&'a mut self) -> Stream<'a, T> {
        Stream {
            conn: &mut self.conn,
            sock: &mut self.sock,
        }
    }
}

pub struct Stream<'a, T> {
    conn: &'a mut Connection,
    sock: &'a mut T,
}

impl<'a, T: io::Read + io::Write> Stream<'a, T> {
    pub fn new(conn: &'a mut Connection, sock: &'a mut T) -> Self {
        Self { conn, sock }
    }
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
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.complete_io()?;

        let len = self.conn.send_plain(buf);
        let _ = self.conn.complete_io(self.sock)?;
        Ok(len)
    }

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
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.as_stream().read(buf)
    }
}

impl<T> io::Write for StreamOwned<T>
where
    T: io::Read + io::Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.as_stream().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.as_stream().flush()
    }
}
