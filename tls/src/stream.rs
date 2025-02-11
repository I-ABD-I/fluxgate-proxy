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
    fn compleate_io(&mut self) -> io::Result<()> {
        if self.conn.is_handshaking() {
            self.conn.compleate_io(self.sock)?;
        }

        if self.conn.wants_write() {
            self.conn.compleate_io(self.sock)?;
        }
        Ok(())
    }
}

impl<T> io::Read for Stream<'_, T>
where
    T: io::Read + io::Write,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.compleate_io()?;

        while self.conn.wants_read() {
            if self.conn.compleate_io(self.sock)?.0 == 0 {
                break;
            }
        }

        let used = (&self.conn.recived_plaintext[..]).read(buf)?;
        self.conn.recived_plaintext.drain(0..used);
        Ok(used)
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
