use futures::prelude::*;
use std::io;
use std::io::{Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

/// A structure that converts asynchronous reads to synchronous reads.
///
/// This structure holds a mutable reference to an I/O object and a task context.
pub(super) struct ReadSyncConverter<'a, 'b, T> {
    /// A mutable reference to the I/O object.
    pub io: &'a mut T,
    /// A mutable reference to the task context.
    pub cx: &'a mut Context<'b>,
}

impl<T: AsyncRead + Unpin> Read for ReadSyncConverter<'_, '_, T> {
    /// Reads data into the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - A mutable slice of bytes to store the read data.
    ///
    /// # Returns
    ///
    /// A result containing the number of bytes read or an I/O error.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match Pin::new(&mut self.io).poll_read(self.cx, buf) {
            Poll::Ready(res) => res,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// A structure that converts asynchronous writes to synchronous writes.
///
/// This structure holds a mutable reference to an I/O object and a task context.
pub(super) struct WriteSyncConverter<'a, 'b, T> {
    /// A mutable reference to the I/O object.
    pub io: &'a mut T,
    /// A mutable reference to the task context.
    pub cx: &'a mut Context<'b>,
}

impl<T: AsyncWrite + Unpin> Write for WriteSyncConverter<'_, '_, T> {
    /// Writes data from the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - A slice of bytes to write.
    ///
    /// # Returns
    ///
    /// A result containing the number of bytes written or an I/O error.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut self.io).poll_write(self.cx, buf) {
            Poll::Ready(res) => res,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    /// Flushes the I/O object.
    ///
    /// # Returns
    ///
    /// A result indicating success or an I/O error.
    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut self.io).poll_flush(self.cx) {
            Poll::Ready(res) => res,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}
