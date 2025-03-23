use futures::prelude::*;
use std::io;
use std::io::{Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
pub(super) struct ReadSyncConverter<'a, 'b, T> {
    pub io: &'a mut T,
    pub cx: &'a mut Context<'b>,
}

impl<T: AsyncRead + Unpin> Read for ReadSyncConverter<'_, '_, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match Pin::new(&mut self.io).poll_read(self.cx, buf) {
            Poll::Ready(res) => res,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

pub(super) struct WriteSyncConverter<'a, 'b, T> {
    pub io: &'a mut T,
    pub cx: &'a mut Context<'b>,
}

impl<T: AsyncWrite + Unpin> Write for WriteSyncConverter<'_, '_, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut self.io).poll_write(self.cx, buf) {
            Poll::Ready(res) => res,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut self.io).poll_flush(self.cx) {
            Poll::Ready(res) => res,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}
