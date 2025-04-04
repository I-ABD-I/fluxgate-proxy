use futures::{AsyncRead, AsyncWrite};
use std::pin::Pin;
use std::task::{Context, Poll};

pub struct HandshakeLogger<'a, T> {
    transport: &'a mut T,
    handshake_log: Vec<u8>,
}

impl<T> HandshakeLogger<'_, T> {
    pub fn take_log(self) -> Vec<u8> {
        self.handshake_log
    }
}
impl<'a, T> From<&'a mut T> for HandshakeLogger<'a, T> {
    fn from(transport: &'a mut T) -> Self {
        Self {
            transport,
            handshake_log: Vec::with_capacity(2048),
        }
    }
}
impl<T> AsyncRead for HandshakeLogger<'_, T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.transport).poll_read(cx, buf) {
            Poll::Ready(Ok(n)) => {
                // Log the handshake data
                self.handshake_log.extend_from_slice(&buf[..n]);
                Poll::Ready(Ok(n))
            }
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

impl<T> AsyncWrite for HandshakeLogger<'_, T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.transport).poll_write(cx, buf)
    }
    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.transport).poll_flush(cx)
    }

    #[inline]
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.transport).poll_close(cx)
    }
}
