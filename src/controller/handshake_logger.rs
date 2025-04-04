use futures::{AsyncRead, AsyncWrite};
use std::pin::Pin;
use std::task::{Context, Poll};

/// A logger for capturing handshake data during a TLS handshake.
///
/// # Fields
/// * `transport` - The underlying transport.
/// * `handshake_log` - A buffer to store the handshake data.
pub struct HandshakeLogger<'a, T> {
    transport: &'a mut T,
    handshake_log: Vec<u8>,
}

impl<T> HandshakeLogger<'_, T> {
    /// Takes the handshake log and returns it.
    ///
    /// # Returns
    /// The handshake log as a vector of bytes.
    pub fn take_log(self) -> Vec<u8> {
        self.handshake_log
    }
}

impl<'a, T> From<&'a mut T> for HandshakeLogger<'a, T> {
    /// Creates a new `HandshakeLogger` from a mutable reference to a transport.
    ///
    /// # Arguments
    /// * `transport` - The underlying transport.
    ///
    /// # Returns
    /// A new `HandshakeLogger` instance.
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
    /// Polls to read data from the transport.
    ///
    /// # Arguments
    /// * `cx` - The context for the asynchronous task.
    /// * `buf` - The buffer to read data into.
    ///
    /// # Returns
    /// A `Poll` indicating the readiness of the read operation.
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
    /// Polls to write data to the transport.
    ///
    /// # Arguments
    /// * `cx` - The context for the asynchronous task.
    /// * `buf` - The buffer containing the data to write.
    ///
    /// # Returns
    /// A `Poll` indicating the readiness of the write operation.
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.transport).poll_write(cx, buf)
    }

    /// Polls to flush the transport.
    ///
    /// # Arguments
    /// * `cx` - The context for the asynchronous task.
    ///
    /// # Returns
    /// A `Poll` indicating the readiness of the flush operation.
    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.transport).poll_flush(cx)
    }

    /// Polls to close the transport.
    ///
    /// # Arguments
    /// * `cx` - The context for the asynchronous task.
    ///
    /// # Returns
    /// A `Poll` indicating the readiness of the close operation.
    #[inline]
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.transport).poll_close(cx)
    }
}