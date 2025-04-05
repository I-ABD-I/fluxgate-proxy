mod utils;

use crate::config::ServerConfig;
use crate::error::Error;
use crate::futures::utils::{ReadSyncConverter, WriteSyncConverter};
use crate::server::{Accepted, AcceptedAlert, Acceptor, Connection};
use crate::state::ClientHello;
use futures::{AsyncBufRead, AsyncRead, AsyncWrite, TryStreamExt};
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::{io, mem};

/// A structure representing a stream.
///
/// This structure contains a mutable reference to an I/O object and a mutable reference to a TLS connection session.
/// It also keeps track of whether the end-of-file (EOF) has been reached.
pub struct Stream<'a, IO> {
    /// A mutable reference to the I/O object.
    pub(crate) io: &'a mut IO,
    /// A mutable reference to the TLS connection session.
    pub(crate) session: &'a mut Connection,
    /// A boolean indicating whether the end-of-file (EOF) has been reached.
    eof: bool,
}

impl<'a, IO> Stream<'a, IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Creates a new `Stream` instance.
    ///
    /// # Arguments
    ///
    /// * `session` - A mutable reference to a `Connection`.
    /// * `io` - A mutable reference to an I/O object.
    ///
    /// # Returns
    ///
    /// A new `Stream` instance.
    fn new(session: &'a mut Connection, io: &'a mut IO) -> Self {
        Self {
            io,
            session,
            eof: false,
        }
    }

    /// Sets the end-of-file (EOF) flag.
    ///
    /// # Arguments
    ///
    /// * `eof` - A boolean indicating whether the EOF has been reached.
    ///
    /// # Returns
    ///
    /// The `Stream` instance with the updated EOF flag.
    fn set_eof(mut self, eof: bool) -> Self {
        self.eof = eof;
        self
    }

    /// Converts the `Stream` instance to a pinned mutable reference.
    ///
    /// # Returns
    ///
    /// A pinned mutable reference to the `Stream` instance.
    fn as_mut_pin(&mut self) -> Pin<&mut Self> {
        Pin::new(self)
    }

    /// Reads data from the I/O object into the TLS session.
    ///
    /// # Arguments
    ///
    /// * `cx` - A mutable reference to the task context.
    ///
    /// # Returns
    ///
    /// A `Poll` indicating the result of the read operation.
    pub fn read_io(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
        let mut reader = ReadSyncConverter { io: self.io, cx };
        let n = match self.session.read_tls(&mut reader) {
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(e) => return Poll::Ready(Err(e)),
        };

        self.session.process_new_packets().map_err(|err| {
            let _ = self.write_io(cx);
            io::Error::new(io::ErrorKind::Other, err)
        })?;

        Poll::Ready(Ok(n))
    }

    /// Writes data from the TLS session to the I/O object.
    ///
    /// # Arguments
    ///
    /// * `cx` - A mutable reference to the task context.
    ///
    /// # Returns
    ///
    /// A `Poll` indicating the result of the write operation.
    pub fn write_io(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
        let mut writer = WriteSyncConverter { io: self.io, cx };
        match self.session.write_tls(&mut writer) {
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            res => Poll::Ready(res),
        }
    }

    /// Performs the TLS handshake.
    ///
    /// # Arguments
    ///
    /// * `cx` - A mutable reference to the task context.
    ///
    /// # Returns
    ///
    /// A `Poll` indicating the result of the handshake operation.
    pub fn handshake(&mut self, cx: &mut Context) -> Poll<io::Result<(usize, usize)>> {
        let mut wrlen = 0;
        let mut rdlen = 0;

        loop {
            let mut write_would_block = false;
            let mut read_would_block = false;
            let mut need_flush = false;

            while self.session.wants_write() {
                match self.write_io(cx) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                    Poll::Ready(Ok(n)) => {
                        wrlen += n;
                        need_flush = true;
                    }
                    Poll::Pending => {
                        write_would_block = true;
                        break;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            if need_flush {
                match Pin::new(&mut self.io).poll_flush(cx) {
                    Poll::Ready(Ok(())) => (),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => write_would_block = true,
                }
            }

            while !self.eof && self.session.wants_read() {
                match self.read_io(cx) {
                    Poll::Ready(Ok(0)) => self.eof = true,
                    Poll::Ready(Ok(n)) => rdlen += n,
                    Poll::Pending => {
                        read_would_block = true;
                        break;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            return match (self.eof, self.session.is_handshaking()) {
                (true, true) => {
                    let err = io::Error::new(io::ErrorKind::UnexpectedEof, "tls handshake eof");
                    Poll::Ready(Err(err))
                }
                (_, false) => Poll::Ready(Ok((rdlen, wrlen))),
                (_, true) if write_would_block || read_would_block => {
                    if rdlen != 0 || wrlen != 0 {
                        Poll::Ready(Ok((rdlen, wrlen)))
                    } else {
                        Poll::Pending
                    }
                }
                (..) => continue,
            };
        }
    }

    /// Fills the buffer with data from the TLS session.
    ///
    /// # Arguments
    ///
    /// * `cx` - A mutable reference to the task context.
    ///
    /// # Returns
    ///
    /// A `Poll` indicating the result of the buffer fill operation.
    fn poll_fill_buf(mut self, cx: &mut Context<'_>) -> Poll<io::Result<&'a [u8]>> {
        let mut io_pending = false;

        while !self.eof && self.session.wants_read() {
            match self.read_io(cx) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(_)) => (),
                Poll::Pending => {
                    io_pending = true;
                    break;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }

        if !self.session.received_plaintext.is_empty() {
            Poll::Ready(Ok(&self.session.received_plaintext))
        } else {
            match self.session.check_no_bytes_state() {
                Ok(_) => Poll::Ready(Ok(&[])),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if !io_pending {
                        // if `wants_read()` is satisfied, we will never return a WouldBlock but if we do, we can try again
                        cx.waker().wake_by_ref();
                    }
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for Stream<'_, IO> {
    /// Polls to read data into the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `cx` - A mutable reference to the task context.
    /// * `buf` - A mutable slice of bytes to store the read data.
    ///
    /// # Returns
    ///
    /// A `Poll` indicating the result of the read operation.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let data = ready!(self.as_mut().poll_fill_buf(cx))?;
        let amt = std::cmp::min(data.len(), buf.len());
        buf[..amt].copy_from_slice(&data[..amt]);
        self.session.core.received_plaintext.drain(0..amt);
        Poll::Ready(Ok(amt))
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncBufRead for Stream<'_, IO> {
    /// Polls to fill the buffer with data.
    ///
    /// # Arguments
    ///
    /// * `cx` - A mutable reference to the task context.
    ///
    /// # Returns
    ///
    /// A `Poll` indicating the result of the buffer fill operation.
    fn poll_fill_buf(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        Stream {
            // reborrow
            io: this.io,
            session: this.session,
            ..*this
        }
        .poll_fill_buf(cx)
    }

    /// Consumes the specified amount of data from the buffer.
    ///
    /// # Arguments
    ///
    /// * `amt` - The amount of data to consume.
    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        self.session.received_plaintext.drain(0..amt);
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Stream<'_, IO> {
    /// Polls to write data from the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `cx` - A mutable reference to the task context.
    /// * `buf` - A slice of bytes to write.
    ///
    /// # Returns
    ///
    /// A `Poll` indicating the result of the write operation.
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut pos = 0;
        while pos != buf.len() {
            let mut would_block = false;
            pos += self.session.send_plain(&buf[pos..]);

            while self.session.wants_write() {
                match self.write_io(cx) {
                    Poll::Ready(Ok(0)) | Poll::Pending => {
                        would_block = true;
                        break;
                    }
                    Poll::Ready(Ok(_)) => (),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            return match (pos, would_block) {
                (0, true) => Poll::Pending,
                (n, true) => Poll::Ready(Ok(n)),
                (_, false) => continue,
            };
        }

        Poll::Ready(Ok(buf.len()))
    }

    /// Polls to flush the I/O object.
    ///
    /// # Arguments
    ///
    /// * `cx` - A mutable reference to the task context.
    ///
    /// # Returns
    ///
    /// A `Poll` indicating the result of the flush operation.
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.session.wants_write() {
            if ready!(self.write_io(cx))? == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }
        Pin::new(&mut self.io).poll_flush(cx)
    }

    /// Polls to close the I/O object.
    ///
    /// # Arguments
    ///
    /// * `cx` - A mutable reference to the task context.
    ///
    /// # Returns
    ///
    /// A `Poll` indicating the result of the close operation.
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.session.wants_write() {
            if ready!(self.write_io(cx))? == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }

        Poll::Ready(match ready!(Pin::new(&mut self.io).poll_close(cx)) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotConnected => Ok(()),
            Err(e) => Err(e),
        })
    }
}

/// Represents the state of a TLS connection.
enum TlsState {
    /// The connection is in a streaming state.
    Stream,
    /// The read side of the connection is shut down.
    ReadShutdown,
    /// The write side of the connection is shut down.
    WriteShutdown,
    /// Both sides of the connection are shut down.
    Shutdown,
}

impl TlsState {
    /// Shuts down the write side of the connection.
    fn shutdown_write(&mut self) {
        match self {
            TlsState::Stream => *self = TlsState::WriteShutdown,
            TlsState::ReadShutdown => *self = TlsState::Shutdown,
            _ => (),
        }
    }

    /// Shuts down the read side of the connection.
    fn shutdown_read(&mut self) {
        match self {
            TlsState::Stream => *self = TlsState::ReadShutdown,
            TlsState::WriteShutdown => *self = TlsState::Shutdown,
            _ => (),
        }
    }

    /// Checks if the connection is readable.
    ///
    /// # Returns
    ///
    /// `true` if the connection is readable, `false` otherwise.
    fn readable(&self) -> bool {
        !matches!(*self, TlsState::ReadShutdown | TlsState::Shutdown)
    }

    /// Checks if the connection is writable.
    ///
    /// # Returns
    ///
    /// `true` if the connection is writable, `false` otherwise.
    fn writeable(&self) -> bool {
        !matches!(self, TlsState::WriteShutdown | TlsState::Shutdown)
    }
}

/// A structure representing an owned stream with a TLS connection.
pub struct StreamOwned<IO> {
    /// The I/O object.
    pub(crate) io: IO,
    /// The TLS connection session.
    pub(crate) session: ConnectionWrapper,
    /// The state of the TLS connection.
    state: TlsState,
}

impl<IO> AsyncRead for StreamOwned<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Polls to read data into the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `cx` - A mutable reference to the task context.
    /// * `buf` - A mutable slice of bytes to store the read data.
    ///
    /// # Returns
    ///
    /// A `Poll` indicating the result of the read operation.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let data = ready!(self.as_mut().poll_fill_buf(cx))?;
        let len = data.len().min(buf.len());
        buf[..len].copy_from_slice(&data[..len]);
        self.consume(len);
        Poll::Ready(Ok(len))
    }
}

impl<IO> AsyncBufRead for StreamOwned<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Polls to fill the buffer with data.
    ///
    /// # Arguments
    ///
    /// * `cx` - A mutable reference to the task context.
    ///
    /// # Returns
    ///
    /// A `Poll` indicating the result of the buffer fill operation.
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        match self.state {
            TlsState::Stream | TlsState::WriteShutdown => {
                let this = self.get_mut();
                let stream =
                    Stream::new(&mut this.session, &mut this.io).set_eof(!this.state.readable());

                match stream.poll_fill_buf(cx) {
                    Poll::Ready(Ok(buf)) => {
                        if buf.is_empty() {
                            this.state.shutdown_read();
                        }

                        Poll::Ready(Ok(buf))
                    }
                    Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::ConnectionAborted => {
                        this.state.shutdown_read();
                        Poll::Ready(Err(err))
                    }
                    output => output,
                }
            }
            TlsState::ReadShutdown | TlsState::Shutdown => Poll::Ready(Ok(&[])),
        }
    }

    /// Consumes the specified amount of data from the buffer.
    ///
    /// # Arguments
    ///
    /// * `amt` - The amount of data to consume.
    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        self.session.received_plaintext.drain(0..amt);
    }
}

impl<IO> AsyncWrite for StreamOwned<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Polls to write data from the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `cx` - A mutable reference to the task context.
    /// * `buf` - A slice of bytes to write.
    ///
    /// # Returns
    ///
    /// A `Poll` indicating the result of the write operation.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.session, &mut this.io).set_eof(!this.state.readable());
        stream.as_mut_pin().poll_write(cx, buf)
    }

    /// Polls to flush the I/O object.
    ///
    /// # Arguments
    ///
    /// * `cx` - A mutable reference to the task context.
    ///
    /// # Returns
    ///
    /// A `Poll` indicating the result of the flush operation.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.session, &mut this.io).set_eof(!this.state.readable());
        stream.as_mut_pin().poll_flush(cx)
    }

    /// Polls to close the I/O object.
    ///
    /// # Arguments
    ///
    /// * `cx` - A mutable reference to the task context.
    ///
    /// # Returns
    ///
    /// A `Poll` indicating the result of the close operation.
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.state.writeable() {
            // TODO: Send close notify
            self.state.shutdown_write();
        }

        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.session, &mut this.io).set_eof(!this.state.readable());
        stream.as_mut_pin().poll_close(cx)
    }
}
/// A structure representing a lazy acceptor.
///
/// This structure contains an acceptor, an optional I/O object, and an optional alert.
pub struct LazyAcceptor<IO> {
    /// The acceptor.
    acceptor: Acceptor,
    /// An optional I/O object.
    io: Option<IO>,
    /// An optional alert containing an error and an accepted alert.
    alert: Option<(Error, AcceptedAlert)>,
}

impl<IO> LazyAcceptor<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Creates a new `LazyAcceptor` instance.
    ///
    /// # Arguments
    ///
    /// * `acceptor` - The acceptor.
    /// * `io` - The I/O object.
    ///
    /// # Returns
    ///
    /// A new `LazyAcceptor` instance.
    pub fn new(acceptor: Acceptor, io: IO) -> Self {
        Self {
            acceptor,
            io: Some(io),
            alert: None,
        }
    }
}

impl<IO> Future for LazyAcceptor<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<StartHandshake<IO>, io::Error>;

    /// Polls the lazy acceptor to progress the future.
    ///
    /// # Arguments
    ///
    /// * `cx` - A mutable reference to the task context.
    ///
    /// # Returns
    ///
    /// A `Poll` indicating the result of the future.
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            let io = match this.io.as_mut() {
                None => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        "acceptor cant be polled after acceptance",
                    )));
                }
                Some(io) => io,
            };

            if let Some((err, mut alert)) = this.alert.take() {
                match alert.write(&mut WriteSyncConverter { io, cx }) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        this.alert = Some((err, alert));
                        return Poll::Pending;
                    }
                    Ok(0) | Err(_) => {
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, err)));
                    }
                    Ok(_) => {
                        this.alert = Some((err, alert));
                        continue;
                    }
                }
            }

            let mut reader = ReadSyncConverter { io, cx };
            match this.acceptor.read_tls(&mut reader) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()).into(),
                Ok(_) => (),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Err(e).into(),
            }

            match this.acceptor.accept() {
                Ok(Some(accepted)) => {
                    let io = this.io.take().unwrap();
                    return Poll::Ready(Ok(StartHandshake { accepted, io }));
                }
                Ok(None) => {}
                Err((err, alert)) => {
                    this.alert = Some((err, alert));
                }
            }
        }
    }
}

/// A wrapper for a TLS connection.
pub(crate) struct ConnectionWrapper(Connection);

impl Deref for ConnectionWrapper {
    type Target = Connection;

    /// Dereferences the connection wrapper to get the connection.
    ///
    /// # Returns
    ///
    /// A reference to the connection.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ConnectionWrapper {
    /// Dereferences the connection wrapper to get a mutable reference to the connection.
    ///
    /// # Returns
    ///
    /// A mutable reference to the connection.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A structure representing the start of a handshake.
///
/// This structure contains the accepted connection and the I/O object.
pub struct StartHandshake<IO> {
    /// The accepted connection.
    accepted: Accepted,
    /// The I/O object.
    io: IO,
}

impl<IO> StartHandshake<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Returns the client hello message.
    ///
    /// # Returns
    ///
    /// The client hello message.
    pub fn client_hello(&self) -> ClientHello {
        self.accepted.client_hello()
    }

    /// Converts the start handshake into a stream.
    ///
    /// # Arguments
    ///
    /// * `config` - A reference to the server configuration.
    ///
    /// # Returns
    ///
    /// An `Accept` instance.
    pub fn into_stream(self, config: Arc<ServerConfig>) -> Accept<IO> {
        let mut conn = match self.accepted.into_connection(config) {
            Ok(conn) => conn,
            Err((err, alert)) => {
                return Accept(MidHandshake::SendAlert {
                    io: self.io,
                    err: io::Error::new(io::ErrorKind::InvalidData, err),
                    alert,
                })
            }
        };

        Accept(MidHandshake::Handshaking(StreamOwned {
            session: ConnectionWrapper(conn),
            io: self.io,
            state: TlsState::Stream,
        }))
    }

    /// Takes the I/O object.
    ///
    /// # Returns
    ///
    /// The I/O object.
    pub fn take_io(self) -> IO {
        self.io
    }
}

/// A trait representing a session.
///
/// This trait provides methods to get mutable references to the state, I/O object, and session,
/// and to convert the session into the I/O object.
trait Session {
    type IO;
    type Session;

    /// Gets mutable references to the state, I/O object, and session.
    ///
    /// # Returns
    ///
    /// A tuple containing mutable references to the state, I/O object, and session.
    fn get_mut(&mut self) -> (&mut TlsState, &mut Self::IO, &mut Self::Session);

    /// Converts the session into the I/O object.
    ///
    /// # Returns
    ///
    /// The I/O object.
    fn into_io(self) -> Self::IO;
}

impl<IO> Session for StreamOwned<IO> {
    type IO = IO;
    type Session = ConnectionWrapper;

    /// Gets mutable references to the state, I/O object, and session.
    ///
    /// # Returns
    ///
    /// A tuple containing mutable references to the state, I/O object, and session.
    fn get_mut(&mut self) -> (&mut TlsState, &mut Self::IO, &mut Self::Session) {
        (&mut self.state, &mut self.io, &mut self.session)
    }

    /// Converts the session into the I/O object.
    ///
    /// # Returns
    ///
    /// The I/O object.
    fn into_io(self) -> Self::IO {
        self.io
    }
}

/// A structure representing an accept operation.
///
/// This structure contains a mid-handshake state.
pub struct Accept<IO>(MidHandshake<StreamOwned<IO>>);

/// An enumeration representing the mid-handshake state.
///
/// This enumeration contains variants for handshaking, end, sending an alert, and an error.
enum MidHandshake<S: Session> {
    /// The handshaking state.
    Handshaking(S),
    /// The end state.
    End,
    /// The state for sending an alert.
    SendAlert {
        /// The I/O object.
        io: S::IO,
        /// The error.
        err: io::Error,
        /// The accepted alert.
        alert: AcceptedAlert,
    },
    /// The error state.
    Error {
        /// The I/O object.
        io: S::IO,
        /// The error.
        error: io::Error,
    },
}

impl<S: Session + Unpin> Future for MidHandshake<S>
where
    S::IO: AsyncRead + AsyncWrite + Unpin,
    S::Session: DerefMut + Deref<Target = Connection> + Unpin,
{
    type Output = Result<S, (io::Error, S::IO)>;

    /// Polls the mid-handshake state to progress the future.
    ///
    /// # Arguments
    ///
    /// * `cx` - A mutable reference to the task context.
    ///
    /// # Returns
    ///
    /// A `Poll` indicating the result of the future.
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let mut stream = match mem::replace(this, MidHandshake::End) {
            MidHandshake::Handshaking(stream) => stream,
            MidHandshake::SendAlert {
                mut io,
                mut alert,
                err,
            } => loop {
                match alert.write(&mut WriteSyncConverter { io: &mut io, cx }) {
                    Ok(_) => (),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        *this = MidHandshake::SendAlert { io, alert, err };
                        return Poll::Pending;
                    }
                    Err(_) | Ok(0) => return Poll::Ready(Err((err, io))),
                }
            },
            MidHandshake::Error { io, error } => return Poll::Ready(Err((error, io))),
            _ => panic!("unexpected polling after finish"),
        };

        let (state, io, session) = stream.get_mut();
        let mut tls_stream = Stream::new(session, io).set_eof(!state.readable());

        macro_rules! try_poll {
            ( $e:expr ) => {
                match $e {
                    Poll::Ready(Ok(_)) => (),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err((err, stream.into_io()))),
                    Poll::Pending => {
                        *this = MidHandshake::Handshaking(stream);
                        return Poll::Pending;
                    }
                }
            };
        }

        while tls_stream.session.is_handshaking() {
            try_poll!(tls_stream.handshake(cx));
        }

        try_poll!(Pin::new(&mut tls_stream).poll_flush(cx));

        Poll::Ready(Ok(stream))
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Accept<IO> {
    type Output = io::Result<StreamOwned<IO>>;

    /// Polls the accept operation to progress the future.
    ///
    /// # Arguments
    ///
    /// * `cx` - A mutable reference to the task context.
    ///
    /// # Returns
    ///
    /// A `Poll` indicating the result of the future.
    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map_err(|(err, _)| err)
    }
}
