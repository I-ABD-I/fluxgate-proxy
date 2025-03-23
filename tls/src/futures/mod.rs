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

pub struct Stream<'a, IO> {
    pub(crate) io: &'a mut IO,
    pub(crate) session: &'a mut Connection,
    eof: bool,
}

impl<'a, IO> Stream<'a, IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn new(session: &'a mut Connection, io: &'a mut IO) -> Self {
        Self {
            io,
            session,
            eof: false,
        }
    }

    fn set_eof(mut self, eof: bool) -> Self {
        self.eof = eof;
        self
    }

    fn as_mut_pin(&mut self) -> Pin<&mut Self> {
        Pin::new(self)
    }
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

    pub fn write_io(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
        let mut writer = WriteSyncConverter { io: self.io, cx };
        match self.session.write_tls(&mut writer) {
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            res => Poll::Ready(res),
        }
    }

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

        if self.session.received_plaintext.len() > 0 {
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

impl<'a, IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for Stream<'a, IO> {
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

impl<'a, IO: AsyncRead + AsyncWrite + Unpin> AsyncBufRead for Stream<'a, IO> {
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

    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        self.session.received_plaintext.drain(0..amt);
    }
}
impl<'a, IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Stream<'a, IO> {
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

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.session.wants_write() {
            if ready!(self.write_io(cx))? == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }
        Pin::new(&mut self.io).poll_flush(cx)
    }

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

enum TlsState {
    Stream,
    ReadShutdown,
    WriteShutdown,
    Shutdown,
}

impl TlsState {
    fn shutdown_write(&mut self) {
        match self {
            TlsState::Stream => *self = TlsState::WriteShutdown,
            TlsState::ReadShutdown => *self = TlsState::Shutdown,
            _ => (),
        }
    }
    fn shutdown_read(&mut self) {
        match self {
            TlsState::Stream => *self = TlsState::ReadShutdown,
            TlsState::WriteShutdown => *self = TlsState::Shutdown,
            _ => (),
        }
    }
    fn readable(&self) -> bool {
        !matches!(self, TlsState::ReadShutdown | TlsState::Shutdown)
    }

    fn writeable(&self) -> bool {
        !matches!(self, TlsState::WriteShutdown | TlsState::Shutdown)
    }
}
pub struct StreamOwned<IO> {
    pub(crate) io: IO,
    pub(crate) session: ConnectionWrapper,
    state: TlsState,
}

impl<IO> AsyncRead for StreamOwned<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
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

    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        self.session.received_plaintext.drain(0..amt);
    }
}

impl<IO> AsyncWrite for StreamOwned<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
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

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.session, &mut this.io).set_eof(!this.state.readable());
        stream.as_mut_pin().poll_flush(cx)
    }

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

pub struct LazyAcceptor<IO> {
    acceptor: Acceptor,
    io: Option<IO>,
    alert: Option<(Error, AcceptedAlert)>,
}

impl<IO> LazyAcceptor<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
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
pub(crate) struct ConnectionWrapper(Connection);

impl Deref for ConnectionWrapper {
    type Target = Connection;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ConnectionWrapper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
pub struct StartHandshake<IO> {
    accepted: Accepted,
    io: IO,
}

impl<IO> StartHandshake<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub fn client_hello(&self) -> ClientHello {
        self.accepted.client_hello()
    }

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
}

trait Session {
    type IO;
    type Session;

    fn get_mut(&mut self) -> (&mut TlsState, &mut Self::IO, &mut Self::Session);
    fn into_io(self) -> Self::IO;
}

impl<IO> Session for StreamOwned<IO> {
    type IO = IO;
    type Session = ConnectionWrapper;

    fn get_mut(&mut self) -> (&mut TlsState, &mut Self::IO, &mut Self::Session) {
        (&mut self.state, &mut self.io, &mut self.session)
    }
    fn into_io(self) -> Self::IO {
        self.io
    }
}
pub struct Accept<IO>(MidHandshake<StreamOwned<IO>>);

enum MidHandshake<S: Session> {
    Handshaking(S),
    End,
    SendAlert {
        io: S::IO,
        err: io::Error,
        alert: AcceptedAlert,
    },
    Error {
        io: S::IO,
        error: io::Error,
    },
}

impl<S: Session + Unpin> Future for MidHandshake<S>
where
    S::IO: AsyncRead + AsyncWrite + Unpin,
    S::Session: DerefMut + Deref<Target = Connection> + Unpin,
{
    type Output = Result<S, (io::Error, S::IO)>;

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

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map_err(|(err, _)| err)
    }
}
