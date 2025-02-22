use std::{
    io, mem,
    ops::{Deref, DerefMut},
};

use crate::crypto::kx::SupportedKxGroup;
use crate::{
    error::Error,
    message::{
        enums::ContentType,
        hs::HandshakePayload,
        inbound::{DeframerIter, InboundPlainMessage},
        Message, MessagePayload,
    },
    state::{self, Context, State},
};
use crate::message::deframer::VecDeframerBuffer;

// don't need version, only supporting 1.2
pub struct TlsState {
    may_send_appdata: bool,
    may_recv_appdata: bool,
    sendable_tls: Vec<u8>,
    pub(crate) recived_plaintext: Vec<u8>,
    has_recived_close: bool,
    pub(crate) kx_state: KxState,
    has_seen_eof: bool
}

pub(crate) enum KxState {
    None,
    Start(&'static dyn SupportedKxGroup),
    Done(&'static dyn SupportedKxGroup),
}
impl TlsState {
    fn new() -> Self {
        Self {
            may_send_appdata: false,
            may_recv_appdata: false,
            sendable_tls: Vec::new(),
            recived_plaintext: Vec::new(),
            has_recived_close: false,
            kx_state: KxState::None,
            has_seen_eof: false,
        }
    }

    pub(crate) fn is_handshaking(&self) -> bool {
        !(self.may_recv_appdata && self.may_recv_appdata)
    }

    pub(crate) fn wants_write(&self) -> bool {
        !self.sendable_tls.is_empty()
    }

    pub(crate) fn wants_read(&self) -> bool {
        self.recived_plaintext.is_empty()
            && !self.has_recived_close
            && (self.may_send_appdata || self.sendable_tls.is_empty())
    }

    pub(crate) fn write_tls(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        match wr.write(&self.sendable_tls) {
            Ok(len) => {
                self.sendable_tls.drain(..len);
                Ok(len)
            }
            Err(e) => Err(e),
        }
    }

    fn process_main_protocol(
        &mut self,
        message: Message<'_>,
        mut state: Box<dyn State>,
        sendable_plaintext: &mut Vec<u8>,
    ) -> Result<Box<dyn State>, Error> {
        if self.may_send_appdata {
            if matches!(
                message.payload,
                MessagePayload::HandshakePayload(HandshakePayload::ClientHello(_))
            ) {
                self.send_warning(0u8);
                return Ok(state);
            }
        };

        let mut cx = Context { state: self };
        match state.handle(&mut cx, message) {
            Ok(state) => return Ok(state),
            Err(_) => todo!(),
        }
    }
    pub fn send_warning(&self, discription: u8) -> Error {
        todo!()
    }

    pub fn send_fatal(&self, description: u8) -> Error {
        todo!()
    }
}

// ONLY IMPLEMENTING SERVERSIDE TLS
pub struct ConnectionCore {
    state: Result<Box<dyn State>, Error>,
    tls_state: TlsState,
}

impl ConnectionCore {
    fn new(state: Box<dyn State>, tls_state: TlsState) -> Self {
        Self {
            state: Ok(state),
            tls_state,
        }
    }

    fn process_new_packets(
        &mut self,
        deframer: &mut VecDeframerBuffer,
        sendable_plaintext: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let mut state = match mem::replace(&mut self.state, Err(Error::HandshakeNotCompleate)) {
            Ok(state) => state,
            Err(err) => {
                self.state = Err(err.clone());
                return Err(err);
            }
        };

        let mut progress = 0;
        loop {
            let res = self.deframe(deframer.filled_mut());

            let msg_opt = match res {
                Ok(opt) => opt,
                Err(_) => todo!(),
            };

            let Some((msg, size)) = msg_opt else {
                break;
            };
            progress += size;

            match self.process_msg(msg, state, sendable_plaintext) {
                Ok(s) => state = s,
                Err(_) => todo!(),
            }
        }

        self.state = Ok(state);

        todo!()
    }

    fn deframe<'b>(
        &mut self,
        buffer: &'b mut [u8],
    ) -> Result<Option<(InboundPlainMessage<'b>, usize)>, Error> {
        let is_handshaking = self.is_handshaking();

        let mut iter = DeframerIter::new(buffer);
        let message = match iter.next().transpose() {
            Ok(Some(message)) => message,
            Ok(None) => return Ok(None),
            Err(e) => todo!("{:?}", e),
        };

        let allowed_plaintext = match message.typ {
            ContentType::Handshake | ContentType::ChangeCipherSpec => true,
            ContentType::Alert => is_handshaking,
            _ => false,
        };

        if allowed_plaintext {
            return Ok(Some((message.into(), iter.consumed())));
        }

        todo!();
    }

    fn process_msg(
        &mut self,
        msg: InboundPlainMessage,
        state: Box<dyn State>,
        sendable_plaintext: &mut Vec<u8>,
    ) -> Result<Box<dyn State>, Error> {
        let msg = match Message::try_from(msg) {
            Ok(msg) => msg,
            Err(_) => todo!(),
        };

        self.process_main_protocol(msg, state, sendable_plaintext)
    }
}

impl Deref for ConnectionCore {
    type Target = TlsState;

    fn deref(&self) -> &Self::Target {
        &self.tls_state
    }
}

impl DerefMut for ConnectionCore {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tls_state
    }
}

pub struct Connection {
    core: ConnectionCore,
    deframer_buffer: VecDeframerBuffer,
    sendable_plaintext: Vec<u8>,
}

impl Deref for Connection {
    type Target = ConnectionCore;

    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl DerefMut for Connection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.core
    }
}

impl Connection {
    pub fn new() -> Self {
        Self {
            core: ConnectionCore::new(Box::new(state::ExpectClientHello::new()), TlsState::new()),
            deframer_buffer: VecDeframerBuffer::new(),
            sendable_plaintext: Vec::new(),
        }
    }

    pub(crate) fn read_tls(&mut self, r: &mut dyn io::Read, in_hs: bool) -> io::Result<usize> {
        // TODO: Change this to use a better deframer system, rn trying to read messages that are all 0s aka temp data in the vec
        const MAX_HS_SIZE: usize = 0xffff;

        const READ_SIZE: usize = 4096;

        let allowed_max = match in_hs {
            true => MAX_HS_SIZE,
            false => READ_SIZE,
        };


        let res  = self.deframer_buffer.read(r, self.is_handshaking());
        if let Ok(0) = res {
            self.has_seen_eof = true;
        }
        res
    }

    pub(crate) fn compleate_io<T: io::Read + io::Write>(
        &mut self,
        io: &mut T,
    ) -> Result<(usize, usize), io::Error> {
        let mut eof = false;
        let mut rlen = 0;
        let mut wlen = 0;

        loop {
            if !self.wants_read() && !self.wants_write() {
                return Ok((rlen, wlen));
            }

            while self.wants_write() {
                match self.write_tls(io)? {
                    0 => {
                        io.flush()?;
                        return Ok((rlen, wlen));
                    }
                    n => wlen += n,
                }
            }
            io.flush()?;

            if !self.is_handshaking() && wlen > 0 {
                return Ok((rlen, wlen));
            }

            while !eof && self.wants_read() {
                let bytes_read = match self.read_tls(io, self.is_handshaking()) {
                    Ok(0) => {
                        eof = true;
                        Some(0)
                    }
                    Ok(n) => {
                        rlen += n;
                        Some(n)
                    }
                    Err(ref err) if err.kind() == io::ErrorKind::Interrupted => None,
                    Err(err) => return Err(err),
                };

                if bytes_read.is_some() {
                    break;
                }
            }

            match self.process_new_packets() {
                Ok(_) => {}
                Err(e) => {
                    _ = self.write_tls(io);
                    _ = io.flush();

                    return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                }
            }
        }
    }

    #[inline]
    fn process_new_packets(&mut self) -> Result<(), Error> {
        self.core
            .process_new_packets(&mut self.deframer_buffer, &mut self.sendable_plaintext)
    }
}
