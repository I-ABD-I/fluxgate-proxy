use crate::config::ServerConfig;
use crate::crypto::kx::SupportedKxGroup;
use crate::message::alert::{AlertDescription, AlertLevel, AlertPayload};
use crate::message::deframer::VecDeframerBuffer;
use crate::message::enums::ProtocolVersion;
use crate::message::fragmenter::MessageFragmenter;
use crate::message::outbound::{OutboundOpaqueMessage, OutboundPlainMessage};
use crate::message::PlainMessage;
use crate::record_layer::RecordLayer;
use crate::state::ConnectionSecrets;
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
use log::{debug, error, warn};
use rustls_pki_types::DnsName;
use std::io::Write;
use std::sync::Arc;
use std::{
    io, mem,
    ops::{Deref, DerefMut},
};

// don't need version, only supporting 1.2
/// Represents the state of a TLS connection.
pub struct TlsState {
    /// Indicates if application data can be sent.
    may_send_appdata: bool,
    /// Indicates if application data can be received.
    may_recv_appdata: bool,
    /// Buffer for sendable TLS data.
    pub(crate) sendable_tls: Vec<u8>,
    /// Buffer for received plaintext data.
    pub(crate) received_plaintext: Vec<u8>,
    /// Indicates if a close notification has been received.
    has_received_close: bool,
    /// Key exchange state.
    pub(crate) kx_state: KxState,
    /// Indicates if EOF has been seen.
    has_seen_eof: bool,
    /// Record layer for managing TLS records.
    pub(crate) record_layer: RecordLayer,
    /// Fragmenter for handling message fragmentation.
    fragmenter: MessageFragmenter,
    /// Server Name Indication (SNI) value.
    pub(crate) sni: Option<DnsName<'static>>,
}

/// Represents the state of key exchange.
pub(crate) enum KxState {
    /// No key exchange.
    None,
    /// Key exchange started with the specified group.
    Start(&'static dyn SupportedKxGroup),
    /// Key exchange completed with the specified group.
    Done(&'static dyn SupportedKxGroup),
}

impl KxState {
    /// Marks the key exchange as done.
    pub(crate) fn done(&mut self) {
        if let Self::Start(group) = self {
            *self = Self::Done(*group);
        }
    }
}

impl Default for TlsState {
    /// Creates a new `TlsState` with default values.
    fn default() -> Self {
        Self::new()
    }
}

impl TlsState {
    /// Creates a new `TlsState`.
    pub fn new() -> Self {
        Self {
            may_send_appdata: false,
            may_recv_appdata: false,
            sendable_tls: Vec::new(),
            received_plaintext: Vec::new(),
            has_received_close: false,
            kx_state: KxState::None,
            has_seen_eof: false,
            record_layer: RecordLayer::new(),
            fragmenter: MessageFragmenter,
            sni: None,
        }
    }

    /// Checks if the connection is in the handshaking state.
    ///
    /// # Returns
    /// `true` if handshaking, `false` otherwise.
    pub(crate) fn is_handshaking(&self) -> bool {
        !(self.may_recv_appdata && self.may_send_appdata)
    }

    /// Checks if the connection wants to write data.
    ///
    /// # Returns
    /// `true` if there is data to write, `false` otherwise.
    pub(crate) fn wants_write(&self) -> bool {
        !self.sendable_tls.is_empty()
    }

    /// Checks if the connection wants to read data.
    ///
    /// # Returns
    /// `true` if there is data to read, `false` otherwise.
    pub(crate) fn wants_read(&self) -> bool {
        self.received_plaintext.is_empty()
            && !self.has_received_close
            && (self.may_send_appdata || self.sendable_tls.is_empty())
    }

    /// Writes TLS data to the given writer.
    ///
    /// # Arguments
    /// * `wr` - The writer to write to.
    ///
    /// # Returns
    /// The number of bytes written or an error.
    pub(crate) fn write_tls(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        self.sendable_tls.write_to(wr)
    }

    /// Processes the main protocol logic.
    ///
    /// # Arguments
    /// * `message` - The message to process.
    /// * `state` - The current state.
    /// * `sendable_plaintext` - The buffer for sendable plaintext.
    ///
    /// # Returns
    /// The next state or an error.
    fn process_main_protocol(
        &mut self,
        message: Message<'_>,
        mut state: Box<dyn State>,
        sendable_plaintext: &mut [u8],
    ) -> Result<Box<dyn State>, Error> {
        if self.may_send_appdata
            && matches!(
                message.payload,
                MessagePayload::HandshakePayload(HandshakePayload::ClientHello(_))
            )
        {
            self.send_warning(AlertDescription::NoRenegotiation);
            return Ok(state);
        };

        let mut cx = Context { state: self };
        match state.handle(&mut cx, message) {
            Ok(state) => Ok(state),
            Err(e) => todo!("{e:?}"),
        }
    }

    /// Starts encryption with the given connection secrets.
    ///
    /// # Arguments
    /// * `secrets` - The connection secrets.
    pub(crate) fn start_encryption(&mut self, secrets: &ConnectionSecrets) {
        let (dec, enc) = secrets.make_cipher_pair();
        self.record_layer.prepare_encrypter(enc);
        self.record_layer.prepare_decrypter(dec);
    }

    /// Queues a TLS message for sending.
    ///
    /// # Arguments
    /// * `msg` - The message to queue.
    fn queue_tls_message(&mut self, msg: OutboundOpaqueMessage) {
        self.sendable_tls.append(&mut msg.encode())
    }

    /// Sends a TLS message.
    ///
    /// # Arguments
    /// * `msg` - The message to send.
    /// * `must_encrypt` - Indicates if the message must be encrypted.
    pub fn send_message(&mut self, msg: Message<'_>, must_encrypt: bool) {
        if !must_encrypt {
            self.fragmenter
                .fragment_message(&msg.into())
                .for_each(|fragment| self.queue_tls_message(fragment.to_unencrypted_opaque()));
            return;
        }

        self.fragmenter
            .fragment_message(&msg.into())
            .for_each(|fragment| self.send_single_fragment(fragment));
    }

    /// Sends a single fragment of a TLS message.
    ///
    /// # Arguments
    /// * `m` - The fragment to send.
    fn send_single_fragment(&mut self, m: OutboundPlainMessage<'_>) {
        let em = self.record_layer.encrypt(m);
        self.queue_tls_message(em);
    }

    /// Sends plaintext data.
    ///
    /// # Arguments
    /// * `sendable_plaintext` - The plaintext data to send.
    ///
    /// # Returns
    /// The number of bytes sent.
    pub fn send_plain(&mut self, sendable_plaintext: &[u8]) -> usize {
        // not buffering for now;
        self.send_plain_non_buffering(sendable_plaintext)
    }

    /// Sends plaintext data without buffering.
    ///
    /// # Arguments
    /// * `payload` - The plaintext data to send.
    ///
    /// # Returns
    /// The number of bytes sent.
    fn send_plain_non_buffering(&mut self, payload: &[u8]) -> usize {
        if payload.is_empty() {
            return 0;
        }

        self.send_appdata_encrypt(payload)
    }

    /// Encrypts and sends application data.
    ///
    /// # Arguments
    /// * `payload` - The application data to send.
    ///
    /// # Returns
    /// The number of bytes sent.
    fn send_appdata_encrypt(&mut self, payload: &[u8]) -> usize {
        self.fragmenter
            .fragment_payload(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                payload,
            )
            .for_each(|fragment| self.send_single_fragment(fragment));
        payload.len()
    }

    /// Starts the traffic flow.
    pub(crate) fn start_traffic(&mut self) {
        self.may_recv_appdata = true;
        self.may_send_appdata = true;
    }

    /// Sends a warning alert.
    ///
    /// # Arguments
    /// * `description` - The alert description.
    pub fn send_warning(&mut self, description: AlertDescription) {
        warn!("Sending warning: {description:?}");
        let msg = Message::build_alert(AlertLevel::Warning, description);
        self.send_message(msg, self.record_layer.should_encrypt());
    }

    /// Sends a fatal alert and returns an error.
    ///
    /// # Arguments
    /// * `description` - The alert description.
    /// * `err` - The error to send.
    ///
    /// # Returns
    /// The error.
    pub fn send_fatal(&mut self, description: AlertDescription, err: impl Into<Error>) -> Error {
        error!("Sending error: {description:?}");
        let m = Message::build_alert(AlertLevel::Fatal, description);
        self.send_message(m, self.record_layer.should_encrypt());
        err.into()
    }

    /// Processes an alert message.
    ///
    /// # Arguments
    /// * `alert` - The alert payload.
    ///
    /// # Returns
    /// `Ok` if the alert was processed successfully, otherwise an error.
    fn process_alert(&mut self, alert: &AlertPayload) -> Result<(), Error> {
        if let AlertLevel::Unknown(_) = alert.level {
            return Err(self.send_fatal(
                AlertDescription::IllegalParameter,
                Error::AlertReceived(alert.description),
            ));
        }

        if self.may_recv_appdata && alert.description == AlertDescription::CloseNotify {
            self.has_received_close = true;
            return Ok(());
        };

        if alert.level == AlertLevel::Warning {
            warn!("Received Alert {alert:?}");
            return Ok(());
        }

        error!("Received fatal alert {alert:?}");
        Err(Error::AlertReceived(alert.description))
    }

    /// Checks the state of the connection when no bytes are available.
    ///
    /// # Returns
    /// `Ok` if the state is valid, otherwise an error.
    pub(crate) fn check_no_bytes_state(&self) -> io::Result<()> {
        match (self.has_received_close, self.has_seen_eof) {
            (true, _) => Ok(()),
            (false, true) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF during handshake",
            )),
            (false, false) => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    pub fn send_close_notify(&mut self) {
        self.send_warning(AlertDescription::CloseNotify);
    }
}
// ONLY IMPLEMENTING SERVERSIDE TLS
/// Represents the core of a TLS connection.
pub struct ConnectionCore {
    /// The current state of the connection.
    state: Result<Box<dyn State>, Error>,
    /// The TLS state.
    pub(crate) tls_state: TlsState,
}

impl ConnectionCore {
    /// Creates a new `ConnectionCore`.
    ///
    /// # Arguments
    /// * `state` - The initial state of the connection.
    /// * `tls_state` - The TLS state.
    ///
    /// # Returns
    /// A new `ConnectionCore` instance.
    pub fn new(state: Box<dyn State>, tls_state: TlsState) -> Self {
        Self {
            state: Ok(state),
            tls_state,
        }
    }

    /// Processes new packets from the deframer.
    ///
    /// # Arguments
    /// * `deframer` - The deframer buffer.
    /// * `sendable_plaintext` - The buffer for sendable plaintext.
    ///
    /// # Returns
    /// `Ok(())` if successful, otherwise an error.
    fn process_new_packets(
        &mut self,
        deframer: &mut VecDeframerBuffer,
        sendable_plaintext: &mut [u8],
    ) -> Result<(), Error> {
        let mut state = match mem::replace(&mut self.state, Err(Error::HandshakeNotCompleate)) {
            Ok(state) => state,
            Err(err) => {
                self.state = Err(err.clone());
                return Err(err);
            }
        };

        loop {
            let res = self.deframe(deframer.filled_mut());

            let msg_opt = match res {
                Ok(opt) => opt,
                Err(_) => todo!(),
            };

            let Some((msg, size)) = msg_opt else {
                break;
            };

            match self.process_msg(msg, state, sendable_plaintext) {
                Ok(s) => state = s,
                Err(e) => {
                    self.state = Err(e.clone());
                    deframer.discard(size);
                    return Err(e);
                }
            }

            if self.has_received_close {
                deframer.discard(deframer.filled().len());
                break;
            }

            deframer.discard(size);
        }

        self.state = Ok(state);
        Ok(())
    }

    /// Deframes a buffer into a message.
    ///
    /// # Arguments
    /// * `buffer` - The buffer to deframe.
    ///
    /// # Returns
    /// An optional tuple containing the inbound plain message and its size, or an error.
    fn deframe<'b>(
        &mut self,
        buffer: &'b mut [u8],
    ) -> Result<Option<(InboundPlainMessage<'b>, usize)>, Error> {
        let is_handshaking = self.is_handshaking();

        let mut iter = DeframerIter::new(buffer);
        let message = match iter.next().transpose() {
            Ok(Some(message)) => message,
            Ok(None) => return Ok(None),
            Err(e) => return Err(self.handle_deframe_error(e)),
        };

        let allowed_plaintext = match message.typ {
            // CCS is always plaintext
            ContentType::ChangeCipherSpec => true,
            // Handshake Finished Message should not be plaintext!!
            ContentType::Handshake => !self.record_layer.should_decrypt(),
            ContentType::Alert => is_handshaking,
            _ => false,
        };

        if allowed_plaintext {
            return Ok(Some((message.into(), iter.consumed())));
        }

        let message = match self.record_layer.decrypt(message) {
            Ok(message) => message,
            Err(e) => todo!("handle decryption error {:?}", e),
        };

        Ok(Some((message, iter.consumed())))
    }

    /// Processes a message.
    ///
    /// # Arguments
    /// * `msg` - The inbound plain message.
    /// * `state` - The current state.
    /// * `sendable_plaintext` - The buffer for sendable plaintext.
    ///
    /// # Returns
    /// The next state or an error.
    fn process_msg(
        &mut self,
        msg: InboundPlainMessage,
        state: Box<dyn State>,
        sendable_plaintext: &mut [u8],
    ) -> Result<Box<dyn State>, Error> {
        let msg = match Message::try_from(msg) {
            Ok(msg) => msg,
            Err(e) => todo!("{:?}", e),
        };

        if let MessagePayload::Alert(alert) = &msg.payload {
            self.process_alert(alert)?;
            return Ok(state);
        }

        self.process_main_protocol(msg, state, sendable_plaintext)
    }

    /// Handles deframe errors.
    ///
    /// # Arguments
    /// * `err` - The error to handle.
    ///
    /// # Returns
    /// The handled error.
    fn handle_deframe_error(&mut self, err: Error) -> Error {
        match err {
            Error::InvalidMessage(err) => self.send_fatal(AlertDescription::DecodeError, err),
            Error::PeerSendOversizedRecord => {
                self.send_fatal(AlertDescription::RecordOverflow, err)
            }
            Error::DecryptError => self.send_fatal(AlertDescription::DecryptError, err),
            error => error,
        }
    }
}

impl Deref for ConnectionCore {
    /// The target type for dereferencing.
    type Target = TlsState;

    /// Dereferences the `ConnectionCore` to access the `TlsState`.
    ///
    /// # Returns
    /// A reference to the `TlsState`.
    fn deref(&self) -> &Self::Target {
        &self.tls_state
    }
}

impl DerefMut for ConnectionCore {
    /// Dereferences the `ConnectionCore` to access the `TlsState` mutably.
    ///
    /// # Returns
    /// A mutable reference to the `TlsState`.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tls_state
    }
}

/// Represents a TLS connection.
pub struct Connection {
    /// The core of the connection.
    pub(crate) core: ConnectionCore,
    /// The deframer buffer.
    deframer_buffer: VecDeframerBuffer,
    /// The buffer for sendable plaintext.
    sendable_plaintext: Vec<u8>,
}

impl From<ConnectionCore> for Connection {
    /// Creates a `Connection` from a `ConnectionCore`.
    ///
    /// # Arguments
    /// * `core` - The connection core.
    ///
    /// # Returns
    /// A new `Connection` instance.
    fn from(core: ConnectionCore) -> Self {
        Self {
            core,
            deframer_buffer: VecDeframerBuffer::new(),
            sendable_plaintext: Vec::new(),
        }
    }
}

impl Deref for Connection {
    /// The target type for dereferencing.
    type Target = ConnectionCore;

    /// Dereferences the `Connection` to access the `ConnectionCore`.
    ///
    /// # Returns
    /// A reference to the `ConnectionCore`.
    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl DerefMut for Connection {
    /// Dereferences the `Connection` to access the `ConnectionCore` mutably.
    ///
    /// # Returns
    /// A mutable reference to the `ConnectionCore`.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.core
    }
}

impl Connection {
    /// Creates a new `Connection`.
    ///
    /// # Arguments
    /// * `config` - The server configuration.
    ///
    /// # Returns
    /// A new `Connection` instance.
    pub fn new(config: Arc<ServerConfig>) -> Self {
        ConnectionCore::new(
            Box::new(state::ExpectClientHello::new(config)),
            TlsState::new(),
        )
        .into()
    }

    /// Reads TLS data from the given reader.
    ///
    /// # Arguments
    /// * `r` - The reader to read from.
    ///
    /// # Returns
    /// The number of bytes read or an error.
    pub(crate) fn read_tls(&mut self, r: &mut dyn io::Read) -> io::Result<usize> {
        let res = self.deframer_buffer.read(r, self.is_handshaking());
        if let Ok(0) = res {
            self.has_seen_eof = true;
        }
        res
    }

    /// Completes I/O operations for the connection.
    ///
    /// # Arguments
    /// * `io` - The I/O object to read from and write to.
    ///
    /// # Returns
    /// A tuple containing the number of bytes read and written, or an error.
    pub(crate) fn complete_io<T: io::Read + io::Write>(
        &mut self,
        io: &mut T,
    ) -> Result<(usize, usize), io::Error> {
        let mut eof = false;
        let mut read_len = 0;
        let mut write_len = 0;

        loop {
            if !self.wants_read() && !self.wants_write() {
                return Ok((read_len, write_len));
            }

            while self.wants_write() {
                match self.write_tls(io)? {
                    0 => {
                        io.flush()?;
                        return Ok((read_len, write_len));
                    }
                    n => write_len += n,
                }
            }
            io.flush()?;

            if !self.is_handshaking() && write_len > 0 {
                return Ok((read_len, write_len));
            }

            while !eof && self.wants_read() {
                let bytes_read = match self.read_tls(io) {
                    Ok(0) => {
                        eof = true;
                        Some(0)
                    }
                    Ok(n) => {
                        read_len += n;
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

    /// Processes new packets.
    ///
    /// # Returns
    /// `Ok(())` if successful, otherwise an error.
    #[inline]
    pub(crate) fn process_new_packets(&mut self) -> Result<(), Error> {
        self.core
            .process_new_packets(&mut self.deframer_buffer, &mut self.sendable_plaintext)
    }

    /// Retrieves the first handshake message.
    ///
    /// # Returns
    /// An optional handshake message or an error.
    pub(crate) fn first_handshake_message(&mut self) -> Result<Option<Message<'static>>, Error> {
        let (res) = self
            .core
            .deframe(self.deframer_buffer.filled_mut())
            .map(|opt| opt.map(|(pm, len)| Message::try_from(pm).map(|m| (m.into_owned(), len))));

        match res? {
            Some(Ok((msg, len))) => {
                self.deframer_buffer.discard(len);
                Ok(Some(msg))
            }
            Some(Err(err)) => Err(self.send_fatal(AlertDescription::DecodeError, err)),
            None => Ok(None),
        }
    }

    /// Replaces the current state with a new state.
    ///
    /// # Arguments
    /// * `state` - The new state.
    pub(crate) fn replace_state(&mut self, state: Box<dyn State>) {
        self.core.state = Ok(state);
    }
}

/// Trait for writing data to an I/O object.
pub trait WriteTo {
    /// Writes data to the given writer.
    ///
    /// # Arguments
    /// * `wr` - The writer to write to.
    ///
    /// # Returns
    /// The number of bytes written or an error.
    fn write_to(&mut self, wr: &mut dyn io::Write) -> io::Result<usize>;
}

impl WriteTo for Vec<u8> {
    /// Writes data from the vector to the given writer.
    ///
    /// # Arguments
    /// * `wr` - The writer to write to.
    ///
    /// # Returns
    /// The number of bytes written or an error.
    fn write_to(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        match wr.write(self) {
            Ok(len) => {
                self.drain(..len);
                Ok(len)
            }
            Err(e) => Err(e),
        }
    }
}
