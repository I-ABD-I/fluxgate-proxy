use crate::config::ServerConfig;
use crate::connection::{ConnectionCore, TlsState, WriteTo};
use crate::error::Error;
use crate::message::enums::SignatureScheme;
use crate::message::hs::{ClientHelloPayload, HandshakePayload};
use crate::message::{Message, MessagePayload};
use crate::server::Connection;
use crate::state;
use crate::state::ClientHello;
use std::io;
use std::sync::Arc;

/// Represents the state of accepting a TLS connection.
struct Accepting;

impl state::State for Accepting {
    /// Handles the state transition for the given message.
    ///
    /// # Arguments
    /// * `cx` - The context of the current state.
    /// * `message` - The message to handle.
    ///
    /// # Returns
    /// * `Result<Box<dyn state::State>, Error>` - The next state or an error.
    fn handle(
        self: Box<Self>,
        cx: &mut state::Context,
        message: Message<'_>,
    ) -> Result<Box<dyn state::State>, Error> {
        unreachable!();
    }
}

/// Represents a TLS acceptor.
pub struct Acceptor {
    /// The inner connection.
    inner: Option<Connection>,
}

impl Default for Acceptor {
    /// Creates a new `Acceptor` with default settings.
    ///
    /// # Returns
    /// * `Self` - The new `Acceptor` instance.
    fn default() -> Self {
        Self {
            inner: Some(ConnectionCore::new(Box::new(Accepting), TlsState::new()).into()),
        }
    }
}

impl Acceptor {
    /// Reads TLS data from the given reader.
    ///
    /// # Arguments
    /// * `rd` - The reader to read from.
    ///
    /// # Returns
    /// * `io::Result<usize>` - The number of bytes read or an error.
    pub fn read_tls(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        match &mut self.inner {
            Some(conn) => conn.read_tls(rd),
            None => Err(io::Error::new(
                io::ErrorKind::Other,
                "acceptor cannot read after acceptance",
            )),
        }
    }

    /// Accepts a TLS connection.
    ///
    /// # Returns
    /// * `Result<Option<Accepted>, (Error, AcceptedAlert)>` - The accepted connection or an error.
    pub fn accept(&mut self) -> Result<Option<Accepted>, (Error, AcceptedAlert)> {
        let Some(mut connection) = self.inner.take() else {
            return Err((
                Error::General("Acceptor polled after completion"),
                AcceptedAlert::empty(),
            ));
        };

        let message = match connection.first_handshake_message() {
            Ok(Some(message)) => message,
            Ok(None) => {
                self.inner = Some(connection);
                return Ok(None);
            }
            Err(err) => return Err((err, AcceptedAlert::from(connection))),
        };

        let mut cx = state::Context {
            state: &mut connection.tls_state,
        };
        let sigschemes = match state::process_client_hello(&message, &mut cx) {
            Ok((_, sigschemes)) => sigschemes,
            Err(err) => return Err((err, AcceptedAlert::from(connection))),
        };

        Ok(Some(Accepted {
            connection,
            message,
            signature_schemes: sigschemes,
        }))
    }
}

/// Represents an alert sent after acceptance.
pub struct AcceptedAlert(Vec<u8>);

impl AcceptedAlert {
    /// Creates an empty `AcceptedAlert`.
    ///
    /// # Returns
    /// * `Self` - The new `AcceptedAlert` instance.
    pub(super) fn empty() -> Self {
        Self(Vec::new())
    }

    /// Sends the alert to the client.
    ///
    /// # Arguments
    /// * `wr` - The writer to write to.
    ///
    /// # Returns
    /// * `Result<usize, io::Error>` - The number of bytes written or an error.
    pub fn write(&mut self, wr: &mut dyn io::Write) -> Result<usize, io::Error> {
        self.0.write_to(wr)
    }

    /// Sends the alert to the client, ensuring the entire buffer is written.
    ///
    /// # Arguments
    /// * `wr` - The writer to write to.
    ///
    /// # Returns
    /// * `Result<(), io::Error>` - An error if writing fails.
    pub fn write_all(&mut self, wr: &mut dyn io::Write) -> Result<(), io::Error> {
        while self.write(wr)? != 0 {}
        Ok(())
    }
}

impl From<Connection> for AcceptedAlert {
    /// Converts a `Connection` into an `AcceptedAlert`.
    ///
    /// # Arguments
    /// * `conn` - The connection to convert.
    ///
    /// # Returns
    /// * `Self` - The new `AcceptedAlert` instance.
    fn from(conn: Connection) -> Self {
        Self(conn.core.tls_state.sendable_tls)
    }
}

/// Represents an accepted TLS connection.
pub struct Accepted {
    /// The connection.
    connection: Connection,
    /// The message.
    message: Message<'static>,
    /// The supported signature schemes.
    signature_schemes: Vec<SignatureScheme>,
}

impl Accepted {
    /// Returns the client hello message.
    ///
    /// # Returns
    /// * `ClientHello<'_>` - The client hello message.
    pub fn client_hello(&self) -> ClientHello<'_> {
        let payload = Self::client_hello_payload(&self.message);
         ClientHello {
            server_name: &self.connection.sni,
            sigschemes: &self.signature_schemes,
            cipher_suites: &payload.cipher_suites,
        }
    }

    /// Returns the client hello payload.
    ///
    /// # Arguments
    /// * `message` - The message to extract the payload from.
    ///
    /// # Returns
    /// * `&'a ClientHelloPayload` - The client hello payload.
    fn client_hello_payload<'a>(message: &'a Message<'_>) -> &'a ClientHelloPayload {
        match &message.payload {
            MessagePayload::HandshakePayload(HandshakePayload::ClientHello(ch)) => ch,
            _ => unreachable!(),
        }
    }

    /// Converts the accepted connection into a `Connection`.
    ///
    /// # Arguments
    /// * `config` - The server configuration.
    ///
    /// # Returns
    /// * `Result<Connection, (Error, AcceptedAlert)>` - The new connection or an error.
    pub fn into_connection(
        mut self,
        config: Arc<ServerConfig>,
    ) -> Result<Connection, (Error, AcceptedAlert)> {
        let conn_state = state::ExpectClientHello::new(config);
        let mut cx = state::Context {
            state: &mut self.connection.tls_state,
        };

        let ch = Self::client_hello_payload(&self.message);
        let new =
            match conn_state.with_certified_key(self.signature_schemes, ch, &self.message, &mut cx)
            {
                Ok(new) => new,
                Err(err) => return Err((err, AcceptedAlert::from(self.connection))),
            };

        self.connection.replace_state(new);

        Ok(self.connection)
    }
}