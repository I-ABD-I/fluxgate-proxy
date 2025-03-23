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

struct Accepting;

impl state::State for Accepting {
    fn handle(
        self: Box<Self>,
        cx: &mut state::Context,
        message: Message<'_>,
    ) -> Result<Box<dyn state::State>, Error> {
        unreachable!();
    }
}
pub struct Acceptor {
    inner: Option<Connection>,
}

impl Default for Acceptor {
    fn default() -> Self {
        Self {
            inner: Some(ConnectionCore::new(Box::new(Accepting), TlsState::new()).into()),
        }
    }
}

impl Acceptor {
    pub fn read_tls(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        match &mut self.inner {
            Some(conn) => conn.read_tls(rd),
            None => Err(io::Error::new(
                io::ErrorKind::Other,
                "acceptor cannot read after acceptance",
            )),
        }
    }

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

pub struct AcceptedAlert(Vec<u8>);

impl AcceptedAlert {
    pub(super) fn empty() -> Self {
        Self(Vec::new())
    }

    /// Send the alert to the client.
    ///
    /// To account for short writes this function should be called repeatedly until it
    /// returns `Ok(0)` or an error.
    pub fn write(&mut self, wr: &mut dyn io::Write) -> Result<usize, io::Error> {
        self.0.write_to(wr)
    }

    /// Send the alert to the client.
    ///
    /// This function will invoke the writer until the buffer is empty.
    pub fn write_all(&mut self, wr: &mut dyn io::Write) -> Result<(), io::Error> {
        while self.write(wr)? != 0 {}
        Ok(())
    }
}

impl From<Connection> for AcceptedAlert {
    fn from(conn: Connection) -> Self {
        Self(conn.core.tls_state.sendable_tls)
    }
}
pub struct Accepted {
    connection: Connection,
    message: Message<'static>,
    signature_schemes: Vec<SignatureScheme>,
}

impl Accepted {
    pub fn client_hello(&self) -> ClientHello<'_> {
        let payload = Self::client_hello_payload(&self.message);
         ClientHello {
            server_name: &self.connection.sni,
            sigschemes: &self.signature_schemes,
            cipher_suites: &payload.cipher_suites,
        }
    }

    fn client_hello_payload<'a>(message: &'a Message<'_>) -> &'a ClientHelloPayload {
        match &message.payload {
            MessagePayload::HandshakePayload(HandshakePayload::ClientHello(ch)) => ch,
            _ => unreachable!(),
        }
    }

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
