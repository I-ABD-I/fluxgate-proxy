use crate::message::alert::{AlertDescription, AlertPayload};
use crate::message::enums::ContentType;
use crate::message::MessagePayload;
use core::fmt;
use log::warn;
use std::fmt::write;

/// Represents an invalid message error.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InvalidMessage {
    /// The message is too short.
    MessageTooShort,
    /// Missing data in the message.
    MissingData(&'static str),
    /// Invalid Change Cipher Spec (CCS) message.
    InvalidCCS,
    /// Trailing data in the message.
    TrailingData(&'static str),
    /// The certificate payload is too large.
    CertificatePayloadTooLarge,
    /// The payload is empty.
    InvalidEmptyPayload,
    /// The message is too large.
    MessageTooLarge,
    /// The content type is invalid.
    InvalidContentType,
    /// The protocol version is unknown.
    UnknownProtocolVersion,
    /// The curve is unsupported.
    UnsupportedCurve,
}

/// Represents an error in the TLS connection.
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// The handshake is not complete.
    HandshakeNotCompleate,
    /// An invalid message was received.
    InvalidMessage(InvalidMessage),
    /// An inappropriate handshake message was received.
    InappropriateHandshakeMessage,
    /// Failed to get random data.
    FailedToGetRandom,
    /// A general error occurred.
    General(&'static str),
    /// An error occurred during encryption.
    #[allow(clippy::enum_variant_names)]
    EncryptError,
    /// An error occurred during decryption.
    #[allow(clippy::enum_variant_names)]
    DecryptError,
    /// The peer sent an oversized record.
    PeerSendOversizedRecord,
    /// An inappropriate message was received.
    InappropriateMessage {
        /// The expected content types.
        expect_types: Vec<ContentType>,
        /// The received content type.
        got_type: ContentType,
    },
    /// An alert was received.
    AlertReceived(AlertDescription),
}

impl fmt::Display for Error {
    /// Formats the error for display.
    ///
    /// # Arguments
    /// * `f` - The formatter.
    ///
    /// # Returns
    /// A result indicating success or failure.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::HandshakeNotCompleate => write!(f, "Handshake not compleate"),
            Error::InvalidMessage(_) => write!(f, "invalid message"),
            Error::InappropriateHandshakeMessage => write!(f, "inaproptiate handshake message"),
            Error::FailedToGetRandom => write!(f, "failed to get random"),
            Error::General(s) => f.write_str(s),
            Error::EncryptError => write!(f, "failed to encrypt"),
            Error::DecryptError => write!(f, "failed to decrypt"),
            Error::PeerSendOversizedRecord => write!(f, "peer send oversized record"),
            Error::InappropriateMessage { .. } => write!(f, "inappropriate message"),
            Error::AlertReceived(alert) => write!(f, "received alert {alert:?}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<InvalidMessage> for Error {
    /// Converts an `InvalidMessage` into an `Error`.
    ///
    /// # Arguments
    /// * `value` - The invalid message.
    ///
    /// # Returns
    /// The corresponding error.
    fn from(value: InvalidMessage) -> Self {
        Error::InvalidMessage(value)
    }
}

/// Represents an error in a message.
#[derive(Debug)]
pub enum MessageError {
    /// The message is too short for the header.
    TooShortForHeader,
    /// The message is too short for the length.
    TooShortForLength,
    /// The payload is empty.
    InvalidEmptyPayload,
    /// The message is too large.
    MessageTooLarge,
    /// The content type is invalid.
    InvalidContentType,
    /// The protocol version is unknown.
    UnknownProtocolVersion,
}

/// Represents a failure to get random data.
pub struct GetRandomFailed;

impl From<GetRandomFailed> for Error {
    /// Converts a `GetRandomFailed` into an `Error`.
    ///
    /// # Arguments
    /// * `value` - The failure to get random data.
    ///
    /// # Returns
    /// The corresponding error.
    fn from(value: GetRandomFailed) -> Self {
        Self::FailedToGetRandom
    }
}

/// Creates an inappropriate message error.
///
/// # Arguments
/// * `payload` - The message payload.
/// * `content_types` - The expected content types.
///
/// # Returns
/// The corresponding error.
pub(crate) fn inappropriate_message(
    payload: &MessagePayload<'_>,
    content_types: &[ContentType],
) -> Error {
    warn!(
        "Received a {:?} message while expecting {:?}",
        payload.content_type(),
        content_types
    );
    Error::InappropriateMessage {
        expect_types: content_types.to_vec(),
        got_type: payload.content_type(),
    }
}
