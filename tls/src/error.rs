use crate::message::alert::{AlertDescription, AlertPayload};
use crate::message::enums::ContentType;
use crate::message::MessagePayload;
use core::fmt;
use log::warn;
use std::fmt::write;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InvalidMessage {
    MessageTooShort,
    MissingData(&'static str),
    InvalidCCS,
    TrailingData(&'static str),
    CertificatePayloadTooLarge,
    InvalidEmptyPayload,
    MessageTooLarge,
    InvalidContentType,
    UnknownProtocolVersion,
    UnsupportedCurve,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    HandshakeNotCompleate,
    InvalidMessage(InvalidMessage),
    InappropriateHandshakeMessage,
    FailedToGetRandom,
    General(&'static str),
    #[allow(clippy::enum_variant_names)]
    EncryptError,
    #[allow(clippy::enum_variant_names)]
    DecryptError,
    PeerSendOversizedRecord,
    InappropriateMessage {
        expect_types: Vec<ContentType>,
        got_type: ContentType,
    },
    AlertReceived(AlertDescription),
}

impl fmt::Display for Error {
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
    fn from(value: InvalidMessage) -> Self {
        Error::InvalidMessage(value)
    }
}

#[derive(Debug)]
pub enum MessageError {
    TooShortForHeader,
    TooShortForLength,
    InvalidEmptyPayload,
    MessageTooLarge,
    InvalidContentType,
    UnknownProtocolVersion,
}

pub struct GetRandomFailed;

impl From<GetRandomFailed> for Error {
    fn from(value: GetRandomFailed) -> Self {
        Self::FailedToGetRandom
    }
}

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
