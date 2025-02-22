use core::fmt;

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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Error {
    HandshakeNotCompleate,
    InvalidMessage(InvalidMessage),
    InappropriateHandshakeMessage,
    FailedToGetRandom,
    General(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::HandshakeNotCompleate => write!(f, "Handshake not compleate"),
            Error::InvalidMessage(_) => write!(f, "invalid message"),
            Error::InappropriateHandshakeMessage => write!(f, "inaproptiate handshake message"),
            Error::FailedToGetRandom => write!(f, "failed to get random"),

            Error::General(s) => f.write_str(s),
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
