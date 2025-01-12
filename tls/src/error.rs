#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InvalidMessage {
    MessageTooShort,
    MissingData(&'static str),
    InvalidCCS,
    TrailingData(&'static str),
    CertificatePayloadTooLarge,
}
