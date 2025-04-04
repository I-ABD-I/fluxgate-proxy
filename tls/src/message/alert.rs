use crate::codec::Codec;
use crate::codec::Reader;
use crate::error::InvalidMessage;

enum_builder! {
    #[repr(u8)]
    pub enum AlertLevel {
        Warning => 1,
        Fatal => 2,
    }
}

enum_builder! {
    #[repr(u8)]
    pub enum AlertDescription {
        CloseNotify => 0,
        UnexpectedMessage => 10,
        BadRecordMac => 20,
        DecryptionFailedReserved => 21,
        RecordOverflow => 22,
        DecompressionFailure => 30,
        HandshakeFailure => 40,
        NoCertificateReserved => 41,
        BadCertificate => 42,
        UnsupportedCertificate => 43,
        CertificateRevoked => 44,
        CertificateExpired => 45,
        CertificateUnknown => 46,
        IllegalParameter => 47,
        UnknownCa => 48,
        AccessDenied => 49,
        DecodeError => 50,
        DecryptError => 51,
        ExportRestrictionReserved => 60,
        ProtocolVersion => 70,
        InsufficientSecurity => 71,
        InternalError => 80,
        UserCanceled => 90,
        NoRenegotiation => 100,
        UnsupportedExtension => 110,
    }
}

/// Represents the payload of an alert message in TLS.
#[derive(Debug, Clone)]
pub struct AlertPayload {
    /// The level of the alert.
    pub(crate) level: AlertLevel,
    /// The description of the alert.
    pub(crate) description: AlertDescription,
}

impl Codec<'_> for AlertPayload {
    /// Encodes the alert payload into a byte vector.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A mutable reference to a byte vector where the encoded payload will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.level.encode(bytes);
        self.description.encode(bytes);
    }

    /// Reads an alert payload from a byte reader.
    ///
    /// # Arguments
    ///
    /// * `r` - A mutable reference to a byte reader.
    ///
    /// # Returns
    ///
    /// A result containing the alert payload or an invalid message error.
    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let level = AlertLevel::read(r)?;
        let description = AlertDescription::read(r)?;
        r.expect_empty("AlertPayload")
            .map(|_| Self { level, description })
    }
}
