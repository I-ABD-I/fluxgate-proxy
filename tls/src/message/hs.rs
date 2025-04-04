use rustls_pki_types::{CertificateDer, DnsName};

use crate::codec::u24;
use crate::codec::Codec;
use crate::codec::LengthPrefixedBuffer;
use crate::codec::ListLength;
use crate::codec::Reader;
use crate::codec::TLSListElement;
use crate::crypto::kx::ActiveKx;
use crate::crypto::SecureRandom;
use crate::error::{GetRandomFailed, InvalidMessage};
use crate::message::hs::HandshakePayload::{HelloRequest, ServerHelloDone};
use crate::verify::DigitallySinged;

use super::base::PayloadU16;
use super::base::{Payload, PayloadU8};
use super::enums::ProtocolVersion;
use super::enums::SignatureAlgorithm;
use super::enums::{CipherSuite, NamedCurve};
use super::enums::{CompressionMethod, ECPointFormat};
use super::enums::{ECCurveType, ExtensionType, ServerNameType};
use super::enums::{HashAlgorithm, SignatureScheme};

enum_builder! {
    /// Enum representing different types of handshake messages in the TLS protocol.
    ///
    /// Each variant corresponds to a specific handshake message type, with an associated
    /// numeric value as defined by the TLS protocol.
    #[repr(u8)]
    pub enum HandshakeType {
        HelloRequest => 0,
        ClientHello => 1,
        ServerHello => 2,
        Certificate => 11,
        ServerKeyExchange => 12,
        CertificateRequest => 13,
        ServerHelloDone => 14,
        CertificateVerify => 15,
        ClientKeyExchange => 16,
        Finished => 20,
    }
}
/// Enum representing different types of handshake payloads in the TLS protocol.
///
/// Each variant corresponds to a specific handshake message type, with associated data
/// as defined by the TLS protocol.
#[derive(Debug)]
pub enum HandshakePayload<'a> {
    /// HelloRequest message with no associated data.
    HelloRequest,
    /// ClientHello message containing the `ClientHelloPayload`.
    ClientHello(ClientHelloPayload),
    /// ServerHello message containing the `ServerHelloPayload`.
    ServerHello(ServerHelloPayload),
    /// Certificate message containing a chain of certificates.
    Certificate(CertificateChain<'a>),
    /// ServerKeyExchange message containing the `ServerKeyExchangePayload`.
    ServerKeyExchange(ServerKeyExchangePayload),
    /// ServerHelloDone message with no associated data.
    ServerHelloDone,
    /// CertificateVerify message containing a digitally signed structure.
    CertificateVerify(DigitallySinged),
    /// ClientKeyExchange message containing a payload.
    ClientKeyExchange(Payload<'a>),
    /// Finished message containing a payload.
    Finished(Payload<'a>),
    /// Unknown message containing a payload.
    Unknown(Payload<'a>),
}
impl HandshakePayload<'_> {
    /// Returns the `HandshakeType` corresponding to the `HandshakePayload`.
    ///
    /// # Returns
    /// * `HandshakeType` - The type of the handshake message.
    fn typ(&self) -> HandshakeType {
        match self {
            HandshakePayload::HelloRequest => HandshakeType::HelloRequest,
            HandshakePayload::ClientHello(_) => HandshakeType::ClientHello,
            HandshakePayload::ServerHello(_) => HandshakeType::ServerHello,
            HandshakePayload::Certificate(_) => HandshakeType::Certificate,
            HandshakePayload::ServerKeyExchange(_) => HandshakeType::ServerKeyExchange,
            HandshakePayload::ServerHelloDone => HandshakeType::ServerHelloDone,
            HandshakePayload::CertificateVerify(_) => HandshakeType::CertificateVerify,
            HandshakePayload::ClientKeyExchange(_) => HandshakeType::ClientKeyExchange,
            HandshakePayload::Finished(_) => HandshakeType::Finished,
            HandshakePayload::Unknown(_) => HandshakeType::Unknown(0),
        }
    }

    /// Converts the `HandshakePayload` into an owned version with a `'static` lifetime.
    ///
    /// # Returns
    /// * `HandshakePayload<'static>` - The owned version of the `HandshakePayload`.
    pub fn into_owned(self) -> HandshakePayload<'static> {
        use HandshakePayload::*;

        match self {
            HelloRequest => HelloRequest,
            ClientHello(x) => ClientHello(x),
            ServerHello(x) => ServerHello(x),
            Certificate(x) => Certificate(x.into_owned()),
            ServerKeyExchange(x) => ServerKeyExchange(x),
            CertificateVerify(x) => CertificateVerify(x),
            ServerHelloDone => ServerHelloDone,
            ClientKeyExchange(x) => ClientKeyExchange(x.into_owned()),
            Finished(x) => Finished(x.into_owned()),
            Unknown(x) => Unknown(x.into_owned()),
        }
    }
}
impl<'a> Codec<'a> for HandshakePayload<'a> {
    /// Encodes the `HandshakePayload` into a byte vector.
    ///
    /// # Arguments
    /// * `bytes` - A mutable reference to a vector of bytes where the encoded data will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.typ().encode(bytes);

        let mut nested = LengthPrefixedBuffer::new(
            ListLength::u24 {
                max: usize::MAX,
                error: InvalidMessage::MessageTooLarge,
            },
            bytes,
        );
        match self {
            HandshakePayload::HelloRequest => {}
            HandshakePayload::ClientHello(client_hello) => client_hello.encode(nested.buf),
            HandshakePayload::ServerHello(server_hello) => server_hello.encode(nested.buf),
            HandshakePayload::Certificate(certificate_chain) => {
                certificate_chain.encode(nested.buf)
            }
            HandshakePayload::ServerKeyExchange(kx) => kx.encode(nested.buf),
            HandshakePayload::ServerHelloDone => {}
            HandshakePayload::ClientKeyExchange(payload) => payload.encode(nested.buf),
            HandshakePayload::CertificateVerify(digitaly_singed) => {
                digitaly_singed.encode(nested.buf)
            }
            HandshakePayload::Finished(payload) => payload.encode(nested.buf),
            HandshakePayload::Unknown(payload) => payload.encode(nested.buf),
        }
    }

    /// Reads and decodes a `HandshakePayload` from a byte slice.
    ///
    /// # Arguments
    /// * `r` - A mutable reference to a `Reader` that provides the byte slice to read from.
    ///
    /// # Returns
    /// * `Result<Self, InvalidMessage>` - The decoded `HandshakePayload` or an error if decoding fails.
    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let typ = HandshakeType::read(r)?;
        let length = u24::read(r)?;
        let mut sub = r.slice(length.0 as usize)?;

        let hs = match typ {
            HandshakeType::HelloRequest => HandshakePayload::HelloRequest,
            HandshakeType::ClientHello => {
                HandshakePayload::ClientHello(ClientHelloPayload::read(&mut sub)?)
            }
            HandshakeType::ServerHello => {
                HandshakePayload::ServerHello(ServerHelloPayload::read(&mut sub)?)
            }
            HandshakeType::Certificate => {
                HandshakePayload::Certificate(CertificateChain::read(&mut sub)?)
            }
            HandshakeType::ServerKeyExchange => {
                HandshakePayload::ServerKeyExchange(ServerKeyExchangePayload::read(&mut sub)?)
            }
            HandshakeType::CertificateRequest => unreachable!(),
            HandshakeType::ServerHelloDone => HandshakePayload::ServerHelloDone,
            HandshakeType::CertificateVerify => {
                HandshakePayload::CertificateVerify(DigitallySinged::read(&mut sub)?)
            }
            HandshakeType::ClientKeyExchange => {
                HandshakePayload::ClientKeyExchange(Payload::read(&mut sub))
            }
            HandshakeType::Finished => HandshakePayload::Finished(Payload::read(&mut sub)),
            HandshakeType::Unknown(_) => HandshakePayload::Unknown(Payload::read(&mut sub)),
        };
        sub.expect_empty("HandshakePayload").map(|_| hs)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Random([u8; 32]);

impl Random {
    /// Creates a new `Random` instance filled with random bytes.
    ///
    /// # Arguments
    /// * `sr` - A reference to a `SecureRandom` trait object used to generate random bytes.
    ///
    /// # Returns
    /// * `Result<Self, GetRandomFailed>` - The new `Random` instance or an error if random byte generation fails.
    pub fn new(sr: &dyn SecureRandom) -> Result<Self, GetRandomFailed> {
        let mut bytes = [0u8; 32];
        sr.fill(&mut bytes)?;
        Ok(Self(bytes))
    }
}

impl Codec<'_> for Random {
    /// Encodes the `Random` instance into a byte vector.
    ///
    /// # Arguments
    /// * `bytes` - A mutable reference to a vector of bytes where the encoded data will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0);
    }

    /// Reads and decodes a `Random` instance from a byte slice.
    ///
    /// # Arguments
    /// * `r` - A mutable reference to a `Reader` that provides the byte slice to read from.
    ///
    /// # Returns
    /// * `Result<Self, InvalidMessage>` - The decoded `Random` instance or an error if decoding fails.
    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let Some(bytes) = r.take(32) else {
            return Err(InvalidMessage::MissingData("Random"));
        };
        let mut opaque = [0; 32];
        opaque.clone_from_slice(bytes);
        Ok(Self(opaque))
    }
}

impl AsRef<[u8]> for Random {
    /// Returns a reference to the byte array of the `Random` instance.
    ///
    /// # Returns
    /// * `&[u8]` - A reference to the byte array.
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SessionID {
    length: usize,
    data: [u8; 32],
}

impl SessionID {
    /// Creates an empty `SessionID` instance.
    ///
    /// # Returns
    /// * `Self` - The new empty `SessionID` instance.
    pub fn empty() -> Self {
        Self {
            data: [0u8; 32],
            length: 0,
        }
    }
}

impl Codec<'_> for SessionID {
    /// Encodes the `SessionID` instance into a byte vector.
    ///
    /// # Arguments
    /// * `bytes` - A mutable reference to a vector of bytes where the encoded data will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        debug_assert!(self.length <= 32);
        bytes.push(self.length as u8);
        bytes.extend_from_slice(&self.data[..self.length]);
    }

    /// Reads and decodes a `SessionID` instance from a byte slice.
    ///
    /// # Arguments
    /// * `r` - A mutable reference to a `Reader` that provides the byte slice to read from.
    ///
    /// # Returns
    /// * `Result<Self, InvalidMessage>` - The decoded `SessionID` instance or an error if decoding fails.
    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let length = u8::read(r)? as usize;
        if length > 32 {
            return Err(InvalidMessage::TrailingData("SessionID"));
        };

        let Some(bytes) = r.take(length) else {
            return Err(InvalidMessage::MissingData("SessionID"));
        };

        let mut out = [0u8; 32];
        out[..length].clone_from_slice(&bytes[..length]);
        Ok(Self { length, data: out })
    }
}
/// Represents an unknown extension in the TLS protocol.
///
/// This struct contains the type of the extension and its payload.
#[derive(Debug)]
pub struct UnknownExtension {
    /// The type of the extension.
    pub(crate) typ: ExtensionType,
    /// The payload of the extension.
    pub(crate) payload: Payload<'static>,
}

impl UnknownExtension {
    /// Encodes the `UnknownExtension` into a byte vector.
    ///
    /// # Arguments
    /// * `bytes` - A mutable reference to a vector of bytes where the encoded data will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.payload.encode(bytes);
    }

    /// Reads and decodes an `UnknownExtension` from a byte slice.
    ///
    /// # Arguments
    /// * `typ` - The type of the extension.
    /// * `r` - A mutable reference to a `Reader` that provides the byte slice to read from.
    ///
    /// # Returns
    /// * `Self` - The decoded `UnknownExtension`.
    fn read(typ: ExtensionType, r: &mut Reader<'_>) -> Self {
        let payload = Payload::read(r).into_owned();
        Self { typ, payload }
    }
}

/// Represents a signature and hash algorithm in the TLS protocol.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SignatureAndHashAlgorithm {
    /// The hash algorithm.
    pub(crate) hash: HashAlgorithm,
    /// The signature algorithm.
    pub(crate) signature: SignatureAlgorithm,
}

impl Codec<'_> for SignatureAndHashAlgorithm {
    /// Encodes the `SignatureAndHashAlgorithm` into a byte vector.
    ///
    /// # Arguments
    /// * `bytes` - A mutable reference to a vector of bytes where the encoded data will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.hash.encode(bytes);
        self.signature.encode(bytes);
    }

    /// Reads and decodes a `SignatureAndHashAlgorithm` from a byte slice.
    ///
    /// # Arguments
    /// * `r` - A mutable reference to a `Reader` that provides the byte slice to read from.
    ///
    /// # Returns
    /// * `Result<Self, InvalidMessage>` - The decoded `SignatureAndHashAlgorithm` or an error if decoding fails.
    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let hash = HashAlgorithm::read(r)?;
        let signature = SignatureAlgorithm::read(r)?;
        Ok(Self { hash, signature })
    }
}

/// Represents the payload of a server name in the TLS protocol.
#[derive(Debug)]
pub enum ServerNamePayload {
    /// Host name represented as a `DnsName`.
    HostName(DnsName<'static>),
    /// IP address represented as a `PayloadU16`.
    IpAddress(PayloadU16),
    /// Unknown server name payload.
    Unknown(Payload<'static>),
}

impl ServerNamePayload {
    /// Reads and decodes a host name from a byte slice.
    ///
    /// # Arguments
    /// * `r` - A mutable reference to a `Reader` that provides the byte slice to read from.
    ///
    /// # Returns
    /// * `Result<Self, InvalidMessage>` - The decoded `ServerNamePayload` or an error if decoding fails.
    fn read_hostname(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let raw = PayloadU16::read(r)?;

        use rustls_pki_types::ServerName;
        match ServerName::try_from(raw.0.as_slice()) {
            Ok(ServerName::DnsName(d)) => Ok(Self::HostName(d.to_owned())),
            Ok(ServerName::IpAddress(_)) => Ok(Self::IpAddress(raw)),
            Ok(_) | Err(_) => Err(InvalidMessage::MissingData("ServerName")),
        }
    }

    /// Encodes the `ServerNamePayload` into a byte vector.
    ///
    /// # Arguments
    /// * `bytes` - A mutable reference to a vector of bytes where the encoded data will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            ServerNamePayload::HostName(host_name) => {
                (host_name.as_ref().len() as u16).encode(bytes);
                bytes.extend_from_slice(host_name.as_ref().as_ref());
            }
            ServerNamePayload::IpAddress(ip_addr) => {
                ip_addr.encode(bytes);
            }
            ServerNamePayload::Unknown(payload) => {
                payload.encode(bytes);
            }
        }
    }
}

/// Represents a server name in the TLS protocol.
#[derive(Debug)]
pub struct ServerName {
    /// The type of the server name.
    pub(crate) typ: ServerNameType,
    /// The payload of the server name.
    pub(crate) payload: ServerNamePayload,
}

impl Codec<'_> for ServerName {
    /// Encodes the `ServerName` into a byte vector.
    ///
    /// # Arguments
    /// * `bytes` - A mutable reference to a vector of bytes where the encoded data will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.typ.encode(bytes);
        self.payload.encode(bytes)
    }

    /// Reads and decodes a `ServerName` from a byte slice.
    ///
    /// # Arguments
    /// * `r` - A mutable reference to a `Reader` that provides the byte slice to read from.
    ///
    /// # Returns
    /// * `Result<Self, InvalidMessage>` - The decoded `ServerName` or an error if decoding fails.
    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let typ = ServerNameType::read(r)?;

        let payload = match typ {
            ServerNameType::HostName => ServerNamePayload::read_hostname(r)?,
            _ => ServerNamePayload::Unknown(Payload::read(r).into_owned()),
        };

        Ok(Self { typ, payload })
    }
}

impl TLSListElement for SignatureScheme {
    const LENGHT_SIZE: ListLength = ListLength::u16;
}

impl TLSListElement for NamedCurve {
    const LENGHT_SIZE: ListLength = ListLength::u16;
}

impl TLSListElement for ECPointFormat {
    const LENGHT_SIZE: ListLength = ListLength::u8;
}

impl TLSListElement for ServerName {
    const LENGHT_SIZE: ListLength = ListLength::u16;
}

/// Represents a client extension in the TLS protocol.
#[derive(Debug)]
pub enum ClientExtension {
    /// Signature extension containing a vector of `SignatureScheme`.
    Signature(Vec<SignatureScheme>),
    /// Named groups extension containing a vector of `NamedCurve`.
    NamedGroups(Vec<NamedCurve>),
    /// EC point formats extension containing a vector of `ECPointFormat`.
    ECPointFormats(Vec<ECPointFormat>),
    /// Server name extension containing a vector of `ServerName`.
    ServerName(Vec<ServerName>),
    /// Unknown extension.
    Unknown(UnknownExtension),
} // TODO: support extension

impl ClientExtension {
    /// Returns the `ExtensionType` corresponding to the `ClientExtension`.
    ///
    /// # Returns
    /// * `ExtensionType` - The type of the extension.
    pub fn ext_typ(&self) -> ExtensionType {
        match self {
            ClientExtension::ECPointFormats(_) => ExtensionType::ECPointFormats,
            ClientExtension::Signature(_) => ExtensionType::SignatureAlgorithm,
            ClientExtension::NamedGroups(_) => ExtensionType::EllipticCurves,
            ClientExtension::ServerName(_) => ExtensionType::ServerName,
            ClientExtension::Unknown(ref r) => r.typ,
        }
    }
}

impl Codec<'_> for ClientExtension {
    /// Encodes the `ClientExtension` into a byte vector.
    ///
    /// # Arguments
    /// * `bytes` - A mutable reference to a vector of bytes where the encoded data will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.ext_typ().encode(bytes);
        let nest = LengthPrefixedBuffer::new(ListLength::u16, bytes);
        match self {
            ClientExtension::ServerName(ref r) => r.encode(nest.buf),
            ClientExtension::Signature(ref r) => r.encode(nest.buf),
            ClientExtension::NamedGroups(ref r) => r.encode(nest.buf),
            ClientExtension::Unknown(ref r) => r.encode(nest.buf),
            ClientExtension::ECPointFormats(ref r) => r.encode(nest.buf),
        }
    }

    /// Reads and decodes a `ClientExtension` from a byte slice.
    ///
    /// # Arguments
    /// * `r` - A mutable reference to a `Reader` that provides the byte slice to read from.
    ///
    /// # Returns
    /// * `Result<Self, InvalidMessage>` - The decoded `ClientExtension` or an error if decoding fails.
    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let typ = ExtensionType::read(r)?;
        let length = u16::read(r)?;
        let mut sub = r.slice(length as usize)?;
        let ext = match typ {
            ExtensionType::SignatureAlgorithm => Self::Signature(Vec::read(&mut sub)?),
            ExtensionType::EllipticCurves => Self::NamedGroups(Vec::read(&mut sub)?),
            ExtensionType::ServerName => Self::ServerName(Vec::read(&mut sub)?),
            _ => Self::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        sub.expect_empty("ClientExtension").map(|_| ext)
    }
}

/// Represents a server extension in the TLS protocol.
#[derive(Debug)]
pub enum ServerExtension {
    /// Renegotiation info extension containing a `PayloadU8`.
    RenegotiationInfo(PayloadU8),
    /// Extended master secret acknowledgment extension.
    ExtendedMasterSecretAck,
    /// Server name acknowledgment extension.
    ServerNameAck,
    /// Unknown extension.
    Unknown(UnknownExtension),
}

impl ServerExtension {
    /// Returns the `ExtensionType` corresponding to the `ServerExtension`.
    ///
    /// # Returns
    /// * `ExtensionType` - The type of the extension.
    fn ext_typ(&self) -> ExtensionType {
        match self {
            ServerExtension::RenegotiationInfo(_) => ExtensionType::RenegotationInfo,
            ServerExtension::ExtendedMasterSecretAck => ExtensionType::ExtendedMasterSecret,
            ServerExtension::ServerNameAck => ExtensionType::ServerName,
            ServerExtension::Unknown(ext) => ext.typ,
        }
    }

    /// Creates an empty renegotiation info extension.
    ///
    /// # Returns
    /// * `Self` - The new empty `ServerExtension` instance.
    pub(crate) fn make_empty_reneg_info() -> Self {
        Self::RenegotiationInfo(PayloadU8::new_empty())
    }
}

impl Codec<'_> for ServerExtension {
    /// Encodes the `ServerExtension` into a byte vector.
    ///
    /// # Arguments
    /// * `bytes` - A mutable reference to a vector of bytes where the encoded data will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.ext_typ().encode(bytes);

        let mut nested = LengthPrefixedBuffer::new(ListLength::u16, bytes);

        match self {
            ServerExtension::ExtendedMasterSecretAck | ServerExtension::ServerNameAck => {}
            ServerExtension::RenegotiationInfo(r) => r.encode(nested.buf),
            ServerExtension::Unknown(unknown_extension) => unknown_extension.encode(nested.buf),
        }
    }

    /// Reads and decodes a `ServerExtension` from a byte slice.
    ///
    /// # Arguments
    /// * `r` - A mutable reference to a `Reader` that provides the byte slice to read from.
    ///
    /// # Returns
    /// * `Result<Self, InvalidMessage>` - The decoded `ServerExtension` or an error if decoding fails.
    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        unreachable!() // shouldn't read sever ext
    }
}
/// Implements the `TLSListElement` trait for `CipherSuite`.
impl TLSListElement for CipherSuite {
    /// The length size of the `CipherSuite` list element.
    const LENGHT_SIZE: ListLength = ListLength::u16;
}

/// Implements the `TLSListElement` trait for `CompressionMethod`.
impl TLSListElement for CompressionMethod {
    /// The length size of the `CompressionMethod` list element.
    const LENGHT_SIZE: ListLength = ListLength::u8;
}

/// Implements the `TLSListElement` trait for `ClientExtension`.
impl TLSListElement for ClientExtension {
    /// The length size of the `ClientExtension` list element.
    const LENGHT_SIZE: ListLength = ListLength::u16;
}

/// Implements the `TLSListElement` trait for `ServerExtension`.
impl TLSListElement for ServerExtension {
    /// The length size of the `ServerExtension` list element.
    const LENGHT_SIZE: ListLength = ListLength::u16;
}

/// Represents the payload of a ClientHello message in the TLS protocol.
#[derive(Debug)]
pub struct ClientHelloPayload {
    /// The protocol version used by the client.
    pub client_version: ProtocolVersion,
    /// The random value generated by the client.
    pub random: Random,
    /// The session ID provided by the client.
    pub session: SessionID,
    /// The list of cipher suites supported by the client.
    pub cipher_suites: Vec<CipherSuite>,
    /// The list of compression methods supported by the client.
    pub compression_methods: Vec<CompressionMethod>,
    /// The list of extensions provided by the client.
    pub extensions: Vec<ClientExtension>,
}

impl ClientHelloPayload {
    /// Finds a specific extension in the list of client extensions.
    ///
    /// # Arguments
    /// * `typ` - The type of the extension to find.
    ///
    /// # Returns
    /// * `Option<&ClientExtension>` - A reference to the found extension or `None` if not found.
    pub(crate) fn find_extension(&self, typ: ExtensionType) -> Option<&ClientExtension> {
        self.extensions.iter().find(|ext| ext.ext_typ() == typ)
    }

    /// Returns the list of signature algorithms supported by the client.
    ///
    /// # Returns
    /// * `Option<&[SignatureScheme]>` - A reference to the list of signature schemes or `None` if not found.
    pub(crate) fn signature_algorithm(&self) -> Option<&[SignatureScheme]> {
        match self.find_extension(ExtensionType::SignatureAlgorithm) {
            Some(ClientExtension::Signature(s)) => Some(s),
            _ => None,
        }
    }

    /// Returns the list of named groups supported by the client.
    ///
    /// # Returns
    /// * `Option<&[NamedCurve]>` - A reference to the list of named curves or `None` if not found.
    pub(crate) fn named_groups(&self) -> Option<&[NamedCurve]> {
        match self.find_extension(ExtensionType::EllipticCurves) {
            Some(ClientExtension::NamedGroups(s)) => Some(s),
            _ => None,
        }
    }

    /// Returns the list of EC point formats supported by the client.
    ///
    /// # Returns
    /// * `Option<&[ECPointFormat]>` - A reference to the list of EC point formats or `None` if not found.
    pub(crate) fn ecpoints(&self) -> Option<&[ECPointFormat]> {
        match self.find_extension(ExtensionType::ECPointFormats)? {
            ClientExtension::ECPointFormats(s) => Some(s),
            _ => None,
        }
    }

    /// Checks if the client supports the Extended Master Secret extension.
    ///
    /// # Returns
    /// * `bool` - `true` if the client supports the Extended Master Secret extension, `false` otherwise.
    pub(crate) fn supports_ems(&self) -> bool {
        self.find_extension(ExtensionType::ExtendedMasterSecret)
            .is_some()
    }

    /// Returns the Server Name Indication (SNI) extension provided by the client.
    ///
    /// # Returns
    /// * `Option<&[ServerName]>` - A reference to the list of server names or `None` if not found.
    pub(crate) fn sni_extension(&self) -> Option<&[ServerName]> {
        let ext = self.find_extension(ExtensionType::ServerName)?;

        match *ext {
            ClientExtension::ServerName(ref req)
                if !req
                    .iter()
                    .any(|name| matches!(name.payload, ServerNamePayload::IpAddress(_))) =>
            {
                Some(req)
            }
            _ => None,
        }
    }
}

impl Codec<'_> for ClientHelloPayload {
    /// Encodes the `ClientHelloPayload` into a byte vector.
    ///
    /// # Arguments
    /// * `bytes` - A mutable reference to a vector of bytes where the encoded data will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.client_version.encode(bytes);
        self.random.encode(bytes);
        self.session.encode(bytes);
        self.cipher_suites.encode(bytes);
        self.compression_methods.encode(bytes);
        self.extensions.encode(bytes);
    }

    /// Reads and decodes a `ClientHelloPayload` from a byte slice.
    ///
    /// # Arguments
    /// * `r` - A mutable reference to a `Reader` that provides the byte slice to read from.
    ///
    /// # Returns
    /// * `Result<Self, InvalidMessage>` - The decoded `ClientHelloPayload` or an error if decoding fails.
    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let client_version = ProtocolVersion::read(r)?;
        let random = Random::read(r)?;
        let session = SessionID::read(r)?;
        let cipher_suites = Vec::read(r)?;
        let compression_methods = Vec::read(r)?;
        let extensions = Vec::read(r)?;
        Ok(Self {
            client_version,
            random,
            session,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }
}

/// Represents the payload of a ServerHello message in the TLS protocol.
#[derive(Debug)]
pub struct ServerHelloPayload {
    /// The protocol version used by the server.
    pub(crate) server_version: ProtocolVersion,
    /// The random value generated by the server.
    pub(crate) random: Random,
    /// The session ID provided by the server.
    pub(crate) session: SessionID,
    /// The cipher suite selected by the server.
    pub(crate) cipher_suite: CipherSuite,
    /// The compression method selected by the server.
    pub(crate) compression_method: CompressionMethod,
    /// The list of extensions provided by the server.
    pub extensions: Vec<ServerExtension>,
}

impl Codec<'_> for ServerHelloPayload {
    /// Encodes the `ServerHelloPayload` into a byte vector.
    ///
    /// # Arguments
    /// * `bytes` - A mutable reference to a vector of bytes where the encoded data will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.server_version.encode(bytes);
        self.random.encode(bytes);
        self.session.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.compression_method.encode(bytes);
        self.extensions.encode(bytes);
    }

    /// Reads and decodes a `ServerHelloPayload` from a byte slice.
    ///
    /// # Arguments
    /// * `r` - A mutable reference to a `Reader` that provides the byte slice to read from.
    ///
    /// # Returns
    /// * `Result<Self, InvalidMessage>` - The decoded `ServerHelloPayload` or an error if decoding fails.
    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        todo!()
    }
}

/// Represents a chain of certificates in the TLS protocol.
#[derive(Debug)]
pub struct CertificateChain<'a>(pub Vec<CertificateDer<'a>>);

impl CertificateChain<'_> {
    /// Converts the `CertificateChain` into an owned version with a `'static` lifetime.
    ///
    /// # Returns
    /// * `CertificateChain<'static>` - The owned version of the `CertificateChain`.
    pub(crate) fn into_owned(self) -> CertificateChain<'static> {
        CertificateChain(self.0.into_iter().map(|c| c.into_owned()).collect())
    }
}

impl TLSListElement for CertificateDer<'_> {
    /// The length size of the `CertificateDer` list element.
    const LENGHT_SIZE: ListLength = ListLength::u24 {
        max: MAX_CERTIFICATE_SIZE_LIMIT,
        error: InvalidMessage::CertificatePayloadTooLarge,
    };
}

impl<'a> Codec<'a> for CertificateDer<'a> {
    /// Encodes the `CertificateDer` into a byte vector.
    ///
    /// # Arguments
    /// * `bytes` - A mutable reference to a vector of bytes where the encoded data will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        u24(self.as_ref().len() as u32).encode(bytes);
        bytes.extend(self.as_ref());
    }

    /// Reads and decodes a `CertificateDer` from a byte slice.
    ///
    /// # Arguments
    /// * `r` - A mutable reference to a `Reader` that provides the byte slice to read from.
    ///
    /// # Returns
    /// * `Result<Self, InvalidMessage>` - The decoded `CertificateDer` or an error if decoding fails.
    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let len = u24::read(r)?.0 as usize;
        let mut sub = r.slice(len)?;
        let body = sub.rest();
        Ok(Self::from(body))
    }
}

impl<'a> Codec<'a> for CertificateChain<'a> {
    /// Encodes the `CertificateChain` into a byte vector.
    ///
    /// # Arguments
    /// * `bytes` - A mutable reference to a vector of bytes where the encoded data will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        Vec::encode(&self.0, bytes);
    }

    /// Reads and decodes a `CertificateChain` from a byte slice.
    ///
    /// # Arguments
    /// * `r` - A mutable reference to a `Reader` that provides the byte slice to read from.
    ///
    /// # Returns
    /// * `Result<Self, InvalidMessage>` - The decoded `CertificateChain` or an error if decoding fails.
    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        Vec::read(r).map(Self)
    }
}

/// The maximum size limit for a certificate.
pub const MAX_CERTIFICATE_SIZE_LIMIT: usize = 65536;

/// Represents the parameters for ECDH key exchange in the TLS protocol.
#[derive(Debug)]
pub struct ServerECDHParams {
    /// The type of the curve.
    curve_type: ECCurveType,
    /// The named group used for the key exchange.
    named_group: NamedCurve,
    /// The public key of the server.
    public: PayloadU8,
}

impl ServerECDHParams {
    /// Creates a new `ServerECDHParams` instance.
    ///
    /// # Arguments
    /// * `kx` - A reference to an `ActiveKx` trait object used to generate the key exchange parameters.
    ///
    /// # Returns
    /// * `Self` - The new `ServerECDHParams` instance.
    pub(crate) fn new(kx: &dyn ActiveKx) -> Self {
        Self {
            curve_type: ECCurveType::NamedCurve,
            named_group: kx.group(),
            public: PayloadU8::new(kx.pub_key().to_vec()),
        }
    }
}

impl Codec<'_> for ServerECDHParams {
    /// Encodes the `ServerECDHParams` into a byte vector.
    ///
    /// # Arguments
    /// * `bytes` - A mutable reference to a vector of bytes where the encoded data will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.curve_type.encode(bytes);
        self.named_group.encode(bytes);
        self.public.encode(bytes);
    }

    /// Reads and decodes a `ServerECDHParams` from a byte slice.
    ///
    /// # Arguments
    /// * `r` - A mutable reference to a `Reader` that provides the byte slice to read from.
    ///
    /// # Returns
    /// * `Result<Self, InvalidMessage>` - The decoded `ServerECDHParams` or an error if decoding fails.
    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let ct = ECCurveType::read(r)?;
        if ct != ECCurveType::NamedCurve {
            return Err(InvalidMessage::UnsupportedCurve);
        }
        let grp = NamedCurve::read(r)?;

        Ok(Self {
            curve_type: ct,
            named_group: grp,
            public: PayloadU8::read(r)?,
        })
    }
}

/// Represents the ServerKeyExchange message in the TLS protocol.
#[derive(Debug)]
pub struct ServerKeyExchange {
    /// The ECDH parameters used for the key exchange.
    pub(crate) params: ServerECDHParams,
    /// The digitally signed structure.
    pub(crate) dss: DigitallySinged,
}

impl ServerKeyExchange {
    /// Encodes the `ServerKeyExchange` into a byte vector.
    ///
    /// # Arguments
    /// * `bytes` - A mutable reference to a vector of bytes where the encoded data will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.params.encode(bytes);
        self.dss.encode(bytes);
    }
}

/// Represents the payload of a ServerKeyExchange message in the TLS protocol.
#[derive(Debug)]
pub enum ServerKeyExchangePayload {
    /// Known ServerKeyExchange payload.
    Known(ServerKeyExchange),
    /// Unknown ServerKeyExchange payload.
    Unknown(Payload<'static>),
}

impl From<ServerKeyExchange> for ServerKeyExchangePayload {
    /// Converts a `ServerKeyExchange` into a `ServerKeyExchangePayload`.
    ///
    /// # Arguments
    /// * `value` - The `ServerKeyExchange` instance to convert.
    ///
    /// # Returns
    /// * `Self` - The converted `ServerKeyExchangePayload`.
    fn from(value: ServerKeyExchange) -> Self {
        Self::Known(value)
    }
}

impl Codec<'_> for ServerKeyExchangePayload {
    /// Encodes the `ServerKeyExchangePayload` into a byte vector.
    ///
    /// # Arguments
    /// * `bytes` - A mutable reference to a vector of bytes where the encoded data will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            ServerKeyExchangePayload::Known(server_key_exchange) => {
                server_key_exchange.encode(bytes)
            }
            ServerKeyExchangePayload::Unknown(payload) => payload.encode(bytes),
        }
    }

    /// Reads and decodes a `ServerKeyExchangePayload` from a byte slice.
    ///
    /// # Arguments
    /// * `r` - A mutable reference to a `Reader` that provides the byte slice to read from.
    ///
    /// # Returns
    /// * `Result<Self, InvalidMessage>` - The decoded `ServerKeyExchangePayload` or an error if decoding fails.
    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self::Unknown(Payload::read(r).into_owned()))
    }
}

/// Represents the parameters for ECDH key exchange in the ClientHello message.
pub(crate) struct ClientECDHParams {
    /// The payload containing the public key of the client.
    pub payload: PayloadU8,
}

impl Codec<'_> for ClientECDHParams {
    /// Encodes the `ClientECDHParams` into a byte vector.
    ///
    /// # Arguments
    /// * `bytes` - A mutable reference to a vector of bytes where the encoded data will be stored.
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.payload.encode(bytes)
    }

    /// Reads and decodes a `ClientECDHParams` from a byte slice.
    ///
    /// # Arguments
    /// * `r` - A mutable reference to a `Reader` that provides the byte slice to read from.
    ///
    /// # Returns
    /// * `Result<Self, InvalidMessage>` - The decoded `ClientECDHParams` or an error if decoding fails.
    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            payload: PayloadU8::read(r)?,
        })
    }
}
