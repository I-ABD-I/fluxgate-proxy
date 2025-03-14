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
use crate::verify::DigitalySinged;

use super::base::PayloadU16;
use super::base::{Payload, PayloadU8};
use super::enums::ProtocolVersion;
use super::enums::SignatureAlgorithm;
use super::enums::{CipherSuite, NamedCurve};
use super::enums::{CompressionMethod, ECPointFormat};
use super::enums::{ECCurveType, ExtensionType, ServerNameType};
use super::enums::{HashAlgorithm, SignatureScheme};

enum_builder! {
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

#[derive(Debug)]
pub enum HandshakePayload<'a> {
    HelloRequest,
    ClientHello(ClientHelloPayload),
    ServerHello(ServerHelloPayload),
    Certificate(CertificateChain<'a>),
    ServerKeyExchange(ServerKeyExchangePayload),
    ServerHelloDone,
    CertificateVerify(DigitalySinged),
    ClientKeyExchange(Payload<'a>),
    Finished(Payload<'a>),
    Unknown(Payload<'a>),
}
impl HandshakePayload<'_> {
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
}
impl<'a> Codec<'a> for HandshakePayload<'a> {
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
                HandshakePayload::CertificateVerify(DigitalySinged::read(&mut sub)?)
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
    pub fn new(sr: &dyn SecureRandom) -> Result<Self, GetRandomFailed> {
        let mut bytes = [0u8; 32];
        sr.fill(&mut bytes)?;
        Ok(Self(bytes))
    }
}

impl Codec<'_> for Random {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0);
    }

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
    pub fn empty() -> Self {
        Self {
            data: [0u8; 32], 
            length: 0,
        }
    }
}
impl Codec<'_> for SessionID {
    fn encode(&self, bytes: &mut Vec<u8>) {
        debug_assert!(self.length <= 32);
        bytes.push(self.length as u8);
        bytes.extend_from_slice(&self.data[..self.length]);
    }

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
#[derive(Debug)]
pub struct UnknownExtension {
    pub(crate) typ: ExtensionType,
    pub(crate) payload: Payload<'static>,
}

impl UnknownExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.payload.encode(bytes);
    }

    fn read(typ: ExtensionType, r: &mut Reader<'_>) -> Self {
        let payload = Payload::read(r).into_owned();
        Self { typ, payload }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SignatureAndHashAlgorithm {
    pub(crate) hash: HashAlgorithm,
    pub(crate) signature: SignatureAlgorithm,
}

impl Codec<'_> for SignatureAndHashAlgorithm {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.hash.encode(bytes);
        self.signature.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let hash = HashAlgorithm::read(r)?;
        let signature = SignatureAlgorithm::read(r)?;
        Ok(Self { hash, signature })
    }
}

#[derive(Debug)]
pub enum ServerNamePayload {
    HostName(DnsName<'static>),
    IpAddress(PayloadU16),
    Unknown(Payload<'static>),
}

impl ServerNamePayload {
    fn read_hostname(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let raw = PayloadU16::read(r)?;

        use rustls_pki_types::ServerName;
        match ServerName::try_from(raw.0.as_slice()) {
            Ok(ServerName::DnsName(d)) => Ok(Self::HostName(d.to_owned())),
            Ok(ServerName::IpAddress(_)) => Ok(Self::IpAddress(raw)),
            Ok(_) | Err(_) => Err(InvalidMessage::MissingData("ServerName")),
        }
    }

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

#[derive(Debug)]
pub struct ServerName {
    pub(crate) typ: ServerNameType,
    pub(crate) payload: ServerNamePayload,
}

impl Codec<'_> for ServerName {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.typ.encode(bytes);
        self.payload.encode(bytes)
    }

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

#[derive(Debug)]
pub enum ClientExtension {
    Signature(Vec<SignatureScheme>),
    NamedGroups(Vec<NamedCurve>),
    ECPointFormats(Vec<ECPointFormat>),
    ServerName(Vec<ServerName>),
    Unknown(UnknownExtension),
} // TODO: support extension

impl ClientExtension {
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
#[derive(Debug)]

pub enum ServerExtension {
    RenegotiationInfo(PayloadU8),
    ExtendedMasterSecretAck,
    ServerNameAck,
    Unknown(UnknownExtension),
}

impl ServerExtension {
    fn ext_typ(&self) -> ExtensionType {
        match self {
            ServerExtension::RenegotiationInfo(_) => ExtensionType::RenegotationInfo,
            ServerExtension::ExtendedMasterSecretAck => ExtensionType::ExtendedMasterSecret,
            ServerExtension::ServerNameAck => ExtensionType::ServerName,
            ServerExtension::Unknown(ext) => ext.typ,
        }
    }

    pub(crate) fn make_empty_reneg_info() -> Self {
        Self::RenegotiationInfo(PayloadU8::new_empty())
    }
}

impl Codec<'_> for ServerExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.ext_typ().encode(bytes);

        let mut nested = LengthPrefixedBuffer::new(ListLength::u16, bytes);

        match self {
            ServerExtension::ExtendedMasterSecretAck | ServerExtension::ServerNameAck => {}
            ServerExtension::RenegotiationInfo(r) => r.encode(nested.buf),
            ServerExtension::Unknown(unknown_extension) => unknown_extension.encode(nested.buf),
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        unreachable!() // shouldn't read sever ext
    }
}

impl TLSListElement for CipherSuite {
    const LENGHT_SIZE: ListLength = ListLength::u16;
}

impl TLSListElement for CompressionMethod {
    const LENGHT_SIZE: ListLength = ListLength::u8;
}

impl TLSListElement for ClientExtension {
    const LENGHT_SIZE: ListLength = ListLength::u16;
}

impl TLSListElement for ServerExtension {
    const LENGHT_SIZE: ListLength = ListLength::u16;
}

#[derive(Debug)]
pub struct ClientHelloPayload {
    pub client_version: ProtocolVersion,
    pub random: Random,
    pub session: SessionID,
    pub cipher_suites: Vec<CipherSuite>,
    pub compression_methods: Vec<CompressionMethod>,
    pub extensions: Vec<ClientExtension>,
}

impl ClientHelloPayload {
    pub(crate) fn find_extension(&self, typ: ExtensionType) -> Option<&ClientExtension> {
        self.extensions.iter().find(|ext| ext.ext_typ() == typ)
    }
    pub(crate) fn signature_algorithm(&self) -> Option<&[SignatureScheme]> {
        match self.find_extension(ExtensionType::SignatureAlgorithm) {
            Some(ClientExtension::Signature(s)) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn named_groups(&self) -> Option<&[NamedCurve]> {
        match self.find_extension(ExtensionType::EllipticCurves) {
            Some(ClientExtension::NamedGroups(s)) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn ecpoints(&self) -> Option<&[ECPointFormat]> {
        match self.find_extension(ExtensionType::ECPointFormats)? {
            ClientExtension::ECPointFormats(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn supports_ems(&self) -> bool {
        self.find_extension(ExtensionType::ExtendedMasterSecret)
            .is_some()
    }

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
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.client_version.encode(bytes);
        self.random.encode(bytes);
        self.session.encode(bytes);
        self.cipher_suites.encode(bytes);
        self.compression_methods.encode(bytes);
        self.extensions.encode(bytes);
    }

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

#[derive(Debug)]
pub struct ServerHelloPayload {
    pub(crate) server_version: ProtocolVersion,
    pub(crate) random: Random,
    pub(crate) session: SessionID,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) compression_method: CompressionMethod,
    pub extensions: Vec<ServerExtension>,
}

impl Codec<'_> for ServerHelloPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.server_version.encode(bytes);
        self.random.encode(bytes);
        self.session.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.compression_method.encode(bytes);
        self.extensions.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        todo!()
    }
}

#[derive(Debug)]
pub struct CertificateChain<'a>(pub Vec<CertificateDer<'a>>);

impl TLSListElement for CertificateDer<'_> {
    const LENGHT_SIZE: ListLength = ListLength::u24 {
        max: MAX_CERTIFICATE_SIZE_LIMIT,
        error: InvalidMessage::CertificatePayloadTooLarge,
    };
}

impl<'a> Codec<'a> for CertificateDer<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        u24(self.as_ref().len() as u32).encode(bytes);
        bytes.extend(self.as_ref());
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let len = u24::read(r)?.0 as usize;
        let mut sub = r.slice(len)?;
        let body = sub.rest();
        Ok(Self::from(body))
    }
}

impl<'a> Codec<'a> for CertificateChain<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        Vec::encode(&self.0, bytes);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        Vec::read(r).map(Self)
    }
}

pub const MAX_CERTIFICATE_SIZE_LIMIT: usize = 65536;
#[derive(Debug)]
pub struct ServerECDHParams {
    curve_type: ECCurveType,
    named_group: NamedCurve,
    public: PayloadU8,
}

impl ServerECDHParams {
    pub(crate) fn new(kx: &dyn ActiveKx) -> Self {
        Self {
            curve_type: ECCurveType::NamedCurve,
            named_group: kx.group(),
            public: PayloadU8::new(kx.pub_key().to_vec()),
        }
    }
}

impl Codec<'_> for ServerECDHParams {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.curve_type.encode(bytes);
        self.named_group.encode(bytes);
        self.public.encode(bytes);
    }

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

#[derive(Debug)]
pub struct ServerKeyExchange {
    pub(crate) params: ServerECDHParams,
    pub(crate) dss: DigitalySinged,
}

impl ServerKeyExchange {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.params.encode(bytes);
        self.dss.encode(bytes);
    }
}

#[derive(Debug)]
pub enum ServerKeyExchangePayload {
    Known(ServerKeyExchange),
    Unknown(Payload<'static>),
}

impl From<ServerKeyExchange> for ServerKeyExchangePayload {
    fn from(value: ServerKeyExchange) -> Self {
        Self::Known(value)
    }
}

impl Codec<'_> for ServerKeyExchangePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            ServerKeyExchangePayload::Known(server_key_exchange) => {
                server_key_exchange.encode(bytes)
            }
            ServerKeyExchangePayload::Unknown(payload) => payload.encode(bytes),
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self::Unknown(Payload::read(r).into_owned()))
    }
}

// fn decode_kx_params(kx_algo: KeyExchangeAlgorithm, state: &mut TlsState, kx_params: &[u8]) ->
pub(crate) struct ClientECDHParams {
    pub payload: PayloadU8,
}

impl Codec<'_> for ClientECDHParams {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.payload.encode(bytes)
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            payload: PayloadU8::read(r)?,
        })
    }
}
