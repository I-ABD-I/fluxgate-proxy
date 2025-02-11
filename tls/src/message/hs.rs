use rustls_pki_types::CertificateDer;

use crate::codec::u24;
use crate::codec::Codec;
use crate::codec::LengthPrefixedBuffer;
use crate::codec::ListLength;
use crate::codec::Reader;
use crate::codec::TLSListElement;
use crate::crypto::SecureRandom;
use crate::error::{GetRandomFailed, InvalidMessage};
use crate::verify::DigitalySinged;

use super::base::Payload;
use super::base::PayloadU16;
use super::enums::ExtensionType;
use super::enums::HashAlgorithm;
use super::enums::ProtocolVersion;
use super::enums::SignatureAlgorithm;
use super::enums::{CipherSuite, NamedCurve};
use super::enums::{CompressionMethod, ECPointFormat};

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
        match self {
            HandshakePayload::HelloRequest => {}
            HandshakePayload::ClientHello(client_hello) => client_hello.encode(bytes),
            HandshakePayload::ServerHello(server_hello) => server_hello.encode(bytes),
            HandshakePayload::Certificate(certificate_chain) => certificate_chain.encode(bytes),
            HandshakePayload::ServerKeyExchange(kx) => kx.encode(bytes),
            HandshakePayload::ServerHelloDone => {}
            HandshakePayload::ClientKeyExchange(payload) => payload.encode(bytes),
            HandshakePayload::CertificateVerify(digitaly_singed) => digitaly_singed.encode(bytes),
            HandshakePayload::Finished(payload) => payload.encode(bytes),
            HandshakePayload::Unknown(payload) => payload.encode(bytes),
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

#[derive(Clone, Copy)]
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

#[derive(Copy, Clone)]
pub struct SessionID {
    length: usize,
    data: [u8; 32],
}

impl Codec<'_> for SessionID {
    fn encode(&self, bytes: &mut Vec<u8>) {
        debug_assert!(self.length <= 32);
        bytes.push(self.length as u8);
        bytes.extend_from_slice(&self.data);
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

impl TLSListElement for SignatureAndHashAlgorithm {
    const LENGHT_SIZE: ListLength = ListLength::u16;
}

impl TLSListElement for NamedCurve {
    const LENGHT_SIZE: ListLength = ListLength::u16;
}

impl TLSListElement for ECPointFormat {
    const LENGHT_SIZE: ListLength = ListLength::u8;
}

#[derive(Debug)]
pub enum ClientExtension {
    Signature(Vec<SignatureAndHashAlgorithm>),
    NamedGroups(Vec<NamedCurve>),
    ECPointFormats(Vec<ECPointFormat>),
    Unknown(UnknownExtension),
} // TODO: support extension

impl ClientExtension {
    pub fn ext_typ(&self) -> ExtensionType {
        match self {
            ClientExtension::ECPointFormats(_) => ExtensionType::ECPointFormats,
            ClientExtension::Signature(_) => ExtensionType::SignatureAlgorithm,
            ClientExtension::NamedGroups(_) => ExtensionType::EllipticCurves,
            ClientExtension::Unknown(ref r) => r.typ,
        }
    }
}

impl Codec<'_> for ClientExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.ext_typ().encode(bytes);
        let nest = LengthPrefixedBuffer::new(ListLength::u16, bytes);
        match self {
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
            _ => Self::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        sub.expect_empty("ClientExtension").map(|_| ext)
    }
}
#[derive(Debug)]

pub enum ServerExtension {
    Unknown(UnknownExtension),
}

impl Codec<'_> for ServerExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            ServerExtension::Unknown(unknown_extension) => unknown_extension.encode(bytes),
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
    pub(crate) fn signature_algorithm(&self) -> Option<&[SignatureAndHashAlgorithm]> {
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
pub struct ServerDHParams {
    dh_p: PayloadU16,
    dh_g: PayloadU16,
    dh_ys: PayloadU16,
}

impl Codec<'_> for ServerDHParams {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.dh_g.encode(bytes);
        self.dh_g.encode(bytes);
        self.dh_ys.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let dh_p = PayloadU16::read(r)?;
        let dh_g = PayloadU16::read(r)?;
        let dh_ys = PayloadU16::read(r)?;
        Ok(Self { dh_p, dh_g, dh_ys })
    }
}

pub struct ServerKeyExchange {
    params: ServerDHParams,
    dss: DigitalySinged,
}

impl ServerKeyExchange {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.params.encode(bytes);
        self.dss.encode(bytes);
    }
}

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
