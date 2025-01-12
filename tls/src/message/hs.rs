use rustls_pki_types::CertificateDer;

use crate::codec::u24;
use crate::codec::Codec;
use crate::codec::ListLength;
use crate::codec::Reader;
use crate::codec::TLSListElement;
use crate::error::InvalidMessage;
use crate::verify::DigitalySinged;

use super::base::Payload;
use super::base::PayloadU16;
use super::enums::CipherSuite;
use super::enums::CompressionMethod;
use super::enums::HashAlgorithm;
use super::enums::ProtocolVersion;
use super::enums::SignatureAlgorithm;

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

enum HandshakePayload<'a> {
    HelloRequest,
    ClientHello(ClientHelloPayload),
    Certificate(CertificateChain<'a>),
    ServerKeyExchange(ServerKeyExchangePayload),
    ServerHelloDone,
    ClientKeyExchange(Payload<'a>),
}

pub struct Random([u8; 32]);

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

pub struct UnknownExtension {}

pub struct SignatureAndHashAlgorithm {
    hash: HashAlgorithm,
    signature: SignatureAlgorithm,
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

enum ClientExtension {
    Signature(Vec<SignatureAndHashAlgorithm>),
    Unknown(UnknownExtension),
} // TODO: support extension

pub enum ServerExtension {
    Unknown(UnknownExtension),
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

pub struct ClientHelloPayload {
    client_version: ProtocolVersion,
    random: Random,
    session: SessionID,
    cipher_suites: Vec<CipherSuite>,
    compression_methods: Vec<CompressionMethod>,
    extensions: Vec<ClientExtension>,
}

pub struct ServerHelloPayload {
    server_version: ProtocolVersion,
    random: Random,
    session: SessionID,
    cipher_suite: CipherSuite,
    compression_method: CompressionMethod,
    extensions: Vec<ServerExtension>,
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
        Ok(Self::Unknown(Payload::read(r)?.into_owned()))
    }
}
