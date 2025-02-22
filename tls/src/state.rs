use crate::codec::{Codec, Reader};
use crate::config::CertifiedKey;
use crate::crypto::kx::{ActiveKx, SupportedKxGroup};
use crate::crypto::provider::SupportedCipherSuite;
use crate::hs_hash::HandshakeHash;
use crate::message::enums::{
    CompressionMethod, ECPointFormat, NamedCurve, ProtocolVersion, SignatureAlgorithm,
};
use crate::message::hs::{CertificateChain, ClientECDHParams, ClientHelloPayload, Random, ServerECDHParams, ServerHelloPayload, ServerKeyExchange, ServerKeyExchangePayload, SessionID, SignatureAndHashAlgorithm};
use crate::{
    config::ServerConfig,
    connection::TlsState,
    crypto,
    crypto::compatible_sigscheme_for_suites,
    error::Error,
    hs_hash, message,
    message::{hs::HandshakePayload, Message, MessagePayload},
};
use log::debug;
use rustls_pki_types::{CertificateDer, DnsName};
use std::sync::Arc;
use crate::crypto::sign::SigningKey;
use crate::verify::DigitalySinged;

pub struct Context<'a> {
    pub(crate) state: &'a mut TlsState,
}
pub trait State {
    fn handle<'m>(&self, cx: &mut Context, message: Message<'m>) -> Result<Box<dyn State>, Error>;
}

pub struct ExpectClientHello {
    config: Arc<ServerConfig>,
}

impl ExpectClientHello {
    pub fn new() -> Self {
        Self {
            config: Arc::new(ServerConfig::new()),
        }
    }

    fn choose_suite_and_kx_group(
        &self,
        key: SignatureAlgorithm,
        client_groups: &[NamedCurve],
        client_suites: &[message::enums::CipherSuite],
    ) -> Result<(SupportedCipherSuite, &'static dyn SupportedKxGroup), Error> {
        let mut supported_groups = Vec::with_capacity(client_groups.len());

        for group in client_groups {
            let supported = self
                .config
                .provider
                .kx_groups
                .iter()
                .find(|x| x.group() == *group);
            supported_groups.push(supported);
        }

        let mut suitable_suites_iter = self
            .config
            .provider
            .cipher_suites
            .iter()
            .filter(|s| s.0.usable_for_signature_algorithm(key));

        debug!("suitable_suites_iter: {:?}", suitable_suites_iter);
        let suite = suitable_suites_iter
            .find(|suite| client_suites.contains(&suite.0.suite))
            .unwrap();

        let maybe_skxg = supported_groups
            .iter()
            .find_map(|maybe_skxg| match maybe_skxg {
                Some(skxg) => suite
                    .0
                    .usable_for_kx_algorithm(&skxg.group().key_exchange_algorithm())
                    .then_some(*skxg),
                None => None,
            });

        let skxg = maybe_skxg.unwrap();
        Ok((*suite, *skxg))
    }
}
//#region
pub struct ClientHello<'a> {
    server_name: &'a Option<DnsName<'a>>,
    sigschemes: &'a [SignatureAndHashAlgorithm],
    cipher_suites: &'a [SupportedCipherSuite],
}

impl State for ExpectClientHello {
    fn handle<'m>(&self, cx: &mut Context, message: Message<'m>) -> Result<Box<dyn State>, Error> {
        let MessagePayload::HandshakePayload(HandshakePayload::ClientHello(client_hello)) =
            &message.payload
        else {
            return Err(Error::InappropriateHandshakeMessage);
        };

        let mut sig = client_hello.signature_algorithm().unwrap().to_owned();
        debug!("{:?}", client_hello.cipher_suites);
        debug!("{:?}", self.config.provider.cipher_suites);
        let client_suites: Vec<_> = self
            .config
            .provider
            .cipher_suites
            .iter()
            .copied()
            .filter(|scs| client_hello.cipher_suites.contains(&scs.0.suite))
            .collect();

        sig.retain(|scheme| compatible_sigscheme_for_suites(*scheme, &client_suites));

        // only gonna send X.509 Certifiacte client may terminate
        let certkey = {
            let client_hello = ClientHello {
                server_name: &None, // TODO: CHANGE THIS
                sigschemes: &sig,
                cipher_suites: &client_suites,
            };

            self.config.cert_resolver.resolve(client_hello).unwrap()
        };

        debug!("{:?}", client_suites);
        let (suite, kxg) = self
            .choose_suite_and_kx_group(
                certkey.key.algorithm(),
                client_hello.named_groups().unwrap_or(&[]),
                &client_hello.cipher_suites,
            )
            .unwrap();

        let starting_hash = suite.0.hash_provider;
        let mut hshash = HandshakeHash::start_hash(starting_hash);
        hshash.add_message(&message);

        let client_random = client_hello.random;
        let server_random = Random::new(self.config.provider.random)?;

        FinishCHHandling {
            config: self.config.clone(),
            transcript: hshash,
            suite: &suite.0,
            randoms: ConnectionRandoms {
                client_random, server_random
            }
        }
        .handle(cx, &certkey, client_hello, kxg, sig)
    }
}

struct ConnectionRandoms {
    client_random: Random,
    server_random: Random,
}
struct FinishCHHandling {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static crypto::CipherSuite,
    randoms: ConnectionRandoms,
}

struct HandshakeFlight<'a> {
    buffer: Vec<u8>,
    hash: &'a mut HandshakeHash,
}
impl<'a> HandshakeFlight<'a> {
    fn add(&mut self, message: &HandshakePayload) {
        let start = self.buffer.len();
        message.encode(&mut self.buffer);
        self.hash.add(&self.buffer[start..]);
    }
}

fn emit_server_hello(
    flight: &mut HandshakeFlight,
    server_random: Random,
    suite: &'static crypto::CipherSuite,
    session_id: SessionID,
) {
    let sh = HandshakePayload::ServerHello(ServerHelloPayload {
        server_version: ProtocolVersion::TLSv1_2,
        random: server_random,
        cipher_suite: suite.suite,
        session: session_id,
        compression_method: CompressionMethod::Null,
        extensions: vec![],
    });

    flight.add(&sh);
}

fn emit_certificate(flight: &mut HandshakeFlight, cert: &[CertificateDer<'_>]) {
    flight.add(&HandshakePayload::Certificate(CertificateChain(
        cert.to_vec(),
    )));
}

fn emit_server_kx(
    flight: &mut HandshakeFlight,
    sigschemes: Vec<SignatureAndHashAlgorithm>,
    selected_kxg: &'static dyn SupportedKxGroup,
    signing_key: &dyn SigningKey,
    randoms: &ConnectionRandoms) -> Result<Box<dyn ActiveKx>, Error> {
    let kx = selected_kxg.start()?;
    let kx_params = ServerECDHParams::new(&*kx);

    let mut msg = Vec::new();
    msg.extend(randoms.client_random.as_ref());
    msg.extend(randoms.server_random.as_ref());
    kx_params.encode(&mut msg);

    let signer = signing_key.choose_scheme(&sigschemes).ok_or_else(|| {
        Error::General("incompatible signing key")
    })?;
    let sigscheme = signer.scheme();
    let sig = signer.sign(&msg)?;

    let skx = ServerKeyExchangePayload::from(ServerKeyExchange {
        params: kx_params,
        dss: DigitalySinged::new(sigscheme, sig),
    });

    flight.add(
        &HandshakePayload::ServerKeyExchange(skx),
    );
    Ok(kx)
}
fn emit_server_hello_done(flight: &mut HandshakeFlight) {
    flight.add(&HandshakePayload::ServerHelloDone);
}
impl FinishCHHandling {
    fn handle(
        mut self,
        cx: &mut Context<'_>,
        server_key: &CertifiedKey,
        client_hello: &ClientHelloPayload,
        selected_kxg: &'static dyn SupportedKxGroup,
        sigschemes_ext: Vec<SignatureAndHashAlgorithm>,
    ) -> Result<Box<dyn State>, Error> {
        let ecpoints_ext = client_hello
            .ecpoints()
            .unwrap_or(&[ECPointFormat::Uncompressed]);

        let sigschemes = self.suite.resolve_sig_schemes(&sigschemes_ext);
        let ecptfmt = ECPointFormat::SUPPORTED
            .iter()
            .find(|fmt| ecpoints_ext.contains(fmt))
            .cloned()
            .unwrap();

        let mut flight = HandshakeFlight {
            buffer: Vec::new(),
            hash: &mut self.transcript,
        };

        emit_server_hello(
            &mut flight,
            self.randoms.server_random,
            self.suite,
            client_hello.session,
        );
        emit_certificate(&mut flight, &server_key.cert);
        let kx= emit_server_kx(&mut flight,sigschemes, selected_kxg, &*server_key.key, &self.randoms)?;
        emit_server_hello_done(&mut flight);
        Ok(Box::new(ExpectClientKx {
            config: self.config,
            kx_group: selected_kxg,
            transcript: self.transcript,
            randoms: self.randoms,
            server_key: kx
        }))
    }
}
//#endregion
pub struct ExpectClientKx {
    config: Arc<ServerConfig>,
    kx_group: &'static dyn SupportedKxGroup,
    transcript: HandshakeHash,
    randoms: ConnectionRandoms,
    server_key: Box<dyn ActiveKx>,
}

struct ConnectionSecrets {
    randoms: ConnectionRandoms,
    suite: &'static crypto::CipherSuite,
    master_secret: [u8; 32],
}

impl ConnectionSecrets {
    fn from_key_exchange(
        kx: Box<dyn ActiveKx>,
        peer_pub: &[u8],
        randoms: ConnectionRandoms,
        suite: &'static crypto::CipherSuite,
    ) -> Result<Self, Error> {
        let mut ret = Self {
            randoms,
            suite,
            master_secret: [0; 32],
        };

        let seed = {
            let mut seed = [0u8; 64];
            seed[..32].copy_from_slice(ret.randoms.client_random.as_ref());
            seed[32..].copy_from_slice(ret.randoms.server_random.as_ref());
            seed
        };

        ret.suite.prf_provider.for_key_exchange(
            &mut ret.master_secret,
            kx,
            peer_pub,
            "master secret".as_bytes(),
            &seed,
        );

        Ok(ret)
    }
}

impl State for ExpectClientKx {
    fn handle<'m>(&self, cx: &mut Context, message: Message<'m>) -> Result<Box<dyn State>, Error> {
        let MessagePayload::HandshakePayload(HandshakePayload::ClientKeyExchange(client_kx)) =
            &message.payload
        else {
            return Err(Error::InappropriateHandshakeMessage);
        };

        let mut r = Reader::new(client_kx.bytes());
        let client_kx_params = ClientECDHParams::read(&mut r)?;

        let secrets = ConnectionSecrets::from_key_exchange(
            self.server_key,
            client_kx_params.payload.0,
            self.randoms,
            self.kx_group
        );

        todo!();
    }
}
