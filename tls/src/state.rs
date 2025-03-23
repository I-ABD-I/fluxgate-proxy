use crate::codec::{Codec, Reader};
use crate::config::CertifiedKey;
use crate::crypto::cipher::{AeadKey, MessageDecrypter, MessageEncrypter};
use crate::crypto::hash;
use crate::crypto::hash::Hash;
use crate::crypto::kx::{ActiveKx, SupportedKxGroup};
use crate::crypto::provider::SupportedCipherSuite;
use crate::crypto::sign::SigningKey;
use crate::error::inappropriate_message;
use crate::hs_hash::HandshakeHash;
use crate::message::base::Payload;
use crate::message::ccs::ChangeCipherSpecPayload;
use crate::message::enums::{
    CipherSuite, CompressionMethod, ContentType, ECPointFormat, ExtensionType, NamedCurve,
    ProtocolVersion, SignatureAlgorithm, SignatureScheme,
};
use crate::message::hs::{
    CertificateChain, ClientECDHParams, ClientHelloPayload, Random, ServerECDHParams,
    ServerExtension, ServerHelloPayload, ServerKeyExchange, ServerKeyExchangePayload, ServerName,
    ServerNamePayload, SessionID, SignatureAndHashAlgorithm,
};
use crate::verify::DigitalySinged;
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

pub struct Context<'a> {
    pub(crate) state: &'a mut TlsState,
}
pub trait State {
    fn handle(
        self: Box<Self>,
        cx: &mut Context,
        message: Message<'_>,
    ) -> Result<Box<dyn State>, Error>;
}

pub struct ExpectClientHello {
    config: Arc<ServerConfig>,
}

impl ExpectClientHello {
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self { config }
    }

    pub(crate) fn with_certified_key(
        self,
        mut sig: Vec<SignatureScheme>,
        client_hello: &ClientHelloPayload,
        message: &Message<'_>,
        cx: &mut Context,
    ) -> Result<Box<dyn State>, Error> {
        let client_suites: Vec<_> = self
            .config
            .provider
            .cipher_suites
            .iter()
            .copied()
            .filter(|scs| client_hello.cipher_suites.contains(&scs.0.suite))
            .collect();

        sig.retain(|scheme| compatible_sigscheme_for_suites(*scheme, &client_suites));

        // only gonna send X.509 Certificate client may terminate
        let certkey = {
            let client_hello = ClientHello {
                server_name: &None, // TODO: CHANGE THIS
                sigschemes: &sig,
                cipher_suites: &client_hello.cipher_suites,
            };

            self.config.cert_resolver.resolve(client_hello).unwrap()
        };

        #[allow(clippy::unnecessary_unwrap, clippy::unwrap_used)]
        let (suite, kxg) = self
            .choose_suite_and_kx_group(
                certkey.key.algorithm(),
                client_hello.named_groups().unwrap_or(&[]),
                &client_hello.cipher_suites,
            )
            .unwrap();

        let starting_hash = suite.0.hash_provider;
        let mut hshash = HandshakeHash::start_hash(starting_hash);
        hshash.add_message(message);

        let client_random = client_hello.random;
        let server_random = Random::new(self.config.provider.random)?;

        FinishCHHandling {
            config: self.config.clone(),
            transcript: hshash,
            suite: suite.0,
            randoms: ConnectionRandoms {
                client_random,
                server_random,
            },
        }
        .handle(cx, &certkey, client_hello, kxg, sig)
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
        debug!("Selected Cipher Suite {:?}", suite.0.suite);
        debug!("Selected Key Exchange Group {:?}", skxg.group());
        Ok((*suite, *skxg))
    }
}
//#region
pub struct ClientHello<'a> {
    pub(crate) server_name: &'a Option<DnsName<'a>>,
    pub(crate) sigschemes: &'a [SignatureScheme],
    pub(crate) cipher_suites: &'a [CipherSuite],
}

impl ClientHello<'_> {
    pub fn sni(&self) -> &Option<DnsName> {
        self.server_name
    }
}

fn process_sni(sni: &[ServerName]) -> Option<DnsName<'_>> {
    fn only_dns_hostnames(name: &ServerName) -> Option<DnsName<'_>> {
        if let ServerNamePayload::HostName(dns) = &name.payload {
            Some(dns.borrow())
        } else {
            None
        }
    }

    sni.iter().filter_map(only_dns_hostnames).next()
}

pub(crate) fn process_client_hello<'m>(
    message: &'m Message<'_>,
    cx: &mut Context,
) -> Result<(&'m ClientHelloPayload, Vec<SignatureScheme>), Error> {
    let MessagePayload::HandshakePayload(HandshakePayload::ClientHello(client_hello)) =
        &message.payload
    else {
        return Err(Error::InappropriateHandshakeMessage);
    };

    if let Some(sni) = client_hello.sni_extension() {
        cx.state.sni = process_sni(sni).map(|sni| sni.to_lowercase_owned());
    }

    let mut sig = client_hello.signature_algorithm().unwrap().to_owned();
    Ok((client_hello, sig))
}

impl State for ExpectClientHello {
    fn handle(
        self: Box<Self>,
        cx: &mut Context,
        message: Message<'_>,
    ) -> Result<Box<dyn State>, Error> {
        let (client_hello, mut sig) = process_client_hello(&message, cx)?;
        self.with_certified_key(sig, client_hello, &message, cx)
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
impl HandshakeFlight<'_> {
    fn add(&mut self, message: &HandshakePayload) {
        let start = self.buffer.len();
        message.encode(&mut self.buffer);
        self.hash.add(&self.buffer[start..]);
    }

    fn finish(self, tls_state: &mut TlsState) {
        tls_state.send_message(
            Message {
                version: ProtocolVersion::TLSv1_2,
                payload: MessagePayload::HandshakeFlight(Payload::new(self.buffer)),
            },
            false,
        );
    }
}

#[derive(Default)]

struct ExtensionProcessing {
    exts: Vec<ServerExtension>,
}

impl ExtensionProcessing {
    fn new() -> Self {
        Self::default()
    }

    fn process(&mut self, ch: &ClientHelloPayload, using_ems: bool) {
        if ch.sni_extension().is_some() {
            self.exts.push(ServerExtension::ServerNameAck);
        }

        // dont offer reneg, stops things from complaining abt insecure reneg
        let secure_reneg_offered = ch.find_extension(ExtensionType::RenegotationInfo).is_some()
            || ch
                .cipher_suites
                .contains(&CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

        if secure_reneg_offered {
            self.exts.push(ServerExtension::make_empty_reneg_info());
        }

        // if using_ems {
        //     self.exts.push(ServerExtension::ExtendedMasterSecretAck)
        // }
    }
}

fn emit_server_hello(
    flight: &mut HandshakeFlight,
    client_hello: &ClientHelloPayload,
    server_random: Random,
    suite: &'static crypto::CipherSuite,
    session_id: SessionID,
    using_ems: bool,
) {
    let mut ep = ExtensionProcessing::new();
    ep.process(client_hello, using_ems);

    let sh = HandshakePayload::ServerHello(ServerHelloPayload {
        server_version: ProtocolVersion::TLSv1_2,
        random: server_random,
        cipher_suite: suite.suite,
        session: session_id,
        compression_method: CompressionMethod::Null,
        extensions: ep.exts,
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
    sigschemes: Vec<SignatureScheme>,
    selected_kxg: &'static dyn SupportedKxGroup,
    signing_key: &dyn SigningKey,
    randoms: &ConnectionRandoms,
) -> Result<Box<dyn ActiveKx>, Error> {
    let kx = selected_kxg.start()?;
    let kx_params = ServerECDHParams::new(&*kx);

    let mut msg = Vec::new();
    msg.extend(randoms.client_random.as_ref());
    msg.extend(randoms.server_random.as_ref());
    kx_params.encode(&mut msg);

    let signer = signing_key
        .choose_scheme(&sigschemes)
        .ok_or(Error::General("incompatible signing key"))?;
    let sigscheme = signer.scheme();
    let sig = signer.sign(&msg)?;

    let skx = ServerKeyExchangePayload::from(ServerKeyExchange {
        params: kx_params,
        dss: DigitalySinged::new(sigscheme, sig),
    });

    flight.add(&HandshakePayload::ServerKeyExchange(skx));
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
        sigschemes_ext: Vec<SignatureScheme>,
    ) -> Result<Box<dyn State>, Error> {
        let using_ems = client_hello.supports_ems();

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
            client_hello,
            self.randoms.server_random,
            self.suite,
            SessionID::empty(), // not offering session resumption for now.
            using_ems,
        );
        emit_certificate(&mut flight, &server_key.cert);
        let kx = emit_server_kx(
            &mut flight,
            sigschemes,
            selected_kxg,
            &*server_key.key,
            &self.randoms,
        )?;
        emit_server_hello_done(&mut flight);

        flight.finish(cx.state);

        Ok(Box::new(ExpectClientKx {
            config: self.config,
            suite: self.suite,
            transcript: self.transcript,
            randoms: self.randoms,
            server_key: kx,
            using_ems,
        }))
    }
}
//#endregion
pub struct ExpectClientKx {
    config: Arc<ServerConfig>,
    suite: &'static crypto::CipherSuite,
    transcript: HandshakeHash,
    randoms: ConnectionRandoms,
    server_key: Box<dyn ActiveKx>,
    using_ems: bool,
}

pub(crate) struct ConnectionSecrets {
    randoms: ConnectionRandoms,
    suite: &'static crypto::CipherSuite,
    master_secret: [u8; 48],
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
            master_secret: [0; 48],
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

    pub(crate) fn make_cipher_pair(
        &self,
    ) -> (Box<dyn MessageDecrypter>, Box<dyn MessageEncrypter>) {
        let key_block = self.make_key_block();
        let shape = self.suite.aead_algo.key_shape();

        let (read_key, key_block) = key_block.split_at(shape.0);
        let (write_key, key_block) = key_block.split_at(shape.0);
        let (read_iv, key_block) = key_block.split_at(shape.1);
        let (write_iv, extra) = key_block.split_at(shape.1);

        (
            self.suite
                .aead_algo
                .decrypter(AeadKey::new(read_key), read_iv),
            self.suite
                .aead_algo
                .encrypter(AeadKey::new(write_key), write_iv, extra),
        )
    }

    fn make_key_block(&self) -> Vec<u8> {
        let shape = self.suite.aead_algo.key_shape();
        let len = (shape.0 + shape.1) * 2 + shape.2;

        let mut out = vec![0u8; len];
        let seed = {
            let mut seed = [0u8; 64];
            seed[..32].copy_from_slice(self.randoms.server_random.as_ref());
            seed[32..].copy_from_slice(self.randoms.client_random.as_ref());
            seed
        };

        self.suite
            .prf_provider
            .for_secret(&mut out, &self.master_secret, b"key expansion", &seed);

        out
    }

    fn make_verify_data(&self, hash: &hash::Output, label: &[u8]) -> [u8; 12] {
        let mut out = [0u8; 12];
        self.suite
            .prf_provider
            .for_secret(&mut out, &self.master_secret, label, hash.as_ref());
        out
    }
}

impl State for ExpectClientKx {
    fn handle(
        mut self: Box<Self>,
        cx: &mut Context,
        message: Message<'_>,
    ) -> Result<Box<dyn State>, Error> {
        let MessagePayload::HandshakePayload(HandshakePayload::ClientKeyExchange(client_kx)) =
            &message.payload
        else {
            return Err(Error::InappropriateHandshakeMessage);
        };
        self.transcript.add_message(&message);

        let mut r = Reader::new(client_kx.bytes());
        let client_kx_params = ClientECDHParams::read(&mut r)?;

        let secrets = ConnectionSecrets::from_key_exchange(
            self.server_key,
            &client_kx_params.payload.0,
            self.randoms,
            self.suite,
        )
        .unwrap();

        cx.state.kx_state.done();
        cx.state.start_encryption(&secrets);

        Ok(Box::new(ExpectCcs {
            config: self.config,
            secrets,
            transcript: self.transcript,
        }))
    }
}

struct ExpectCcs {
    config: Arc<ServerConfig>,
    secrets: ConnectionSecrets,
    transcript: HandshakeHash,
}
impl State for ExpectCcs {
    fn handle(
        mut self: Box<Self>,
        cx: &mut Context,
        message: Message<'_>,
    ) -> Result<Box<dyn State>, Error> {
        match message.payload {
            MessagePayload::ChangeCipherSpec(..) => {}
            payload => {
                return Err(inappropriate_message(
                    &payload,
                    &[ContentType::ChangeCipherSpec],
                ));
            }
        }

        cx.state.record_layer.start_decrypting();

        Ok(Box::new(ExpectFinished {
            config: self.config,
            secrets: self.secrets,
            transcript: self.transcript,
        }))
    }
}

fn emit_ccs(state: &mut TlsState) {
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload),
    };

    state.send_message(m, false);
}

fn emit_finished(
    state: &mut TlsState,
    transcript: &mut HandshakeHash,
    secrets: &ConnectionSecrets,
) {
    let vh = transcript.current_hash();
    let verify_data = secrets.make_verify_data(&vh, b"server finished");

    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::HandshakePayload(HandshakePayload::Finished(Payload::Borrowed(
            &verify_data,
        ))),
    };

    transcript.add_message(&m);
    state.send_message(m, true);
}

struct ExpectFinished {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    secrets: ConnectionSecrets,
}

impl State for ExpectFinished {
    fn handle(
        mut self: Box<Self>,
        cx: &mut Context,
        message: Message<'_>,
    ) -> Result<Box<dyn State>, Error> {
        let MessagePayload::HandshakePayload(HandshakePayload::Finished(finished)) =
            &message.payload
        else {
            return Err(Error::InappropriateHandshakeMessage);
        };

        let ch = self.transcript.current_hash();

        let expected_verify_data = self.secrets.make_verify_data(&ch, b"client finished");

        match expected_verify_data == finished.bytes() {
            true => {}
            false => todo!("handle finished msg wrong hash"),
        }

        self.transcript.add_message(&message);
        emit_ccs(cx.state);
        emit_finished(cx.state, &mut self.transcript, &self.secrets);
        cx.state.start_traffic();

        Ok(Box::new(ExpectTraffic {}))
    }
}

struct ExpectTraffic;

impl State for ExpectTraffic {
    fn handle(
        self: Box<Self>,
        cx: &mut Context,
        message: Message<'_>,
    ) -> Result<Box<dyn State>, Error> {
        match message.payload {
            MessagePayload::ApplicationData(appdata) => {
                cx.state.received_plaintext.extend(appdata.bytes())
            }
            payload => {
                return Err(inappropriate_message(
                    &payload,
                    &[ContentType::ApplicationData],
                ));
            }
        }

        Ok(self)
    }
}
