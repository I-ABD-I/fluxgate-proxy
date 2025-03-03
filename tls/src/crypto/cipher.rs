use std::fmt::Debug;
use ring::aead::NONCE_LEN;
use crate::codec;
use crate::crypto::kx::ActiveKx;
use crate::error::Error;
use crate::message::enums::{ContentType, ProtocolVersion};
use crate::message::fragmenter::MAX_FRAGMENT_LENGTH;
use crate::message::inbound::{InboundOpaqueMessage, InboundPlainMessage};
use crate::message::outbound::{OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload};

pub trait AeadAlgorithm: Sync + Debug {
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter>;
    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter>;
    fn key_shape(&self) -> (usize, usize, usize);
}

pub trait MessageEncrypter {
    fn encrypt(&self, msg: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, Error>;

    fn encrypted_payload_len(&self, payload_len: usize) -> usize;
}
pub trait MessageDecrypter {
    fn decrypt<'a>(&self, msg: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, Error>;
}

pub struct Nonce(pub [u8; NONCE_LEN]);

impl Nonce {
    /// Combine an `Iv` and sequence number to produce a unique nonce.
    ///
    /// This is `iv ^ seq` where `seq` is encoded as a 96-bit big-endian integer.
    #[inline]
    pub fn new(iv: &[u8; NONCE_LEN], seq: u64) -> Self {
        let mut nonce = Self([0u8; NONCE_LEN]);
        codec::put_u64(seq, &mut nonce.0[4..]);

        nonce
            .0
            .iter_mut()
            .zip(iv.iter())
            .for_each(|(nonce, iv)| {
                *nonce ^= *iv;
            });

        nonce
    }
}
pub(crate) struct Invalid;

impl MessageEncrypter for Invalid {
    fn encrypt(&self, msg: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, Error> {
        Err(Error::EncryptError)
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len
    }
}

impl MessageDecrypter for Invalid {
    fn decrypt<'a>(&self, msg: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, Error> {
        Err(Error::DecryptError)
    }
}

impl dyn MessageDecrypter {
    pub fn invalid() -> Box<dyn MessageDecrypter> {
        Box::new(Invalid)
    }
}

impl dyn MessageEncrypter {
    pub fn invalid() -> Box<dyn MessageEncrypter> {
        Box::new(Invalid)
    }
}
pub struct AeadKey {
    key: [u8; AeadKey::MAX_SIZE],
    used: usize,
}
impl AeadKey {
    const MAX_SIZE: usize = 32;
    pub(crate) fn new(key: &[u8]) -> Self {
        let mut aead_key = Self {
            key: [0u8; Self::MAX_SIZE],
            used: key.len(),
        };
        aead_key.key[..key.len()].copy_from_slice(key);
        aead_key
    }
}

impl Drop for AeadKey {
    fn drop(&mut self) {
        unsafe {
            std::ptr::write_volatile(&mut self.key, [0u8; AeadKey::MAX_SIZE]);
        }
    }
}

impl AsRef<[u8]> for AeadKey {
    fn as_ref(&self) -> &[u8] {
        &self.key[..self.used]
    }
}
#[derive(Debug)]
pub(crate) struct GCMAlgorithm(&'static ring::aead::Algorithm);
pub(crate) static AES128_GCM: GCMAlgorithm = GCMAlgorithm(&ring::aead::AES_128_GCM);

impl AeadAlgorithm for GCMAlgorithm {
    fn encrypter(&self, key: AeadKey, write_iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
        let enc_key = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(self.0, key.as_ref()).unwrap(),
        );

        let iv = {
            let mut iv = [0u8; NONCE_LEN];
            iv[..4].copy_from_slice(write_iv.as_ref());
            iv[4..].copy_from_slice(extra.as_ref());
            iv
        };

        Box::new(GcmEncrypter {
            enc_key,
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let dec_key = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(self.0, key.as_ref()).unwrap(),
        );

        let mut ret = GcmDecrypter {
            dec_key, salt: [0; 4],
        };

        ret.salt.copy_from_slice(iv);
        Box::new(ret)
    }

    fn key_shape(&self) -> (usize, usize, usize) {
        (self.0.key_len(), 4, 8)
    }
}
struct GcmEncrypter {
    enc_key: ring::aead::LessSafeKey,
    iv: [u8; NONCE_LEN],
}

struct GcmDecrypter {
    dec_key: ring::aead::LessSafeKey,
    salt: [u8; 4],
}

const GCM_EXPLICIT_NONCE_LEN: usize = 8;
const GCM_OVERHEAD: usize = GCM_EXPLICIT_NONCE_LEN + 16;
impl MessageDecrypter for GcmDecrypter {
    fn decrypt<'a>(&self, mut msg: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &msg.payload;
        if payload.len() < GCM_OVERHEAD {
            return Err(Error::DecryptError);
        }

        let nonce = {
            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&self.salt);
            nonce[4..].copy_from_slice(&payload[..8]);
            ring::aead::Nonce::assume_unique_for_key(nonce)
        };

        let aad = ring::aead::Aad::from(
            make_tls12_aad(seq, msg.typ, msg.version, payload.len() - GCM_OVERHEAD)
        );

        let payload = &mut msg.payload;
        let plain_len = self.dec_key.
            open_within(nonce, aad, payload, GCM_EXPLICIT_NONCE_LEN..).
            map_err(|_| {Error::DecryptError})?.len();

        if plain_len > MAX_FRAGMENT_LENGTH {return Err(Error::PeerSendOversizedRecord);}
        payload.truncate(plain_len);
        Ok(msg.into())
    }

}

impl MessageEncrypter for GcmEncrypter {
    fn encrypt(&self, msg: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, Error> {
        let total_len =self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        let nonce = ring::aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad = ring::aead::Aad::from(make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len()));
        payload.extend(&nonce.as_ref()[4..]);
        payload.extend(&msg.payload);

        self.enc_key.
            seal_in_place_separate_tag(nonce, aad, &mut payload.as_mut()[GCM_EXPLICIT_NONCE_LEN..]).
            map(|tag| payload.extend(tag.as_ref())).
            map_err(|_| Error::EncryptError)?;

        Ok(OutboundOpaqueMessage {
            typ: msg.typ,
            version: msg.version,
            payload,
        })
    }


    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + GCM_EXPLICIT_NONCE_LEN + self.enc_key.algorithm().tag_len()
    }
}

fn make_tls12_aad(
    seq: u64, typ: ContentType, version: ProtocolVersion, len: usize
) -> [u8; TLS12_AAD_SIZE] {
    let mut out = [0u8; TLS12_AAD_SIZE];
    codec::put_u64(seq, &mut out[0..]);
    out[8] = typ.into();
    codec::put_u16(version.into(), &mut out[9..]);
    codec::put_u16(len as u16, &mut out[11..]);
    out
}

const TLS12_AAD_SIZE: usize = 8+1+2+2;
pub trait Prf : Debug + Sync {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKx>,
        peer_pub: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), Error>;

    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]);
}