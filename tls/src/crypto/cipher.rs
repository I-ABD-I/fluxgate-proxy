use crate::codec;
use crate::crypto::kx::ActiveKx;
use crate::error::Error;
use crate::message::enums::{ContentType, ProtocolVersion};
use crate::message::fragmenter::MAX_FRAGMENT_LENGTH;
use crate::message::inbound::{InboundOpaqueMessage, InboundPlainMessage};
use crate::message::outbound::{OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload};
use ring::aead::NONCE_LEN;
use std::fmt::Debug;

/// A trait representing an AEAD (Authenticated Encryption with Associated Data) algorithm.
///
/// This trait provides methods to create encrypters and decrypters, and to get the key shape.
pub trait AeadAlgorithm: Send + Sync + Debug {
    /// Creates an encrypter with the given key, IV, and extra data.
    ///
    /// # Arguments
    ///
    /// * `key` - The AEAD key.
    /// * `iv` - The initialization vector.
    /// * `extra` - Additional data.
    ///
    /// # Returns
    ///
    /// A boxed `MessageEncrypter`.
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter>;

    /// Creates a decrypter with the given key and IV.
    ///
    /// # Arguments
    ///
    /// * `key` - The AEAD key.
    /// * `iv` - The initialization vector.
    ///
    /// # Returns
    ///
    /// A boxed `MessageDecrypter`.
    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter>;

    /// Returns the key shape as a tuple of three sizes.
    ///
    /// # Returns
    ///
    /// A tuple containing the key size, IV size, and tag size.
    fn key_shape(&self) -> (usize, usize, usize);
}

/// A trait representing a message encrypter.
///
/// This trait provides methods to encrypt messages and to get the encrypted payload length.
pub trait MessageEncrypter: Sync + Send {
    /// Encrypts the given message with the provided sequence number.
    ///
    /// # Arguments
    ///
    /// * `msg` - The outbound plain message to encrypt.
    /// * `seq` - The sequence number.
    ///
    /// # Returns
    ///
    /// A result containing the outbound opaque message or an error.
    fn encrypt(
        &self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error>;

    /// Returns the length of the encrypted payload.
    ///
    /// # Arguments
    ///
    /// * `payload_len` - The length of the payload.
    ///
    /// # Returns
    ///
    /// The length of the encrypted payload.
    fn encrypted_payload_len(&self, payload_len: usize) -> usize;
}

/// A trait representing a message decrypter.
///
/// This trait provides a method to decrypt messages.
pub trait MessageDecrypter: Send + Sync {
    /// Decrypts the given message with the provided sequence number.
    ///
    /// # Arguments
    ///
    /// * `msg` - The inbound opaque message to decrypt.
    /// * `seq` - The sequence number.
    ///
    /// # Returns
    ///
    /// A result containing the inbound plain message or an error.
    fn decrypt<'a>(
        &self,
        msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error>;
}

/// A structure representing a nonce.
///
/// This structure provides a method to create a new nonce from an IV and sequence number.
pub struct Nonce(pub [u8; NONCE_LEN]);

impl Nonce {
    /// Combines an IV and sequence number to produce a unique nonce.
    ///
    /// This is `iv ^ seq` where `seq` is encoded as a 96-bit big-endian integer.
    ///
    /// # Arguments
    ///
    /// * `iv` - The initialization vector.
    /// * `seq` - The sequence number.
    ///
    /// # Returns
    ///
    /// A new `Nonce`.
    #[inline]
    pub fn new(iv: &[u8; NONCE_LEN], seq: u64) -> Self {
        let mut nonce = Self([0u8; NONCE_LEN]);
        codec::put_u64(seq, &mut nonce.0[4..]);

        nonce.0.iter_mut().zip(iv.iter()).for_each(|(nonce, iv)| {
            *nonce ^= *iv;
        });

        nonce
    }
}

/// A structure representing an invalid encrypter.
///
/// This structure provides methods to simulate encryption errors.
pub(crate) struct Invalid;

impl MessageEncrypter for Invalid {
    /// Simulates an encryption error.
    ///
    /// # Arguments
    ///
    /// * `msg` - The outbound plain message to encrypt.
    /// * `seq` - The sequence number.
    ///
    /// # Returns
    ///
    /// An error indicating encryption failure.
    fn encrypt(
        &self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        Err(Error::EncryptError)
    }

    /// Returns the length of the payload as the encrypted payload length.
    ///
    /// # Arguments
    ///
    /// * `payload_len` - The length of the payload.
    ///
    /// # Returns
    ///
    /// The length of the payload.
    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len
    }
}

impl MessageDecrypter for Invalid {
    /// Simulates a decryption error.
    ///
    /// # Arguments
    ///
    /// * `msg` - The inbound opaque message to decrypt.
    /// * `seq` - The sequence number.
    ///
    /// # Returns
    ///
    /// An error indicating decryption failure.
    fn decrypt<'a>(
        &self,
        msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        Err(Error::DecryptError)
    }
}

impl dyn MessageDecrypter {
    /// Returns an invalid message decrypter.
    ///
    /// # Returns
    ///
    /// A boxed `Invalid` decrypter.
    pub fn invalid() -> Box<dyn MessageDecrypter> {
        Box::new(Invalid)
    }
}

impl dyn MessageEncrypter {
    /// Returns an invalid message encrypter.
    ///
    /// # Returns
    ///
    /// A boxed `Invalid` encrypter.
    pub fn invalid() -> Box<dyn MessageEncrypter> {
        Box::new(Invalid)
    }
}

/// A structure representing an AEAD key.
///
/// This structure provides methods to create a new AEAD key and to get the key as a slice.
pub struct AeadKey {
    key: [u8; AeadKey::MAX_SIZE],
    used: usize,
}

impl AeadKey {
    const MAX_SIZE: usize = 32;

    /// Creates a new AEAD key from the given key slice.
    ///
    /// # Arguments
    ///
    /// * `key` - The key slice.
    ///
    /// # Returns
    ///
    /// A new `AeadKey`.
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
    /// Clears the key when the `AeadKey` is dropped.
    fn drop(&mut self) {
        unsafe {
            std::ptr::write_volatile(&mut self.key, [0u8; AeadKey::MAX_SIZE]);
        }
    }
}

impl AsRef<[u8]> for AeadKey {
    /// Returns the key as a slice.
    ///
    /// # Returns
    ///
    /// A slice of the key.
    fn as_ref(&self) -> &[u8] {
        &self.key[..self.used]
    }
}

/// A structure representing a GCM (Galois/Counter Mode) algorithm.
///
/// This structure provides methods to create encrypters and decrypters for GCM.
#[derive(Debug)]
pub(crate) struct GCMAlgorithm(&'static ring::aead::Algorithm);

/// A static instance of the AES-128-GCM algorithm.
pub(crate) static AES128_GCM: GCMAlgorithm = GCMAlgorithm(&ring::aead::AES_128_GCM);

impl AeadAlgorithm for GCMAlgorithm {
    /// Creates a GCM encrypter with the given key, IV, and extra data.
    ///
    /// # Arguments
    ///
    /// * `key` - The AEAD key.
    /// * `write_iv` - The initialization vector.
    /// * `extra` - Additional data.
    ///
    /// # Returns
    ///
    /// A boxed `GcmEncrypter`.
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

        Box::new(GcmEncrypter { enc_key, iv })
    }

    /// Creates a GCM decrypter with the given key and IV.
    ///
    /// # Arguments
    ///
    /// * `key` - The AEAD key.
    /// * `iv` - The initialization vector.
    ///
    /// # Returns
    ///
    /// A boxed `GcmDecrypter`.
    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let dec_key = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(self.0, key.as_ref()).unwrap(),
        );

        let mut ret = GcmDecrypter {
            dec_key,
            salt: [0; 4],
        };

        ret.salt.copy_from_slice(iv);
        Box::new(ret)
    }

    /// Returns the key shape as a tuple of three sizes.
    ///
    /// # Returns
    ///
    /// A tuple containing the key size, IV size, and tag size.
    fn key_shape(&self) -> (usize, usize, usize) {
        (self.0.key_len(), 4, 8)
    }
}

/// A structure representing a GCM encrypter.
///
/// This structure provides methods to encrypt messages using GCM.
struct GcmEncrypter {
    enc_key: ring::aead::LessSafeKey,
    iv: [u8; NONCE_LEN],
}

/// A structure representing a GCM decrypter.
///
/// This structure provides methods to decrypt messages using GCM.
struct GcmDecrypter {
    dec_key: ring::aead::LessSafeKey,
    salt: [u8; 4],
}

const GCM_EXPLICIT_NONCE_LEN: usize = 8;
const GCM_OVERHEAD: usize = GCM_EXPLICIT_NONCE_LEN + 16;

impl MessageDecrypter for GcmDecrypter {
    /// Decrypts the given message with the provided sequence number.
    ///
    /// # Arguments
    ///
    /// * `msg` - The inbound opaque message to decrypt.
    /// * `seq` - The sequence number.
    ///
    /// # Returns
    ///
    /// A result containing the inbound plain message or an error.
    fn decrypt<'a>(
        &self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
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

        let aad = ring::aead::Aad::from(make_tls12_aad(
            seq,
            msg.typ,
            msg.version,
            payload.len() - GCM_OVERHEAD,
        ));

        let payload = &mut msg.payload;
        let plain_len = self
            .dec_key
            .open_within(nonce, aad, payload, GCM_EXPLICIT_NONCE_LEN..)
            .map_err(|_| Error::DecryptError)?
            .len();

        if plain_len > MAX_FRAGMENT_LENGTH {
            return Err(Error::PeerSendOversizedRecord);
        }
        payload.truncate(plain_len);
        Ok(msg.into())
    }
}

impl MessageEncrypter for GcmEncrypter {
    /// Encrypts the given message with the provided sequence number.
    ///
    /// # Arguments
    ///
    /// * `msg` - The outbound plain message to encrypt.
    /// * `seq` - The sequence number.
    ///
    /// # Returns
    ///
    /// A result containing the outbound opaque message or an error.
    fn encrypt(
        &self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        let nonce = ring::aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad =
            ring::aead::Aad::from(make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len()));
        payload.extend(&nonce.as_ref()[4..]);
        payload.extend(msg.payload);

        self.enc_key
            .seal_in_place_separate_tag(nonce, aad, &mut payload.as_mut()[GCM_EXPLICIT_NONCE_LEN..])
            .map(|tag| payload.extend(tag.as_ref()))
            .map_err(|_| Error::EncryptError)?;

        Ok(OutboundOpaqueMessage {
            typ: msg.typ,
            version: msg.version,
            payload,
        })
    }

    /// Returns the length of the encrypted payload.
    ///
    /// # Arguments
    ///
    /// * `payload_len` - The length of the payload.
    ///
    /// # Returns
    ///
    /// The length of the encrypted payload.
    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + GCM_EXPLICIT_NONCE_LEN + self.enc_key.algorithm().tag_len()
    }
}

/// Creates a TLS 1.2 Additional Authenticated Data (AAD) for the given parameters.
///
/// # Arguments
///
/// * `seq` - The sequence number.
/// * `typ` - The content type.
/// * `version` - The protocol version.
/// * `len` - The length of the payload.
///
/// # Returns
///
/// A 13-byte array containing the AAD.
fn make_tls12_aad(
    seq: u64,
    typ: ContentType,
    version: ProtocolVersion,
    len: usize,
) -> [u8; TLS12_AAD_SIZE] {
    let mut out = [0u8; TLS12_AAD_SIZE];
    codec::put_u64(seq, &mut out[0..]);
    out[8] = typ.into();
    codec::put_u16(version.into(), &mut out[9..]);
    codec::put_u16(len as u16, &mut out[11..]);
    out
}

const TLS12_AAD_SIZE: usize = 8 + 1 + 2 + 2;

/// A trait representing a Pseudo-Random Function (PRF).
///
/// This trait provides methods to generate keys for key exchange and secrets.
pub trait Prf: Debug + Sync {
    /// Generates a key for key exchange.
    ///
    /// # Arguments
    ///
    /// * `output` - The output buffer.
    /// * `kx` - The active key exchange.
    /// * `peer_pub` - The peer's public key.
    /// * `label` - The label.
    /// * `seed` - The seed.
    ///
    /// # Returns
    ///
    /// A result indicating success or failure.
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKx>,
        peer_pub: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), Error>;

    /// Generates a secret.
    ///
    /// # Arguments
    ///
    /// * `output` - The output buffer.
    /// * `secret` - The secret.
    /// * `label` - The label.
    /// * `seed` - The seed.
    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]);
}
