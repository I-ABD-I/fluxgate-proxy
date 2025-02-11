use std::fmt::Debug;

pub trait AeadAlgorithm: Sync + Debug {
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter>;
    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter>;
}

pub trait MessageEncrypter {
    fn encrypt(&self);
}
pub trait MessageDecrypter {
    fn decrypt(&self);
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
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
        let enc_key = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(self.0, key.as_ref()).unwrap(),
        );
        todo!();
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        todo!()
    }
}
