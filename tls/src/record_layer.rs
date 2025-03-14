use crate::crypto::cipher::{MessageDecrypter, MessageEncrypter};
use crate::error::Error;
use crate::message::inbound::{InboundOpaqueMessage, InboundPlainMessage};
use crate::message::outbound::{OutboundOpaqueMessage, OutboundPlainMessage};

#[derive(PartialOrd, PartialEq)]
enum EncryptionState {
    Invalid,
    Prepared,
    Active,
}
pub(crate) struct RecordLayer {
    message_encrypter: Box<dyn MessageEncrypter>,
    message_decrypter: Box<dyn MessageDecrypter>,

    encrypt_state: EncryptionState,
    decrypt_state: EncryptionState,

    read_seq: u64,
    write_seq: u64,
}

impl RecordLayer {
    pub fn new() -> Self {
        Self {
            message_encrypter: <dyn MessageEncrypter>::invalid(),
            message_decrypter: <dyn MessageDecrypter>::invalid(),
            encrypt_state: EncryptionState::Invalid,
            decrypt_state: EncryptionState::Invalid,
            write_seq: 0,
            read_seq: 0,
        }
    }

    pub(crate) fn prepare_encrypter(&mut self, encrypter: Box<dyn MessageEncrypter>) {
        self.message_encrypter = encrypter;
        self.encrypt_state = EncryptionState::Prepared;
    }

    pub(crate) fn prepare_decrypter(&mut self, decrypter: Box<dyn MessageDecrypter>) {
        self.message_decrypter = decrypter;
        self.decrypt_state = EncryptionState::Prepared;
    }

    pub(crate) fn start_decrypting(&mut self) {
        debug_assert!(self.decrypt_state == EncryptionState::Prepared);
        self.decrypt_state = EncryptionState::Active;
    }

    pub(crate) fn should_decrypt(&self) -> bool {
        self.decrypt_state == EncryptionState::Active
    }
    pub(crate) fn should_encrypt(&self) -> bool {
        self.encrypt_state == EncryptionState::Active
    }

    
    pub(crate) fn decrypt<'a>(
        &mut self,
        message: InboundOpaqueMessage<'a>,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        if self.decrypt_state != EncryptionState::Active {
            return Ok(message.into());
        }

        let encrypted_len = message.payload.len();
        match self.message_decrypter.decrypt(message, self.read_seq) {
            Ok(plaintext) => {
                self.read_seq += 1;
                Ok(plaintext)
            }
            Err(err) => Err(err),
        }
    }

    pub(crate) fn encrypt(&mut self, message: OutboundPlainMessage<'_>) -> OutboundOpaqueMessage {
        let seq = self.write_seq;
        self.write_seq += 1;
        self.message_encrypter.encrypt(message, seq).unwrap()
    }
}
