use crate::crypto::cipher::{MessageDecrypter, MessageEncrypter};
use crate::error::Error;
use crate::message::inbound::{InboundOpaqueMessage, InboundPlainMessage};
use crate::message::outbound::{OutboundOpaqueMessage, OutboundPlainMessage};

/// Represents the state of encryption.
#[derive(PartialOrd, PartialEq)]
enum EncryptionState {
    /// Invalid state.
    Invalid,
    /// Prepared state.
    Prepared,
    /// Active state.
    Active,
}

/// Manages the record layer for encrypting and decrypting messages.
pub(crate) struct RecordLayer {
    /// The message encrypter.
    message_encrypter: Box<dyn MessageEncrypter>,
    /// The message decrypter.
    message_decrypter: Box<dyn MessageDecrypter>,

    /// The state of encryption.
    encrypt_state: EncryptionState,
    /// The state of decryption.
    decrypt_state: EncryptionState,

    /// The read sequence number.
    read_seq: u64,
    /// The write sequence number.
    write_seq: u64,
}

impl RecordLayer {
    /// Creates a new `RecordLayer`.
    ///
    /// # Returns
    /// A new `RecordLayer` instance.
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

    /// Prepares the encrypter for use.
    ///
    /// # Arguments
    /// * `encrypter` - The encrypter to use.
    pub(crate) fn prepare_encrypter(&mut self, encrypter: Box<dyn MessageEncrypter>) {
        self.message_encrypter = encrypter;
        self.encrypt_state = EncryptionState::Active;
    }

    /// Prepares the decrypter for use.
    ///
    /// # Arguments
    /// * `decrypter` - The decrypter to use.
    pub(crate) fn prepare_decrypter(&mut self, decrypter: Box<dyn MessageDecrypter>) {
        self.message_decrypter = decrypter;
        self.decrypt_state = EncryptionState::Prepared;
    }

    /// Starts the decryption process.
    pub(crate) fn start_decrypting(&mut self) {
        debug_assert!(self.decrypt_state == EncryptionState::Prepared);
        self.decrypt_state = EncryptionState::Active;
    }

    /// Checks if decryption should be performed.
    ///
    /// # Returns
    /// `true` if decryption should be performed, `false` otherwise.
    pub(crate) fn should_decrypt(&self) -> bool {
        self.decrypt_state == EncryptionState::Active
    }

    /// Checks if encryption should be performed.
    ///
    /// # Returns
    /// `true` if encryption should be performed, `false` otherwise.
    pub(crate) fn should_encrypt(&self) -> bool {
        self.encrypt_state == EncryptionState::Active
    }

    /// Decrypts an inbound message.
    ///
    /// # Arguments
    /// * `message` - The inbound opaque message.
    ///
    /// # Returns
    /// The decrypted plain message or an error.
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

    /// Encrypts an outbound message.
    ///
    /// # Arguments
    /// * `message` - The outbound plain message.
    ///
    /// # Returns
    /// The encrypted opaque message.
    pub(crate) fn encrypt(&mut self, message: OutboundPlainMessage<'_>) -> OutboundOpaqueMessage {
        let seq = self.write_seq;
        self.write_seq += 1;
        self.message_encrypter.encrypt(message, seq).unwrap()
    }
}
