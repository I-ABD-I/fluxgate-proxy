use crate::error::{Error, GetRandomFailed};
use crate::message::enums::NamedCurve;
use std::fmt::Debug;

/// A trait representing a supported key exchange group.
///
/// This trait provides methods to start a key exchange and to get the group.
pub trait SupportedKxGroup: Send + Sync + Debug {
    /// Starts a key exchange.
    ///
    /// # Returns
    ///
    /// A result containing a boxed `ActiveKx` or an error.
    fn start(&self) -> Result<Box<dyn ActiveKx>, Error>;

    /// Returns the key exchange group.
    ///
    /// # Returns
    ///
    /// The `NamedCurve` representing the group.
    fn group(&self) -> NamedCurve;
}

/// Describes supported key exchange mechanisms.
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum KeyExchangeAlgorithm {
    /// Diffie-Hellman Key exchange (with only known parameters as defined in [RFC 7919]).
    ///
    /// [RFC 7919]: https://datatracker.ietf.org/doc/html/rfc7919
    DHE,
    /// Key exchange performed via elliptic curve Diffie-Hellman.
    ECDHE,
}

/// A structure representing a key exchange group.
///
/// This structure contains the group and the agreement algorithm.
#[derive(Debug)]
pub struct KxGroup {
    pub(crate) group: NamedCurve,
    pub(crate) agreement_algorithm: &'static ring::agreement::Algorithm,
}

impl SupportedKxGroup for KxGroup {
    /// Starts a key exchange.
    ///
    /// # Returns
    ///
    /// A result containing a boxed `ActiveKx` or an error.
    fn start(&self) -> Result<Box<dyn ActiveKx>, Error> {
        let rng = ring::rand::SystemRandom::new();
        let priv_key =
            ring::agreement::EphemeralPrivateKey::generate(self.agreement_algorithm, &rng)
                .map_err(|_| GetRandomFailed)?;

        let pub_key = priv_key.compute_public_key().map_err(|_| GetRandomFailed)?;

        Ok(Box::new(KeyExchange {
            group: self.group,
            agreement_algorithm: self.agreement_algorithm,
            priv_key,
            pub_key,
        }))
    }

    /// Returns the key exchange group.
    ///
    /// # Returns
    ///
    /// The `NamedCurve` representing the group.
    fn group(&self) -> NamedCurve {
        self.group
    }
}

/// A static instance of the X25519 key exchange group.
pub static X25519: KxGroup = KxGroup {
    group: NamedCurve::x25519,
    agreement_algorithm: &ring::agreement::X25519,
};

/// A trait representing an active key exchange.
///
/// This trait provides methods to complete the key exchange, get the group, and get the public key.
pub trait ActiveKx: Send + Sync {
    /// Completes the key exchange.
    ///
    /// # Arguments
    ///
    /// * `peer_pub_key` - A slice of bytes representing the peer's public key.
    ///
    /// # Returns
    ///
    /// A result containing a vector of bytes or an error.
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<Vec<u8>, Error>;

    /// Returns the key exchange group.
    ///
    /// # Returns
    ///
    /// The `NamedCurve` representing the group.
    fn group(&self) -> NamedCurve;

    /// Returns the public key.
    ///
    /// # Returns
    ///
    /// A slice of bytes representing the public key.
    fn pub_key(&self) -> &[u8];
}

/// A structure representing a key exchange.
///
/// This structure contains the group, the agreement algorithm, the private key, and the public key.
struct KeyExchange {
    group: NamedCurve,
    agreement_algorithm: &'static ring::agreement::Algorithm,
    priv_key: ring::agreement::EphemeralPrivateKey,
    pub_key: ring::agreement::PublicKey,
}

impl ActiveKx for KeyExchange {
    /// Completes the key exchange.
    ///
    /// # Arguments
    ///
    /// * `peer_pub_key` - A slice of bytes representing the peer's public key.
    ///
    /// # Returns
    ///
    /// A result containing a vector of bytes or an error.
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<Vec<u8>, Error> {
        let peer_key =
            ring::agreement::UnparsedPublicKey::new(self.agreement_algorithm, &peer_pub_key);
        ring::agreement::agree_ephemeral(self.priv_key, &peer_key, |slice| slice.to_vec())
            .map_err(|_| GetRandomFailed.into())
    }

    /// Returns the key exchange group.
    ///
    /// # Returns
    ///
    /// The `NamedCurve` representing the group.
    fn group(&self) -> NamedCurve {
        self.group
    }

    /// Returns the public key.
    ///
    /// # Returns
    ///
    /// A slice of bytes representing the public key.
    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_ref()
    }
}
