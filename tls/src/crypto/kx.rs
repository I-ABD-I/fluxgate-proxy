use crate::message::enums::NamedCurve;
use std::fmt::Debug;
use crate::error::{Error, GetRandomFailed};

pub trait SupportedKxGroup: Sync + Debug {
    fn start(&self) -> Result<Box<dyn ActiveKx>, Error>;

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

#[derive(Debug)]
pub struct KxGroup {
    pub(crate) group: NamedCurve,
    pub(crate) agreement_algorithm: &'static ring::agreement::Algorithm,
}

impl SupportedKxGroup for KxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKx>, Error> {
        let rng = ring::rand::SystemRandom::new();
        let priv_key = ring::agreement::EphemeralPrivateKey::generate(self.agreement_algorithm,&rng ).map_err(|_| GetRandomFailed)?;

        let pub_key = priv_key.compute_public_key().map_err(|_| GetRandomFailed)?;

        Ok(Box::new(KeyExchange {
            group: self.group,
            agreement_algorithm: self.agreement_algorithm,
            priv_key, pub_key
        }))
    }
    fn group(&self) -> NamedCurve {
        self.group
    }
}

pub static X25519: KxGroup = KxGroup {
    group: NamedCurve::x25519,
    agreement_algorithm: &ring::agreement::X25519,
};


pub trait ActiveKx {
    fn group(&self) -> NamedCurve;
    fn pub_key(&self) -> &[u8];
}



struct KeyExchange {
    group: NamedCurve,
    agreement_algorithm: &'static ring::agreement::Algorithm,
    priv_key: ring::agreement::EphemeralPrivateKey,
    pub_key: ring::agreement::PublicKey,
}

impl ActiveKx for KeyExchange {
    fn group(&self) -> NamedCurve {
        self.group
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_ref()
    }
}