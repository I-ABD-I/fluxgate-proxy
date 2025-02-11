use crate::message::enums::NamedCurve;
use std::fmt::Debug;

pub trait SupportedKxGroup: Sync + Debug {
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
    fn group(&self) -> NamedCurve {
        self.group
    }
}

pub static X25519: KxGroup = KxGroup {
    group: NamedCurve::x25519,
    agreement_algorithm: &ring::agreement::X25519,
};
