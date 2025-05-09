#![allow(non_camel_case_types)]

use crate::codec::{Codec, Reader};
use crate::crypto;
use crate::error::InvalidMessage;

enum_builder! {
/// Represents the protocol version in TLS.
    #[repr(u16)]
    pub enum ProtocolVersion {
        SSLv2 => 0x0200,
        SSLv3 => 0x0300,
        TLSv1_0 => 0x0301,
        TLSv1_1 => 0x0302,
        TLSv1_2 => 0x0303,
        TLSv1_3 => 0x0304,
        DTLSv1_0 => 0xFEFF,
        DTLSv1_2 => 0xFEFD,
        DTLSv1_3 => 0xFEFC,
    }
}

enum_builder! {
/// Represents the content type in TLS.
    #[repr(u8)]
    pub enum ContentType {
        ChangeCipherSpec => 20,
        Alert => 21,
        Handshake => 22,
        ApplicationData => 23,
    }
}

enum_builder! {
/// Represents the cipher suite in TLS.
    #[repr(u16)]
    pub enum CipherSuite {
        TLS_NULL_WITH_NULL_NULL => 0x0000,
        TLS_RSA_WITH_NULL_MD5 => 0x0001,
        TLS_RSA_WITH_NULL_SHA => 0x0002,
        TLS_RSA_WITH_RC4_128_MD5 => 0x0004,
        TLS_RSA_WITH_RC4_128_SHA => 0x0005,
        TLS_RSA_WITH_3DES_EDE_CBC_SHA => 0x000A,
        TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA => 0x000D,
        TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA => 0x0010,
        TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA => 0x0013,
        TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA => 0x0016,
        TLS_DH_anon_WITH_RC4_128_MD5 => 0x0018,
        TLS_DH_anon_WITH_3DES_EDE_CBC_SHA => 0x001B,
        TLS_RSA_WITH_AES_128_CBC_SHA => 0x002F,
        TLS_DH_DSS_WITH_AES_128_CBC_SHA => 0x0030,
        TLS_DH_RSA_WITH_AES_128_CBC_SHA => 0x0031,
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA => 0x0032,
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA => 0x0033,
        TLS_DH_anon_WITH_AES_128_CBC_SHA => 0x0034,
        TLS_RSA_WITH_AES_256_CBC_SHA => 0x0035,
        TLS_DH_DSS_WITH_AES_256_CBC_SHA => 0x0036,
        TLS_DH_RSA_WITH_AES_256_CBC_SHA => 0x0037,
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA => 0x0038,
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA => 0x0039,
        TLS_DH_anon_WITH_AES_256_CBC_SHA => 0x003A,
        TLS_RSA_WITH_NULL_SHA256 => 0x003B,
        TLS_RSA_WITH_AES_128_CBC_SHA256 => 0x003C,
        TLS_RSA_WITH_AES_256_CBC_SHA256 => 0x003D,
        TLS_DH_DSS_WITH_AES_128_CBC_SHA256 => 0x003E,
        TLS_DH_RSA_WITH_AES_128_CBC_SHA256 => 0x003F,
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 => 0x0040,
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 => 0x0067,
        TLS_DH_DSS_WITH_AES_256_CBC_SHA256 => 0x0068,
        TLS_DH_RSA_WITH_AES_256_CBC_SHA256 => 0x0069,
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 => 0x006A,
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 => 0x006B,
        TLS_DH_anon_WITH_AES_128_CBC_SHA256 => 0x006C,
        TLS_DH_anon_WITH_AES_256_CBC_SHA256 => 0x006D,
        TLS_ECDHE_ECDSA_WITH_NULL_SHA => 0xC006,
        TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA => 0xC008,
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA => 0xC009,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => 0xC00A,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => 0xC02B,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => 0xC02C,
        TLS_ECDHE_RSA_WITH_NULL_SHA => 0xC010,
        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA => 0xC012,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => 0xC013,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => 0xC014,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => 0xC02F,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => 0xC030,
        TLS_ECDH_anon_WITH_NULL_SHA => 0xC015,
        TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA => 0xC017,
        TLS_ECDH_anon_WITH_AES_128_CBC_SHA => 0xC018,
        TLS_ECDH_anon_WITH_AES_256_CBC_SHA => 0xC019,
        TLS_EMPTY_RENEGOTIATION_INFO_SCSV => 0x00ff,
    }
}

enum_builder! {
/// Represents the compression method in TLS.
    #[repr(u8)]
    pub enum CompressionMethod {
        Null => 0
    }
}

enum_builder! {
/// Represents the extension type in TLS.
    #[repr(u16)]
    pub enum ExtensionType {
        ServerName => 0,
        SignatureAlgorithm => 13,
        EllipticCurves => 10,
        ECPointFormats => 11,
        RenegotationInfo => 0xff01,
        ExtendedMasterSecret => 0x0017,
    }
}

enum_builder! {
/// Represents the hash algorithm in TLS.
    #[repr(u8)]
    pub enum HashAlgorithm {
        none => 0,
        md5 => 1,
        sha1 => 2,
        sha224 => 3,
        sha256 => 4,
        sha384 => 5,
        sha512 => 6,
        reserved => 255,
    }
}

enum_builder! {
/// Represents the signature algorithm in TLS.
    #[repr(u8)]
    pub enum SignatureAlgorithm {
        anonymous => 0,
        rsa => 1, // not supporting rsa_pss
        dsa => 2,
        ecdsa => 3,
        reserved => 255,
    }
}

enum_builder! {
/// Represents the key exchange algorithm in TLS.
    #[repr(u8)]
    pub enum KeyExchangeAlgorithm {
        dhe_dss => 0,
        dhe_rsa => 1,
        dh_anon => 2,
        rsa => 3,
        dh_dss => 4,
        dh_rsa => 5,
    }
}

enum_builder! {
/// Represents the named curve in TLS.
    #[repr(u16)]
    pub enum NamedCurve {
        secp256r1 => 23,
        secp384r1 => 24,
        secp521r1 => 25,
        x25519 => 29,
        x448 => 30,
    }
}

impl NamedCurve {
    /// Return the key exchange algorithm associated with this `NamedCurve`.
    pub fn key_exchange_algorithm(self) -> crypto::kx::KeyExchangeAlgorithm {
        match u16::from(self) {
            x if (0x100..0x200).contains(&x) => crypto::kx::KeyExchangeAlgorithm::DHE,
            _ => crypto::kx::KeyExchangeAlgorithm::ECDHE,
        }
    }
}

enum_builder! {
    /// The `ECPointFormat` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    #[repr(u8)]
    pub enum ECPointFormat {
        Uncompressed => 0x00,
        ANSIX962CompressedPrime => 0x01,
        ANSIX962CompressedChar2 => 0x02,
    }
}

impl ECPointFormat {
    /// Returns the supported point format for the given `ECPointFormat`.
    pub(crate) const SUPPORTED: [Self; 1] = [Self::Uncompressed];
}

enum_builder! {
    /// The `ECCurveType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    #[repr(u8)]
    pub(crate) enum ECCurveType {
        ExplicitPrime => 0x01,
        ExplicitChar2 => 0x02,
        NamedCurve => 0x03,
    }
}

enum_builder! {
    /// The `ServerNameType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    #[repr(u8)]
    pub(crate) enum ServerNameType {
        HostName => 0x00,
    }
}

enum_builder! {
    /// The `SignatureScheme` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    #[repr(u16)]
    pub enum SignatureScheme {
        RSA_PKCS1_SHA1 => 0x0201,
        ECDSA_SHA1_Legacy => 0x0203,
        RSA_PKCS1_SHA256 => 0x0401,
        ECDSA_NISTP256_SHA256 => 0x0403,
        RSA_PKCS1_SHA384 => 0x0501,
        ECDSA_NISTP384_SHA384 => 0x0503,
        RSA_PKCS1_SHA512 => 0x0601,
        ECDSA_NISTP521_SHA512 => 0x0603,
        RSA_PSS_SHA256 => 0x0804,
        RSA_PSS_SHA384 => 0x0805,
        RSA_PSS_SHA512 => 0x0806,
    }
}

impl SignatureScheme {
    /// Returns the signature algorithm associated with this `SignatureScheme`.
    pub(crate) fn algorithm(&self) -> SignatureAlgorithm {
        match *self {
            Self::RSA_PKCS1_SHA1
            | Self::RSA_PKCS1_SHA256
            | Self::RSA_PKCS1_SHA384
            | Self::RSA_PKCS1_SHA512
            | Self::RSA_PSS_SHA256
            | Self::RSA_PSS_SHA384
            | Self::RSA_PSS_SHA512 => SignatureAlgorithm::rsa,
            Self::ECDSA_SHA1_Legacy
            | Self::ECDSA_NISTP256_SHA256
            | Self::ECDSA_NISTP384_SHA384
            | Self::ECDSA_NISTP521_SHA512 => SignatureAlgorithm::ecdsa,
            _ => SignatureAlgorithm::Unknown(0),
        }
    }
}
