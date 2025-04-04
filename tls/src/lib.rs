//! This crate provides a TLS implementation with various modules for handling different aspects of the TLS protocol.
//!
//! The modules include:
//! - `acceptor`: Handles TLS acceptor functionality.
//! - `codec`: Encodes and decodes data in the TLS protocol.
//! - `config`: Manages TLS configuration settings.
//! - `connection`: Manages TLS connections.
//! - `crypto`: Performs cryptographic operations in the TLS protocol.
//! - `error`: Handles errors in the TLS protocol.
//! - `futures`: Manages futures in the TLS protocol.
//! - `hs_hash`: Manages handshake hash operations in the TLS protocol.
//! - `message`: Handles TLS messages.
//! - `record_layer`: Manages the TLS record layer.
//! - `state`: Manages the state of the TLS protocol.
//! - `stream`: Handles TLS streams.
//! - `verify`: Verifies TLS data.
//! - `server`: Provides server-side TLS functionality.
//! - `pki_types`: Handles PKI types in the TLS protocol.

#![allow(unused)]
extern crate core;

/// Module for handling TLS acceptor functionality.
mod acceptor;

/// Module for encoding and decoding data in the TLS protocol.
pub(crate) mod codec;

/// Module for TLS configuration settings.
pub mod config;

/// Module for managing TLS connections.
mod connection;

/// Module for cryptographic operations in the TLS protocol.
pub mod crypto;

/// Module for handling errors in the TLS protocol.
pub(crate) mod error;

/// Module for handling futures in the TLS protocol.
pub mod futures;

/// Module for managing handshake hash operations in the TLS protocol.
mod hs_hash;

/// Module for handling TLS messages.
pub(crate) mod message;

/// Module for managing the TLS record layer.
mod record_layer;

/// Module for managing the state of the TLS protocol.
pub mod state;

/// Module for handling TLS streams.
pub mod stream;

/// Module for verifying TLS data.
pub(crate) mod verify;

/// Module for server-side TLS functionality.
pub mod server {
    use super::acceptor;
    use super::connection;

    pub use acceptor::*;
    pub use connection::Connection;
}

/// Module for handling PKI types in the TLS protocol.
pub mod pki_types {
    pub use rustls_pki_types::*;
}
