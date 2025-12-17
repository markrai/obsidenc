//! obsidenc library API
//! 
//! This library exposes parsing and cryptographic functions for fuzzing and testing.
//! The main binary interface is in main.rs.

pub mod aead;
pub mod error;
pub mod format;

// Re-export commonly used types for convenience
pub use error::Error;
pub use format::{
    Header, HEADER_LEN, SALT_LEN, NONCE_LEN, ARGON_PARAMS_LEN, VERIFICATION_TOKEN_LEN,
    ARGON2_VARIANT_ID, ARGON2_VERSION_13, KDF_DOMAIN_VERSION_V1, VERSION,
};

