//! obsidenc library API
//! 
//! This library exposes parsing and cryptographic functions for fuzzing and testing.
//! The main binary interface is in main.rs.

pub mod aead;
pub mod error;
pub mod format;

// Re-export commonly used types for convenience
pub use error::Error;
pub use format::{Header, HEADER_LEN};

