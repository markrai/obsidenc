use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid arguments: {0}")]
    InvalidArgs(&'static str),

    #[error("unsupported input: {0}")]
    Unsupported(&'static str),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("cryptographic failure")]
    Crypto,

    #[error("authentication failed")]
    AuthenticationFailed,

    #[error("incorrect password or keyfile")]
    BadPassword,

    #[error("container format error: {0}")]
    Format(&'static str),

    #[error("refusing to overwrite existing path: {0}")]
    WouldOverwrite(PathBuf),

    #[error("keyfile too large (maximum 4 MiB)")]
    KeyfileTooLarge,

    #[error("password policy violation: {0}")]
    PasswordPolicy(&'static str),

    #[error("operation interrupted by user")]
    Interrupted,
}
