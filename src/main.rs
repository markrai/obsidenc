//! Threat model:
//! - The attacker can read/modify the encrypted container.
//! - The attacker has unlimited offline time.
//! - The attacker does not have runtime access to the machine during encryption/decryption.
//!
//! Design choices prioritize minimizing plaintext exposure and defensive parsing over convenience.

mod aead;
mod cli;
mod commands;
mod error;
mod format;
mod kdf;
mod securemem;
mod vaulttar;

use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = cli::Cli::parse();
    match commands::run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

