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
    // Set up signal handlers for graceful cleanup on Ctrl+C
    // This ensures Drop implementations (MemoryLock, Zeroize) run to clean up secrets
    if let Err(e) = commands::setup_signal_handlers() {
        eprintln!("Warning: Failed to set up signal handlers: {}", e);
        // Continue anyway - Drop will still run on normal exit
    }

    let cli = cli::Cli::parse();
    match commands::run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

