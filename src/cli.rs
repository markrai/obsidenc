use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "obsidenc", version)]
#[command(
    about = "Encrypt/decrypt a directory as a single encrypted tar archive.",
    long_about = "obsidenc - paranoid-grade directory encryption.\n\n\
Encrypts a directory into a single .oen file (TAR + XChaCha20-Poly1305, Argon2id),\n\
and decrypts it back to a directory. Source data is never deleted or modified\n\
automatically during encryption.\n",
    after_help = "EXAMPLES:\n  Encrypt a directory:\n    obsidenc encrypt /home/user/vault /home/user/vault.oen\n\n  Encrypt on Windows:\n    obsidenc encrypt C:\\\\Users\\\\Alice\\\\vault C:\\\\Users\\\\Alice\\\\vault.oen\n\n  Decrypt an archive:\n    obsidenc decrypt /home/user/vault.oen /home/user/vault_out\n\n  Use a keyfile (in addition to password):\n    obsidenc encrypt ./vault ./vault.oen --keyfile ./keyfile.bin\n    obsidenc decrypt ./vault.oen ./vault_out --keyfile ./keyfile.bin\n\n  Read password(s) from stdin (no interactive prompt):\n    # Encrypt: password then confirmation, each on its own line\n    printf 'my very long password here\\nmy very long password here\\n' | \\\n      obsidenc --password-stdin encrypt ./vault ./vault.oen\n\n    # Decrypt: single password line\n    printf 'my very long password here\\n' | \\\n      obsidenc --password-stdin decrypt ./vault.oen ./vault_out\n"
)]
pub struct Cli {
    /// Read password(s) from stdin instead of prompting on the TTY.
    ///
    /// Encryption expects two lines on stdin: password then confirmation.
    /// Decryption expects one line on stdin: password.
    #[arg(long, global = true)]
    pub password_stdin: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Encrypt {
        vault_dir: PathBuf,
        output_file: PathBuf,
        #[arg(long)]
        keyfile: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    Decrypt {
        input_file: PathBuf,
        output_dir: PathBuf,
        #[arg(long)]
        keyfile: Option<PathBuf>,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        /// Overwrite staging files with zeros before deletion (slower but more secure)
        secure_delete: bool,
    },
}
