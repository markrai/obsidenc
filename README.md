# obsidenc

Paranoid-grade vault encryption utility for Obsidian (or any directory). It tars a directory (no compression) and encrypts/decrypts it with Argon2id (RFC 9106 guidance) + XChaCha20-Poly1305.

## Security model

- Attacker has full access to the encrypted file.
- Attacker has unlimited offline time.
- Attacker does *not* have runtime access to the machine during encryption/decryption.

If you need usability over security, this tool is not the right fit.

## Usage

```sh
obsidenc encrypt <vault_dir> <output_file> [--keyfile <path>] [--force]
obsidenc decrypt <input_file> <output_dir> [--keyfile <path>] [--force]
```

Notes:
- Encryption prompts for the password twice (confirmation).
- Minimum password length is 20 characters.
- If `--keyfile` is used, both password and keyfile are required.
- Decryption refuses to overwrite an existing output directory unless `--force` is supplied.

## Supply-chain security (release blockers)

Install and run:

```sh
cargo install cargo-audit
cargo audit
```

Treat all RustSec advisories as release blockers.

