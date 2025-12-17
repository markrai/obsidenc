<img width="256" height="256" alt="image-removebg-preview (3)" src="https://github.com/user-attachments/assets/c870f10a-206f-4387-b479-45c7346b418b" />


# obsidenc v0.1.9

Paranoid-grade encryption utility. It tars a directory (no compression) and encrypts/decrypts it with Argon2id (RFC 9106 guidance) + XChaCha20-Poly1305. See [ANALYSIS.md](https://github.com/markrai/obsidenc/edit/master/ANALYSIS.md) for full details.

## Building

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (latest stable version)

### Build Commands

**Debug build:**
```sh
cargo build
```
Binary will be at: `target/debug/obsidenc` (or `target/debug/obsidenc.exe` on Windows)

**Release build (optimized):**
```sh
cargo build --release
```
Binary will be at: `target/release/obsidenc` (or `target/release/obsidenc.exe` on Windows)

**Run directly (without installing):**
```sh
cargo run -- encrypt <vault_dir> <output_file>
cargo run --release -- encrypt <vault_dir> <output_file>
```

**Windows (Command Prompt):**
```batch
run.bat encrypt <vault_dir> <output_file>
```

## Security model

- Attacker has full access to the encrypted file.
- Attacker has unlimited offline time.
- Attacker does *not* have runtime access to the machine during encryption/decryption.

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

## Fuzzing

The project includes fuzzing infrastructure to verify robustness against malformed input. Fuzzing helps ensure that the decryption parser never panics on invalid data.

**Platform Support:** Fuzzing is only available on Linux/Unix. The fuzzing targets are automatically disabled on Windows (libfuzzer-sys doesn't support Windows). The main obsidenc binary works perfectly on Windows - only the fuzzing infrastructure is platform-limited.

To run fuzzing (Linux/Unix only):

```sh
cargo install cargo-fuzz
cargo fuzz run fuzz_decrypt
```

The fuzzing target (`fuzz/fuzz_targets/fuzz_decrypt.rs`) tests:
- Header parsing with malformed input
- Chunk parsing with invalid lengths and data
- Buffer handling edge cases
- Ensures all errors are returned as `Result::Err`, never panics

**Windows Users:** If you need to run fuzzing, use WSL (Windows Subsystem for Linux) or a Linux VM. The main encryption/decryption functionality works natively on Windows.
