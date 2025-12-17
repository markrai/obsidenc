<img width="256" height="256" alt="Obsidenc Logo" src="https://github.com/user-attachments/assets/c870f10a-206f-4387-b479-45c7346b418b" />


# obsidenc v0.1.11

Paranoid-grade encryption utility. It tars a directory (no compression) and encrypts/decrypts it with Argon2id (RFC 9106 guidance) + XChaCha20-Poly1305. See [ANALYSIS.md](./ANALYSIS.md) for full details.

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

**Linux/Unix:**
```sh
chmod +x run.sh
./run.sh encrypt <vault_dir> <output_file>
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

### Non-interactive password input

For automation (and the bundled GUI), passwords can be provided via stdin:

```sh
# Encrypt: 2 lines on stdin (password + confirmation)
printf '%s\n%s\n' "$PW" "$PW" | obsidenc --password-stdin encrypt <vault_dir> <output_file>

# Decrypt: 1 line on stdin (password)
printf '%s\n' "$PW" | obsidenc --password-stdin decrypt <input_file> <output_dir>
```

## GUI (Tauri)

The repository includes a minimal Tauri desktop UI that drives `obsidenc` as a bundled sidecar binary. The GUI does **not** implement crypto; it spawns `obsidenc` and passes the password via stdin (`--password-stdin`).

From `gui/`:

```sh
# Dev (builds sidecar + starts a local UI server)
cargo tauri dev

# Release bundle (builds sidecar from source and embeds it)
cargo tauri build
```

## Supply-chain security (release blockers)

Install and run:

```sh
cargo install cargo-audit
cargo audit
```

## Fuzzing

The project includes fuzzing infrastructure to verify robustness against malformed input. Fuzzing helps ensure that the decryption parser never panics on invalid data.

**Platform Support:** Fuzzing is only available on Linux/Unix. The fuzzing targets are automatically disabled on Windows (libfuzzer-sys doesn't support Windows). The main obsidenc binary works perfectly on Windows - only the fuzzing infrastructure is platform-limited.

### Running Fuzzing on Linux

**Prerequisites:**
- Linux system (or WSL on Windows)
- Rust nightly toolchain (fuzzing requires nightly features)
- LLVM/Clang (required for libfuzzer)

**Step 1: Install Rust nightly toolchain**
```sh
# Install nightly (if not already installed)
rustup toolchain install nightly

# Use nightly for fuzzing (you can switch back to stable after)
rustup default nightly
# OR use nightly just for this project:
rustup override set nightly
```

**Step 2: Install cargo-fuzz**
```sh
cargo install cargo-fuzz
```

**Step 3: Run the fuzzing target**
```sh
# From the project root directory
cargo fuzz run fuzz_decrypt
```

**Note:** If you want to keep stable as your default toolchain, you can use `rustup override set nightly` in the project directory instead of `rustup default nightly`. This sets nightly only for this project.

**Step 3: Let it run**
- The fuzzer will run indefinitely, generating random inputs
- Press Ctrl+C to stop
- If a panic is found, the fuzzer will save the input that caused it to `fuzz/artifacts/fuzz_decrypt/`
- Check the output for any crashes or panics

**Advanced options:**
```sh
# Run with a timeout (e.g., 60 seconds)
cargo fuzz run fuzz_decrypt -- -max_total_time=60

# Run for a specific number of iterations
cargo fuzz run fuzz_decrypt -- -runs=10000

# Run with corpus (saved interesting inputs)
cargo fuzz run fuzz_decrypt -- -merge=1
```

**What the fuzzing target tests:**
- Header parsing with malformed input (wrong magic bytes, invalid version, etc.)
- Chunk parsing with invalid lengths and data
- Buffer handling edge cases (empty chunks, oversized chunks, etc.)
- Ensures all errors are returned as `Result::Err`, never panics

**Improving Fuzzing Coverage:**

The fuzzer automatically constructs valid headers to test chunk parsing logic, but you can improve coverage by adding seed corpus files. Seed corpus files are real encrypted files that help the fuzzer discover valid input patterns.

**Creating a Seed Corpus:**

1. Create some test encrypted files:
   ```sh
   # Create a test directory
   mkdir -p /tmp/test_vault
   echo "test content" > /tmp/test_vault/test.txt
   
   # Encrypt it
   ./target/release/obsidenc encrypt /tmp/test_vault /tmp/test.oen
   
   # Copy to seed corpus
   cp /tmp/test.oen fuzz/corpus/fuzz_decrypt/seed_001.oen
   ```

2. The fuzzer will automatically use files in `fuzz/corpus/fuzz_decrypt/` as starting points.

3. You can add multiple seed files with different characteristics:
   - Small files (empty or single byte)
   - Large files (multi-chunk)
   - Files with various directory structures
   - Files encrypted with different Argon2 parameters

**Fuzzing Strategy:**

The improved fuzzer uses a dual-mode approach:
- **Mode 1**: Tests raw header parsing to find edge cases in error handling
- **Mode 2**: Constructs valid headers with random data to test chunk parsing logic

This ensures coverage of both error paths and the actual decryption code paths.

**Windows Users:** If you need to run fuzzing, use WSL (Windows Subsystem for Linux) or a Linux VM. The main encryption/decryption functionality works natively on Windows.
