# obsidenc: Encryption Utility Analysis

## Overview

**obsidenc** is a high-security, paranoid-grade encryption utility written in Rust that encrypts entire directory structures into single encrypted archive files. It prioritizes security, defensive programming, and resistance to offline attacks over convenience.

## Core Specifications

### Encryption Algorithm
- **Cipher**: XChaCha20-Poly1305 (AEAD authenticated encryption)
- **Key Derivation**: Argon2id (RFC 9106 compliant)
- **Chunking**: 64KB chunks with per-chunk authentication
- **Archive Format**: Uncompressed TAR archive (no compression to avoid side-channel leaks)

### Key Derivation Function (KDF)

**Argon2id Configuration:**
- **Variant**: Argon2id (hybrid resistance to time-memory trade-offs)
- **Version**: Argon2 v1.3
- **Memory Cost**: Adaptive, 85% of available system memory
  - Minimum: 512 MiB (hard floor)
  - Maximum: 2 GiB (RFC 9106 target)
- **Time Cost (Iterations)**: Adaptive based on available memory
  - 2+ GiB memory: 1 iteration (RFC 9106 guidance)
  - < 2 GiB memory: 2-4 iterations (maintains security cost target)
- **Parallelism**: Up to 4 threads (capped at available CPU cores)

**Key Hierarchy:**
- Master key derived from password + optional keyfile via Argon2id
- Encryption key derived via HKDF-SHA256 with domain separation
- Nonce key derived via HKDF-SHA256 for per-chunk nonce generation
- All keys use zeroize for secure memory management

### Security Features

**Memory Protection:**
- Memory locking (mlock/VirtualLock) to prevent swapping of sensitive data
- MemoryLock struct owns locked data to guarantee lifetime safety (prevents use-after-free)
- Zeroize crate for automatic secure memory clearing
- Memory locks applied to passwords, keyfiles, master keys, and derived keys

**Password Policy:**
- Minimum password length: 20 characters
- Password confirmation required during encryption
- Optional keyfile support (up to 4 MiB, permission checks on Unix)

**Authentication:**
- Per-chunk authentication tags (Poly1305)
- Additional authenticated data (AAD) includes header, chunk index, and final chunk flag
- Auth-first decryption (verification before plaintext exposure)

**File Format Security:**
- Magic bytes: "OBSIDENC"
- Versioned format (currently v1)
- Defensive parsing with strict validation
- Constant-time comparison for magic bytes

### Threat Model

**Assumed Attack Scenarios:**
- Attacker has full access to encrypted file
- Attacker has unlimited offline time
- Attacker does NOT have runtime access during encryption/decryption

**Security Guarantees:**
- Confidentiality: XChaCha20-Poly1305 provides IND-CCA2 security
- Integrity: Poly1305 authentication tags prevent tampering
- Key derivation: Argon2id provides resistance to GPU/ASIC attacks
- Forward secrecy: Each encryption uses unique salt and nonce

### Operational Security

**Encryption Process:**
- Streams TAR archive directly to encryption writer (uses small fixed 64KB buffer for chunking, no full archive buffering)
- Encrypts in 64KB chunks with unique nonces as data is written
- Writes header (magic, version, salt, Argon2 params, base nonce)
- Writes chunk records: [u32 length][ciphertext+tag]

**Decryption Process:**
- Streaming decryption (no full archive accumulation in memory)
- Staging directory with atomic rename on success
- Automatic cleanup on failure
- Refuses to overwrite existing directories unless `--force` flag used

**Archive Handling:**
- Rejects symlinks (security hardening)
- Path length limits (4096 characters, zip-bomb protection)
- File count limits (1 million files, zip-bomb protection)
- Permission sanitization on extract (removes executable bits, setuid/setgid)
- Safe path sanitization (strips leading "./", rejects ".." and absolute paths for security)
- Metadata scrubbing on archive creation (removes timestamps, ownership, device IDs to prevent privacy leaks)

### Platform Support

- **Unix/Linux**: Full support with mlock, permission checks
- **Windows**: Full support with VirtualLock
- **File Permissions**: 
  - Unix: Creates files with 0o600 (encrypted files), extracts with 0o644
  - Windows: Standard file permissions

### Build Configuration

**Release Optimizations:**
- Link-time optimization (LTO)
- Single codegen unit
- Panic = unwind (default) - ensures Drop implementations run to clean up secrets on panic
- Symbol stripping enabled

**Dependencies:**
- RustCrypto primitives (chacha20poly1305, hkdf, sha2)
- Argon2 (RFC 9106 compliant)
- Zeroize (secure memory clearing)
- Subtle (constant-time operations)

### Code Quality

**Defensive Programming:**
- Extensive input validation
- Bounds checking
- Error handling with custom error types (all library functions return Result, no panics)
- No unsafe code except for OS memory locking APIs
- Defensive parsing with format validation

**Security Best Practices:**
- Domain separation for key derivation
- Constant-time operations where needed
- Secure memory management throughout
- No compression (avoids side-channel attacks)
- Auth-first decryption semantics

## Use Cases

- Long-term archival encryption
- Secure backup storage
- Sensitive data protection
- Compliance with high-security requirements
- Protection against offline brute-force attacks

## Limitations

- No compression (by design, for security)
- No incremental updates (full re-encryption required)
- Requires significant memory (minimum 512 MiB free)
- Slower than convenience-focused tools (security-first design)
- No key rotation or update mechanisms

## Summary

obsidenc is a production-grade encryption utility that prioritizes security over convenience. It implements modern cryptographic best practices, defensive programming techniques, and resistance to sophisticated attack scenarios. The adaptive Argon2id parameters ensure strong security across different hardware configurations while maintaining reasonable performance. The streaming architecture and memory protection features minimize plaintext exposure windows, making it suitable for high-security use cases where data protection is paramount.


