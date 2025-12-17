use crate::error::Error;
use crate::format::Argon2Params;
use crate::securemem::MemoryLock;
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use sysinfo::System;
use zeroize::Zeroizing;

pub const MIN_PASSWORD_CHARS: usize = 20;
pub const SALT_LEN: usize = crate::format::SALT_LEN;

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn random_nonce() -> [u8; crate::format::NONCE_LEN] {
    let mut nonce = [0u8; crate::format::NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// RFC 9106-style adaptive parameters for desktop/server-class machines.
///
/// Selects memory and iterations to maintain security while targeting reasonable runtime.
///
/// **Memory Selection:**
/// Uses ~85% of available memory (leaving 15% headroom for system), with:
/// - Minimum: 512 MiB (hard floor)
/// - Maximum: 2 GiB (RFC 9106 target)
///
/// This replaces the arbitrary 256 MiB reserve with a percentage-based approach that
/// scales with available memory, ensuring we use available resources efficiently.
///
/// **Iteration Selection (Adaptive):**
/// - If memory >= 2 GiB: t=1 (RFC 9106 guidance)
/// - If memory < 2 GiB: increases iterations to maintain cost (memory * iterations)
///
/// This ensures that when memory is constrained, we maintain security by increasing
/// iterations, making ASIC/GPU attacks more expensive. The cost target is 2 GiB
/// (i.e., 2 GiB * 1 iteration), so:
/// - 1 GiB → t=2 (cost = 2 GiB)
/// - 512 MiB → t=4 (cost = 2 GiB)
///
/// Iterations are capped at 4 to avoid excessive runtime on low-memory systems.
pub fn select_params_rfc9106_v1() -> Result<Argon2Params, Error> {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let parallelism = cores.min(4).max(1) as u32;

    let mut system = System::new();
    system.refresh_memory();
    let available_bytes = system.available_memory();

    const TARGET_BYTES: u64 = 2_u64 * 1024 * 1024 * 1024; // 2 GiB
    const MIN_BYTES: u64 = 512_u64 * 1024 * 1024; // 512 MiB
    const MEMORY_USAGE_RATIO: f64 = 0.85; // Use 85% of available memory

    // Select memory: use 85% of available, capped at 2 GiB, floored at 512 MiB
    let chosen_bytes = {
        let candidate = (available_bytes as f64 * MEMORY_USAGE_RATIO) as u64;
        candidate.min(TARGET_BYTES).max(MIN_BYTES)
    };

    if available_bytes < MIN_BYTES {
        return Err(Error::Unsupported(
            "insufficient memory for Argon2id (need >= 512 MiB free)",
        ));
    }

    let mut memory_kib: u32 = (chosen_bytes / 1024)
        .try_into()
        .map_err(|_| Error::Format("argon2 memory overflow"))?;

    // Argon2 memory is measured in 1 KiB blocks. The algorithm divides memory into `p` lanes and
    // 4 slices per pass; enforce `m % (4*p) == 0` to avoid implementation-defined behavior.
    let lanes = parallelism;
    let align = lanes
        .checked_mul(4)
        .ok_or(Error::Format("argon2 lane arithmetic overflow"))?;
    if align != 0 {
        memory_kib -= memory_kib % align;
    }

    // Maintain the mandatory minimum even after alignment.
    let min_kib: u32 = (MIN_BYTES / 1024)
        .try_into()
        .map_err(|_| Error::Format("argon2 memory overflow"))?;
    if memory_kib < min_kib {
        memory_kib = min_kib;
        if align != 0 {
            let rem = memory_kib % align;
            if rem != 0 {
                memory_kib = memory_kib
                    .checked_add(align - rem)
                    .ok_or(Error::Format("argon2 memory overflow"))?;
            }
        }
    }

    // Adaptive iterations: maintain security when memory is constrained
    // RFC 9106 guidance: 2 GiB with t=1 is the reference point
    // Cost = memory * iterations; we aim to maintain cost >= 2 GiB
    let iterations = if memory_kib as u64 >= (TARGET_BYTES / 1024) {
        // Memory >= 2 GiB: use RFC 9106 guidance (t=1)
        1
    } else {
        // Memory < 2 GiB: increase iterations to maintain cost
        // Target cost: 2 GiB = 2^21 KiB
        // iterations = ceil(2^21 / memory_kib)
        let target_cost_kib = TARGET_BYTES / 1024;
        let computed_iterations = (target_cost_kib + memory_kib as u64 - 1) / memory_kib as u64;
        // Cap at 4 iterations to avoid excessive runtime
        computed_iterations.min(4).max(2) as u32
    };

    let params = Argon2Params {
        kdf_domain_version: crate::format::KDF_DOMAIN_VERSION_V1,
        argon2_variant: crate::format::ARGON2_VARIANT_ID,
        argon2_version: crate::format::ARGON2_VERSION_13,
        _reserved: 0, // Reserved byte, must be 0
        memory_kib,
        iterations,
        parallelism,
    };
    params.validate_for_v1()?;
    Ok(params)
}

pub fn enforce_password_policy(password: &str) -> Result<(), Error> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(Error::PasswordPolicy(
            "minimum length is 20 characters",
        ));
    }
    Ok(())
}

/// Read keyfile with security hardening:
/// - Size cap: 4 MiB maximum
/// - Permission check: fails if world-readable on Unix
/// - Raw bytes: no trimming or processing
pub fn read_keyfile(path: &std::path::Path) -> Result<Zeroizing<Vec<u8>>, Error> {
    const MAX_KEYFILE_BYTES: u64 = 4 * 1024 * 1024; // 4 MiB cap
    
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Err(Error::InvalidArgs("keyfile must be a regular file"));
    }
    
    // Size cap: reject overly large keyfiles
    if meta.len() > MAX_KEYFILE_BYTES {
        return Err(Error::KeyfileTooLarge);
    }
    
    // Permission check on Unix: fail if world-readable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = meta.permissions();
        let mode = perms.mode();
        // Check if world-readable (others have read permission)
        // Octal: 0o004 = others read, 0o002 = others write, 0o001 = others execute
        if (mode & 0o004) != 0 {
            return Err(Error::InvalidArgs(
                "keyfile is world-readable (security risk: use chmod 600)",
            ));
        }
    }
    
    // Read raw bytes: no trimming, no processing
    // std::fs::read reads the entire file as-is, including any trailing newlines
    let bytes = std::fs::read(path)?;
    Ok(Zeroizing::new(bytes))
}

fn build_kdf_input(password: &[u8], keyfile: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>, Error> {
    // Domain separation avoids ambiguity and makes the keyfile mixing explicit.
    const PREFIX: &[u8] = b"obsidenc\0kdf\0v1\0";

    let password_len: u32 = password
        .len()
        .try_into()
        .map_err(|_| Error::InvalidArgs("password too long"))?;
    let keyfile_len: u32 = keyfile
        .map(|k| k.len())
        .unwrap_or(0)
        .try_into()
        .map_err(|_| Error::KeyfileTooLarge)?;

    let mut ikm = Vec::with_capacity(
        PREFIX.len()
            + 4
            + password_len as usize
            + 4
            + keyfile.map(|k| k.len()).unwrap_or(0),
    );
    ikm.extend_from_slice(PREFIX);
    ikm.extend_from_slice(&password_len.to_le_bytes());
    ikm.extend_from_slice(password);
    ikm.extend_from_slice(&keyfile_len.to_le_bytes());
    if let Some(k) = keyfile {
        ikm.extend_from_slice(k);
    }
    Ok(Zeroizing::new(ikm))
}

/// Derive master key from password/keyfile using Argon2id.
/// This is the root key from which all subkeys are derived.
pub fn derive_master_key(
    password: Zeroizing<Vec<u8>>,
    keyfile: Option<Zeroizing<Vec<u8>>>,
    salt: &[u8; SALT_LEN],
    params: Argon2Params,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let password = MemoryLock::new(password);
    let keyfile = keyfile.map(MemoryLock::new);
    // Use the locked data via Deref - password and keyfile are now MemoryLock guards
    let ikm = build_kdf_input(password.as_ref(), keyfile.as_ref().map(|k| k.as_ref()))?;
    let ikm = MemoryLock::new(ikm);

    // Validate variant matches what we're using
    if params.argon2_variant != crate::format::ARGON2_VARIANT_ID {
        return Err(Error::Format("unsupported Argon2 variant"));
    }
    if params.argon2_version != crate::format::ARGON2_VERSION_13 {
        return Err(Error::Format("unsupported Argon2 version"));
    }

    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|_| Error::Crypto)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = MemoryLock::new(Zeroizing::new([0u8; 32]));
    // Use the locked ikm via Deref
    argon2
        .hash_password_into(ikm.as_ref(), salt, out.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(out.clone())
}

/// Key derivation hierarchy:
///
/// master_key = Argon2id(password, keyfile, salt, params)
///   ↓
/// enc_key = HKDF(master_key, "obsidenc\0enc")
/// nonce_key = HKDF(master_key, "obsidenc\0nonce")
/// (future: header_key, chunk_nonce_key, etc.)
///
/// This prevents key reuse and makes future extensions safer.

/// Derive encryption key from master key using HKDF with domain separation.
/// Domain: "obsidenc\0enc"
const ENC_KEY_INFO: &[u8] = b"obsidenc\0enc";

pub fn derive_encryption_key(master_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(ENC_KEY_INFO, &mut *okm)
        .map_err(|_| Error::Crypto)?;
    Ok(okm)
}

/// Derive nonce key from master key using HKDF with domain separation.
/// Domain: "obsidenc\0nonce"
/// This key is used to derive per-chunk nonces.
const NONCE_KEY_INFO: &[u8] = b"obsidenc\0nonce";

pub fn derive_nonce_key(master_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(NONCE_KEY_INFO, &mut *okm)
        .map_err(|_| Error::Crypto)?;
    Ok(okm)
}

