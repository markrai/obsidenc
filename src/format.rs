use crate::error::Error;
use subtle::ConstantTimeEq;

pub const MAGIC: [u8; 8] = *b"OBSIDENC";
pub const VERSION: u8 = 2;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;

pub const ARGON_PARAMS_LEN: usize = 16;
// Verification token for early password validation
pub const VERIFICATION_TOKEN_PLAINTEXT: &[u8] = b"OBSIDENC_VERIFY";
pub const VERIFICATION_TOKEN_LEN: usize = 16; // XChaCha20-Poly1305 ciphertext size for 14-byte plaintext
pub const HEADER_LEN: usize = 8 + 1 + SALT_LEN + ARGON_PARAMS_LEN + NONCE_LEN + VERIFICATION_TOKEN_LEN;

// Argon2 variant identifiers (for documentation and future extensibility)
#[allow(dead_code)]
pub const ARGON2_VARIANT_D: u8 = 0;
#[allow(dead_code)]
pub const ARGON2_VARIANT_I: u8 = 1;
pub const ARGON2_VARIANT_ID: u8 = 2;

// Argon2 version identifiers
pub const ARGON2_VERSION_13: u8 = 0x13; // v1.3

// KDF domain version (for future extensibility)
pub const KDF_DOMAIN_VERSION_V1: u8 = 1;

/// Argon2Params encoding (16 bytes, little-endian):
///
/// Byte layout:
///   [0]     kdf_domain_version: u8 (KDF domain version, currently 1)
///   [1]     argon2_variant: u8 (0=Argon2d, 1=Argon2i, 2=Argon2id)
///   [2]     argon2_version: u8 (0x13 = Argon2 v1.3)
///   [3]     reserved: u8 (must be 0, reserved for future use)
///   [4-7]   memory_kib: u32 LE (memory cost in KiB, m_cost)
///   [8-11]  iterations: u32 LE (time cost, t_cost)
///   [12-15] parallelism: u32 LE (parallelism, p_cost)
#[derive(Clone, Copy, Debug)]
pub struct Argon2Params {
    pub kdf_domain_version: u8,
    pub argon2_variant: u8,
    pub argon2_version: u8,
    /// Reserved byte, must be 0. Reserved for future use.
    pub _reserved: u8,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Argon2Params {
    /// Encode parameters to 16-byte array (little-endian).
    pub fn encode(self) -> [u8; ARGON_PARAMS_LEN] {
        let mut out = [0u8; ARGON_PARAMS_LEN];
        out[0] = self.kdf_domain_version;
        out[1] = self.argon2_variant;
        out[2] = self.argon2_version;
        out[3] = 0; // reserved, must be 0
        out[4..8].copy_from_slice(&self.memory_kib.to_le_bytes());
        out[8..12].copy_from_slice(&self.iterations.to_le_bytes());
        out[12..16].copy_from_slice(&self.parallelism.to_le_bytes());
        out
    }

    /// Decode parameters from 16-byte array (little-endian).
    pub fn decode(bytes: &[u8; ARGON_PARAMS_LEN]) -> Self {
        let kdf_domain_version = bytes[0];
        let argon2_variant = bytes[1];
        let argon2_version = bytes[2];
        let reserved = bytes[3];
        let memory_kib = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let iterations = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let parallelism = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        Self {
            kdf_domain_version,
            argon2_variant,
            argon2_version,
            _reserved: reserved,
            memory_kib,
            iterations,
            parallelism,
        }
    }

    pub fn validate_for_v1(&self) -> Result<(), Error> {
        // Validate KDF domain version
        if self.kdf_domain_version != KDF_DOMAIN_VERSION_V1 {
            return Err(Error::Format("unsupported KDF domain version"));
        }

        // Validate Argon2 variant (only Argon2id is supported)
        if self.argon2_variant != ARGON2_VARIANT_ID {
            return Err(Error::Format("unsupported Argon2 variant (only Argon2id supported)"));
        }

        // Validate Argon2 version
        if self.argon2_version != ARGON2_VERSION_13 {
            return Err(Error::Format("unsupported Argon2 version (only v1.3 supported)"));
        }

        // Validate reserved byte (must be 0)
        if self._reserved != 0 {
            return Err(Error::Format("invalid reserved byte (must be 0)"));
        }

        // Validate memory cost (m_cost)
        let min_kib = 512_u32
            .checked_mul(1024)
            .ok_or(Error::Format("argon2 memory overflow"))?;
        let max_kib = 2_u32
            .checked_mul(1024)
            .and_then(|mib| mib.checked_mul(1024))
            .ok_or(Error::Format("argon2 memory overflow"))?;
        if self.memory_kib < min_kib {
            return Err(Error::Format("argon2 memory too low (minimum 512 MiB)"));
        }
        if self.memory_kib > max_kib {
            return Err(Error::Format("argon2 memory too high (maximum 2 GiB)"));
        }

        // Validate time cost (t_cost)
        if !(1..=4).contains(&self.iterations) {
            return Err(Error::Format("unsupported argon2 iterations (must be 1-4)"));
        }

        // Validate parallelism (p_cost)
        if !(1..=4).contains(&self.parallelism) {
            return Err(Error::Format("unsupported argon2 parallelism (must be 1-4)"));
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Header {
    pub salt: [u8; SALT_LEN],
    pub argon2: Argon2Params,
    pub nonce: [u8; NONCE_LEN],
    /// Encrypted verification token for early password validation
    pub verification_token: [u8; VERIFICATION_TOKEN_LEN],
}

impl Header {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.argon2.encode());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.verification_token);
        out
    }

    pub fn parse(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() != HEADER_LEN {
            return Err(Error::Format("malformed header length"));
        }
        let magic = &buf[0..8];
        if magic.ct_eq(&MAGIC).unwrap_u8() != 1 {
            return Err(Error::Format("bad magic bytes"));
        }
        let version = buf[8];
        if version != VERSION {
            return Err(Error::Format("unknown container version"));
        }

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&buf[9..9 + SALT_LEN]);

        let mut params_bytes = [0u8; ARGON_PARAMS_LEN];
        params_bytes.copy_from_slice(&buf[9 + SALT_LEN..9 + SALT_LEN + ARGON_PARAMS_LEN]);
        let argon2 = Argon2Params::decode(&params_bytes);
        argon2.validate_for_v1()?;

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(
            &buf[9 + SALT_LEN + ARGON_PARAMS_LEN..9 + SALT_LEN + ARGON_PARAMS_LEN + NONCE_LEN],
        );

        let mut verification_token = [0u8; VERIFICATION_TOKEN_LEN];
        verification_token.copy_from_slice(
            &buf[9 + SALT_LEN + ARGON_PARAMS_LEN + NONCE_LEN
                ..9 + SALT_LEN + ARGON_PARAMS_LEN + NONCE_LEN + VERIFICATION_TOKEN_LEN],
        );

        Ok(Self {
            salt,
            argon2,
            nonce,
            verification_token,
        })
    }
}
