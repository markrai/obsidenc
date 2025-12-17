use crate::error::Error;
use crate::format::NONCE_LEN;
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks

/// Derive a chunk nonce from the nonce key and chunk index.
pub fn derive_chunk_nonce(nonce_key: &[u8; 32], chunk_index: u64) -> [u8; NONCE_LEN] {
    let hk = Hkdf::<Sha256>::new(None, nonce_key);
    let mut info = Vec::with_capacity(24);
    info.extend_from_slice(&chunk_index.to_le_bytes());
    info.extend_from_slice(&[0u8; 16]); // 16 zero bytes to pad to 24
    let mut nonce = [0u8; NONCE_LEN];
    hk.expand(&info, &mut nonce).expect("HKDF expansion failed");
    nonce
}

/// Build AAD for a chunk: header_bytes || chunk_index || is_final
pub fn build_chunk_aad(header_bytes: &[u8], chunk_index: u64, is_final: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header_bytes.len() + 9);
    aad.extend_from_slice(header_bytes);
    aad.extend_from_slice(&chunk_index.to_le_bytes());
    aad.push(if is_final { 1 } else { 0 });
    aad
}

/// Encrypt a plaintext chunk and return ciphertext with tag.
pub fn encrypt_chunk(
    cipher: &XChaCha20Poly1305,
    chunk_nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let nonce = XNonce::from_slice(chunk_nonce);
    let mut buffer = plaintext.to_vec();
    cipher
        .encrypt_in_place(nonce, aad, &mut buffer)
        .map_err(|_| Error::Crypto)?;
    Ok(buffer)
}

/// Decrypt a ciphertext chunk and return plaintext.
pub fn decrypt_chunk(
    cipher: &XChaCha20Poly1305,
    chunk_nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let nonce = XNonce::from_slice(chunk_nonce);
    let mut buffer = ciphertext.to_vec();
    cipher
        .decrypt_in_place(nonce, aad, &mut buffer)
        .map_err(|_| Error::AuthenticationFailed)?;
    Ok(buffer)
}

/// Create an XChaCha20Poly1305 cipher from a 32-byte key.
pub fn create_cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.into())
}

pub const CHUNK_SIZE_BYTES: usize = CHUNK_SIZE;
