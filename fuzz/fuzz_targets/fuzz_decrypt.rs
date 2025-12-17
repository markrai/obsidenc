#![no_main]
#[cfg(not(windows))]
use libfuzzer_sys::fuzz_target;
#[cfg(not(windows))]
use obsidenc::{format, aead};

#[cfg(not(windows))]
fuzz_target!(|data: &[u8]| {
    // Strategy: We fuzz in two modes to maximize coverage:
    // 1. If data is large enough, construct a valid header and fuzz chunk parsing
    // 2. Always test header parsing with raw data to find edge cases
    
    // Mode 1: Test header parsing with raw data (tests error handling)
    // This ensures we find panics in the header parser itself
    if data.len() >= format::HEADER_LEN {
        let (header_bytes, _) = data.split_at(format::HEADER_LEN);
        // This should never panic, only return Result
        let _ = format::Header::parse(header_bytes);
    }
    
    // Mode 2: Construct valid header and fuzz chunk parsing (tests decryption logic)
    // This is where we get real coverage of the chunk parsing code
    if data.len() >= format::HEADER_LEN + 4 {
        // Construct a valid header with random but valid data
        let mut header_bytes = vec![0u8; format::HEADER_LEN];
        
        // Set magic bytes (required for parsing to succeed)
        header_bytes[0..8].copy_from_slice(b"OBSIDENC");
        
        // Set version (required: must be 2)
        header_bytes[8] = format::VERSION;
        
        // Use random data from input for salt (bytes 9-24)
        let salt_start = 9;
        let salt_end = salt_start + format::SALT_LEN;
        if data.len() >= salt_end {
            header_bytes[salt_start..salt_end].copy_from_slice(&data[0..format::SALT_LEN]);
        } else {
            // Not enough data, fill with zeros
            header_bytes[salt_start..salt_end].fill(0);
        }
        
        // Set valid Argon2 parameters (required for validation to pass)
        // Position: after salt (byte 25)
        let params_start = salt_end;
        let params_end = params_start + format::ARGON_PARAMS_LEN;
        
        // KDF domain version (must be 1)
        header_bytes[params_start] = format::KDF_DOMAIN_VERSION_V1;
        // Argon2 variant (must be 2 = Argon2id)
        header_bytes[params_start + 1] = format::ARGON2_VARIANT_ID;
        // Argon2 version (must be 0x13 = v1.3)
        header_bytes[params_start + 2] = format::ARGON2_VERSION_13;
        // Reserved byte (must be 0)
        header_bytes[params_start + 3] = 0;
        
        // Memory cost: use random but valid value (512 MiB to 2 GiB)
        // We'll use a safe value: 1 GiB = 1024 * 1024 KiB
        let memory_kib = 1024u32 * 1024;
        header_bytes[params_start + 4..params_start + 8].copy_from_slice(&memory_kib.to_le_bytes());
        
        // Iterations: valid range is 1-4, use 1 (safe minimum)
        header_bytes[params_start + 8..params_start + 12].copy_from_slice(&1u32.to_le_bytes());
        
        // Parallelism: valid range is 1-4, use 1 (safe minimum)
        header_bytes[params_start + 12..params_end].copy_from_slice(&1u32.to_le_bytes());
        
        // Nonce (bytes after params)
        let nonce_start = params_end;
        let nonce_end = nonce_start + format::NONCE_LEN;
        if data.len() >= nonce_end {
            header_bytes[nonce_start..nonce_end].copy_from_slice(&data[format::SALT_LEN..format::SALT_LEN + format::NONCE_LEN]);
        } else {
            header_bytes[nonce_start..nonce_end].fill(0);
        }
        
        // Verification token (last 16 bytes)
        let token_start = nonce_end;
        let token_end = token_start + format::VERIFICATION_TOKEN_LEN;
        if data.len() >= token_end {
            let src_start = format::SALT_LEN + format::NONCE_LEN;
            let src_end = src_start + format::VERIFICATION_TOKEN_LEN;
            if data.len() >= src_end {
                header_bytes[token_start..token_end].copy_from_slice(&data[src_start..src_end]);
            } else {
                header_bytes[token_start..token_end].fill(0);
            }
        } else {
            header_bytes[token_start..token_end].fill(0);
        }
        
        // Now parse the constructed header (should succeed)
        if let Ok(header) = format::Header::parse(&header_bytes) {
            // Use the header to test chunk parsing logic
            // This ensures we actually exercise the decryption code paths
            
            // Mock keys for testing parsing logic (not crypto correctness)
            let mock_key = [0u8; 32];
            let cipher = aead::create_cipher(&mock_key);
            let mock_nonce_key = [0u8; 32];
            
            // Get chunk data (everything after header)
            let chunk_data = if data.len() > format::HEADER_LEN {
                &data[format::HEADER_LEN..]
            } else {
                return; // Not enough data for chunks
            };
            
            // Fuzz Chunk Parsing - this is the critical path we want to test
            let mut offset = 0;
            let mut chunk_index = 0u64;
            
            while offset + 4 <= chunk_data.len() {
                // Read length (4 bytes, little-endian)
                let len_bytes: [u8; 4] = match chunk_data[offset..offset+4].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => break, // Bounds check failed, exit loop
                };
                let chunk_ciphertext_len = u32::from_le_bytes(len_bytes) as usize;
                
                offset += 4;
                
                // Zero-length chunk marks end (sentinel)
                if chunk_ciphertext_len == 0 {
                    break;
                }
                
                // Sanity check: reject chunks larger than 10MB (same as real code)
                if chunk_ciphertext_len > 10 * 1024 * 1024 {
                    break;
                }
                
                // Check if we have enough data for this chunk
                if offset + chunk_ciphertext_len > chunk_data.len() {
                    break;
                }
                
                let chunk_ciphertext = &chunk_data[offset..offset + chunk_ciphertext_len];
                
                // Derive chunk nonce using the same logic as real code
                // This tests the nonce derivation path
                if let Ok(chunk_nonce) = aead::derive_chunk_nonce(&mock_nonce_key, chunk_index) {
                    // Build AAD using the same logic as real code
                    // Try both is_final=false and is_final=true to test both paths
                    let aad_false = aead::build_chunk_aad(&header_bytes, chunk_index, false);
                    let aad_true = aead::build_chunk_aad(&header_bytes, chunk_index, true);
                    
                    // Attempt decrypt with both AAD values (will fail auth, but must not panic)
                    // This tests the actual decryption parsing logic
                    let _ = aead::decrypt_chunk(&cipher, &chunk_nonce, &aad_false, chunk_ciphertext);
                    let _ = aead::decrypt_chunk(&cipher, &chunk_nonce, &aad_true, chunk_ciphertext);
                }
                
                offset += chunk_ciphertext_len;
                chunk_index += 1;
                
                // Limit number of chunks to prevent excessive processing
                if chunk_index > 1000 {
                    break;
                }
            }
        }
    }
});

#[cfg(windows)]
fn main() {
    eprintln!("Fuzzing is not supported on Windows.");
    eprintln!("The main obsidenc binary works fine on Windows - only fuzzing is disabled.");
    eprintln!("For fuzzing, please use Linux/Unix or WSL.");
}
