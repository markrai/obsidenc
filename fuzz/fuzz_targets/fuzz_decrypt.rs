#![no_main]
#[cfg(not(windows))]
use libfuzzer_sys::fuzz_target;
#[cfg(not(windows))]
use obsidenc::{format, aead};

#[cfg(not(windows))]
fuzz_target!(|data: &[u8]| {
    // Minimum size check (header is fixed size)
    if data.len() < format::HEADER_LEN {
        return;
    }

    // Split input: first part is header, rest is chunk data
    let (header_bytes, rest) = data.split_at(format::HEADER_LEN);
    
    // Fuzz Header Parsing - must never panic, only return Result
    if let Ok(header) = format::Header::parse(header_bytes) {
        // If header parsing succeeds, proceed to fuzz the chunk logic
        
        // Mock keys for testing parsing logic (not crypto correctness)
        // We just want to test that the *parsing* logic never panics
        let mock_key = [0u8; 32]; 
        let cipher = aead::create_cipher(&mock_key);
        
        // Fuzz Chunk Parsing
        // Try to interpret the 'rest' as chunk data
        // We are looking for panics in the loop logic or buffer handling
        let mut offset = 0;
        while offset + 4 <= rest.len() {
            // Read length (4 bytes)
            let len_bytes: [u8; 4] = match rest[offset..offset+4].try_into() {
                Ok(bytes) => bytes,
                Err(_) => break, // Bounds check failed, exit loop
            };
            let chunk_len = u32::from_le_bytes(len_bytes) as usize;
            
            offset += 4;
            
            // Check bounds to prevent manual panic, let the parser handle it
            if chunk_len == 0 {
                // Zero-length chunk marks end (sentinel)
                break;
            }
            
            if chunk_len > 10 * 1024 * 1024 {
                // Sanity check: reject chunks larger than 10MB (same as real code)
                break;
            }
            
            if offset + chunk_len > rest.len() {
                // Not enough data for this chunk
                break;
            }
            
            let chunk_data = &rest[offset..offset+chunk_len];
            
            // Attempt decrypt (will fail auth, but must not panic)
            // Use mock nonce and AAD - we're testing parsing, not crypto
            let mock_nonce = [0u8; 24];
            let mock_aad = &[];
            let _ = aead::decrypt_chunk(
                &cipher, 
                &mock_nonce,
                mock_aad,
                chunk_data
            );
            
            offset += chunk_len;
        }
    }
    // If header parsing failed, that's fine - we're testing that it fails gracefully
});

#[cfg(windows)]
fn main() {
    eprintln!("Fuzzing is not supported on Windows.");
    eprintln!("The main obsidenc binary works fine on Windows - only fuzzing is disabled.");
    eprintln!("For fuzzing, please use Linux/Unix or WSL.");
}
