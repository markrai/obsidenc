use crate::aead;
use crate::cli::{Cli, Command};
use crate::error::Error;
use crate::format::{Header, HEADER_LEN};
use crate::kdf;
use crate::securemem::MemoryLock;
use crate::vaulttar;
use rand_core::{OsRng, RngCore};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use chacha20poly1305::XChaCha20Poly1305;
use zeroize::Zeroizing;

pub fn run(cli: Cli) -> Result<(), Error> {
    match cli.command {
        Command::Encrypt {
            vault_dir,
            output_file,
            keyfile,
            force,
        } => encrypt(&vault_dir, &output_file, keyfile.as_deref(), force),
        Command::Decrypt {
            input_file,
            output_dir,
            keyfile,
            force,
        } => decrypt(&input_file, &output_dir, keyfile.as_deref(), force),
    }
}

fn open_new_file(path: &Path, force: bool) -> Result<File, Error> {
    if path.exists() && !force {
        return Err(Error::WouldOverwrite(path.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut oo = OpenOptions::new();
        oo.write(true).create(true).truncate(true).mode(0o600);
        return Ok(oo.open(path)?);
    }
    #[cfg(not(unix))]
    {
        let mut oo = OpenOptions::new();
        oo.write(true).create(true).truncate(true);
        return Ok(oo.open(path)?);
    }
}

fn prompt_password(confirm: bool) -> Result<Zeroizing<Vec<u8>>, Error> {
    let pw = rpassword::prompt_password("Password: ")
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "password input failed"))?;
    kdf::enforce_password_policy(&pw)?;
    let pw = Zeroizing::new(pw.into_bytes());
    if confirm {
        let pw2 = rpassword::prompt_password("Confirm password: ").map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "password input failed")
        })?;
        let pw2 = Zeroizing::new(pw2.into_bytes());
        if pw.as_slice() != pw2.as_slice() {
            return Err(Error::PasswordPolicy("passwords did not match"));
        }
    }
    Ok(pw)
}

fn staging_dir_for(output_dir: &Path) -> Result<PathBuf, Error> {
    let parent = output_dir
        .parent()
        .ok_or(Error::InvalidArgs("output_dir has no parent"))?;
    for _ in 0..32 {
        let mut rnd = [0u8; 8];
        OsRng.fill_bytes(&mut rnd);
        let suffix = hex8(&rnd);
        let candidate = parent.join(format!(".obsidenc-staging-{suffix}"));
        if !candidate.exists() {
            fs::create_dir_all(&candidate)?;
            return Ok(candidate);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not create staging directory",
    )
    .into())
}

fn hex8(bytes: &[u8; 8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 16];
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    String::from_utf8_lossy(&out).to_string()
}

pub fn encrypt(
    vault_dir: &Path,
    output_file: &Path,
    keyfile: Option<&Path>,
    force: bool,
) -> Result<(), Error> {
    let meta = fs::symlink_metadata(vault_dir)?;
    if !meta.is_dir() {
        return Err(Error::InvalidArgs("vault_dir must be a directory"));
    }
    if meta.file_type().is_symlink() {
        return Err(Error::Unsupported("refusing to encrypt symlinked vault root"));
    }

    let password = prompt_password(true)?;

    let keyfile_bytes = match keyfile {
        Some(p) => Some(kdf::read_keyfile(p)?),
        None => None,
    };

    let params = kdf::select_params_rfc9106_v1()?;
    let salt = kdf::random_salt();
    let base_nonce = kdf::random_nonce();

    // Derive master key from password/keyfile
    let master_key = kdf::derive_master_key(password, keyfile_bytes, &salt, params)?;
    let _master_key_lock = MemoryLock::lock(master_key.as_ref());

    // Derive subkeys from master key with domain separation
    let enc_key = kdf::derive_encryption_key(&*master_key);
    let _enc_key_lock = MemoryLock::lock(&*enc_key);
    let nonce_key = kdf::derive_nonce_key(&*master_key);
    let _nonce_key_lock = MemoryLock::lock(&*nonce_key);

    let header = Header {
        salt,
        argon2: params,
        nonce: base_nonce,
    };
    let header_bytes = header.encode_v1();
    debug_assert_eq!(header_bytes.len(), HEADER_LEN);

    // Create cipher from encryption key
    let cipher = aead::create_cipher(&*enc_key);

    // Write header
    let mut out = open_new_file(output_file, force)?;
    out.write_all(&header_bytes)?;

    // Create tar archive in memory buffer (we'll chunk it)
    let mut tar_buffer = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buffer);
        vaulttar::append_vault_dir(&mut builder, vault_dir)?;
    }

    // Encrypt in chunks
    let mut chunk_index = 0u64;
    let mut remaining = &tar_buffer[..];
    const CHUNK_SIZE: usize = aead::CHUNK_SIZE_BYTES;

    while !remaining.is_empty() {
        let chunk_plaintext_len = remaining.len().min(CHUNK_SIZE);
        let chunk_plaintext = &remaining[..chunk_plaintext_len];
        remaining = &remaining[chunk_plaintext_len..];

        let is_final = remaining.is_empty();
        let chunk_nonce = aead::derive_chunk_nonce(&*nonce_key, chunk_index);
        let aad = aead::build_chunk_aad(&header_bytes, chunk_index, is_final);

        let chunk_ciphertext = aead::encrypt_chunk(&cipher, &chunk_nonce, &aad, chunk_plaintext)?;

        // Write chunk record: [u32 len][ciphertext]
        let chunk_len = chunk_ciphertext.len() as u32;
        out.write_all(&chunk_len.to_le_bytes())?;
        out.write_all(&chunk_ciphertext)?;

        chunk_index += 1;
    }

    out.flush()?;
    Ok(())
}

pub fn decrypt(
    input_file: &Path,
    output_dir: &Path,
    keyfile: Option<&Path>,
    force: bool,
) -> Result<(), Error> {
    let meta = fs::metadata(input_file)?;
    if !meta.is_file() {
        return Err(Error::InvalidArgs("input_file must be a regular file"));
    }

    if output_dir.exists() && !force {
        return Err(Error::WouldOverwrite(output_dir.to_path_buf()));
    }

    let password = prompt_password(false)?;
    let keyfile_bytes = match keyfile {
        Some(p) => Some(kdf::read_keyfile(p)?),
        None => None,
    };

    let mut f = File::open(input_file)?;
    let mut header_buf = vec![0u8; HEADER_LEN];
    f.read_exact(&mut header_buf)?;
    let header = Header::parse_v1(&header_buf)?;

    // Derive master key from password/keyfile
    let master_key = kdf::derive_master_key(password, keyfile_bytes, &header.salt, header.argon2)?;
    let _master_key_lock = MemoryLock::lock(master_key.as_ref());

    // Derive subkeys from master key with domain separation
    let enc_key = kdf::derive_encryption_key(&*master_key);
    let _enc_key_lock = MemoryLock::lock(&*enc_key);
    let nonce_key = kdf::derive_nonce_key(&*master_key);
    let _nonce_key_lock = MemoryLock::lock(&*nonce_key);

    // Create cipher from encryption key
    let cipher = aead::create_cipher(&*enc_key);

    // Create staging directory
    let staging = staging_dir_for(output_dir)?;
    let mut staging_cleanup = StagingCleanup::new(&staging);

    // Stream decrypt chunks directly to tar extractor (auth-first, no memory accumulation)
    let decrypt_reader = StreamingDecryptReader::new(
        f,
        meta.len(),
        cipher,
        nonce_key,
        header_buf,
    )?;
    vaulttar::extract_to_dir(decrypt_reader, &staging)?;

    if output_dir.exists() {
        if force {
            safe_remove_dir_all(output_dir)?;
        } else {
            return Err(Error::WouldOverwrite(output_dir.to_path_buf()));
        }
    }
    fs::rename(&staging, output_dir)?;
    staging_cleanup.disarm();
    Ok(())
}

struct StagingCleanup {
    path: PathBuf,
    armed: bool,
}

impl StagingCleanup {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn safe_remove_dir_all(path: &Path) -> Result<(), Error> {
    // Defense-in-depth: refuse to delete obvious dangerous targets.
    if path.as_os_str().is_empty() {
        return Err(Error::InvalidArgs("refusing to delete empty path"));
    }
    if path.parent().is_none() {
        return Err(Error::InvalidArgs("refusing to delete filesystem root"));
    }
    fs::remove_dir_all(path)?;
    Ok(())
}

/// Streaming decrypt reader that decrypts chunks on-the-fly without accumulating in memory.
/// Verifies authentication for each chunk before providing plaintext (auth-first semantics).
struct StreamingDecryptReader {
    file: File,
    file_len: u64,
    cipher: XChaCha20Poly1305,
    nonce_key: Zeroizing<[u8; 32]>,
    header_bytes: Vec<u8>,
    chunk_index: u64,
    current_chunk: Vec<u8>,
    current_pos: usize,
    eof: bool,
}

impl StreamingDecryptReader {
    fn new(
        file: File,
        file_len: u64,
        cipher: XChaCha20Poly1305,
        nonce_key: Zeroizing<[u8; 32]>,
        header_bytes: Vec<u8>,
    ) -> Result<Self, Error> {
        let mut reader = Self {
            file,
            file_len,
            cipher,
            nonce_key,
            header_bytes,
            chunk_index: 0,
            current_chunk: Vec::new(),
            current_pos: 0,
            eof: false,
        };
        // Load first chunk
        reader.load_next_chunk()?;
        Ok(reader)
    }

    fn load_next_chunk(&mut self) -> Result<(), Error> {
        if self.eof {
            return Ok(());
        }

        // Read chunk length
        let mut len_bytes = [0u8; 4];
        match self.file.read_exact(&mut len_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // End of file - check if we got at least one chunk
                if self.chunk_index == 0 {
                    return Err(Error::Format("empty container"));
                }
                self.eof = true;
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }

        let chunk_ciphertext_len = u32::from_le_bytes(len_bytes) as usize;
        if chunk_ciphertext_len == 0 {
            return Err(Error::Format("zero-length chunk"));
        }
        if chunk_ciphertext_len > 10 * 1024 * 1024 {
            // Sanity check: reject chunks larger than 10MB
            return Err(Error::Format("chunk too large"));
        }

        // Determine if this is the final chunk by checking file position after reading
        let pos_before_read = self.file.stream_position()?;
        let pos_after_read = pos_before_read + chunk_ciphertext_len as u64;
        let is_final = pos_after_read >= self.file_len;

        // Read chunk ciphertext
        let mut chunk_ciphertext = vec![0u8; chunk_ciphertext_len];
        self.file.read_exact(&mut chunk_ciphertext)?;

        let chunk_nonce = aead::derive_chunk_nonce(&*self.nonce_key, self.chunk_index);
        let aad = aead::build_chunk_aad(&self.header_bytes, self.chunk_index, is_final);

        // Decrypt chunk (this verifies authentication)
        // If is_final was wrong, try the other value
        let chunk_plaintext = match aead::decrypt_chunk(&self.cipher, &chunk_nonce, &aad, &chunk_ciphertext) {
            Ok(pt) => pt,
            Err(_) if !is_final => {
                // Try with is_final=true in case we misdetected
                let aad_final = aead::build_chunk_aad(&self.header_bytes, self.chunk_index, true);
                aead::decrypt_chunk(&self.cipher, &chunk_nonce, &aad_final, &chunk_ciphertext)?
            }
            Err(e) => {
                // Authentication failed - abort immediately
                return Err(e);
            }
        };

        self.current_chunk = chunk_plaintext;
        self.current_pos = 0;
        self.chunk_index += 1;

        if is_final {
            self.eof = true;
        }

        Ok(())
    }
}

impl Read for StreamingDecryptReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut total_read = 0;

        loop {
            // If current chunk is exhausted, load next
            if self.current_pos >= self.current_chunk.len() {
                if self.eof {
                    return Ok(total_read);
                }
                self.load_next_chunk()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{}", e)))?;
                if self.eof && self.current_chunk.is_empty() {
                    return Ok(total_read);
                }
            }

            // Copy from current chunk
            let available = self.current_chunk.len() - self.current_pos;
            let to_copy = available.min(buf.len() - total_read);
            buf[total_read..total_read + to_copy]
                .copy_from_slice(&self.current_chunk[self.current_pos..self.current_pos + to_copy]);
            self.current_pos += to_copy;
            total_read += to_copy;

            if total_read >= buf.len() {
                return Ok(total_read);
            }

            // If we've exhausted this chunk and there are no more, we're done
            if self.eof && self.current_pos >= self.current_chunk.len() {
                return Ok(total_read);
            }
        }
    }
}
