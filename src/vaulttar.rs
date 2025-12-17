use crate::error::Error;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

fn mtime_secs(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn archive_path(base: &Path, path: &Path) -> Result<PathBuf, Error> {
    let rel = path
        .strip_prefix(base)
        .map_err(|_| Error::InvalidArgs("path outside base"))?;
    if rel.as_os_str().is_empty() {
        return Err(Error::InvalidArgs("cannot archive base directory as entry"));
    }
    Ok(rel.to_path_buf())
}

pub fn append_vault_dir<W: io::Write>(
    builder: &mut tar::Builder<W>,
    vault_dir: &Path,
) -> Result<(), Error> {
    let meta = fs::symlink_metadata(vault_dir)?;
    if !meta.is_dir() {
        return Err(Error::InvalidArgs("vault_dir must be a directory"));
    }
    if meta.file_type().is_symlink() {
        return Err(Error::Unsupported("refusing to archive symlinked vault root"));
    }

    // Builder defaults are acceptable (no compression). We explicitly reject symlinks/special files.
    // Track file count to prevent zip-bomb style attacks
    let mut file_count = 0u64;
    walk(builder, vault_dir, vault_dir, &mut file_count)?;
    builder.finish()?;
    Ok(())
}

/// Walk directory tree during encryption.
/// Uses symlink_metadata to avoid following symlinks (security hardening).
fn walk<W: io::Write>(
    builder: &mut tar::Builder<W>,
    base: &Path,
    path: &Path,
    file_count: &mut u64,
) -> Result<(), Error> {
    const MAX_PATH_LEN: usize = 4096;
    const MAX_FILE_COUNT: u64 = 1_000_000;
    
    // Use symlink_metadata (not metadata) to avoid following symlinks
    // This is critical for security: we must not follow symlinks during encryption
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(Error::Unsupported("vault contains symlink (refused)"));
    }

    // Check path length
    let path_str = path.to_string_lossy();
    if path_str.len() > MAX_PATH_LEN {
        return Err(Error::InvalidArgs("path too long"));
    }

    if meta.is_dir() {
        if path != base {
            let rel = archive_path(base, path)?;
            let rel_str = rel.to_string_lossy();
            if rel_str.len() > MAX_PATH_LEN {
                return Err(Error::InvalidArgs("archive path too long"));
            }
            
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mtime(mtime_secs(&meta));
            // Set safe permissions: directories get 0o755, but we sanitize on extract
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // Preserve directory permissions but remove setuid/setgid bits
                let mode = meta.permissions().mode() & 0o777;
                header.set_mode(mode);
            }
            #[cfg(not(unix))]
            {
                header.set_mode(0o755);
            }
            header.set_cksum();
            builder.append_data(&mut header, &rel, io::empty())?;
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            walk(builder, base, &entry.path(), file_count)?;
        }
        return Ok(());
    }

    if meta.is_file() {
        *file_count += 1;
        if *file_count > MAX_FILE_COUNT {
            return Err(Error::InvalidArgs("too many files (zip-bomb protection)"));
        }
        let rel = archive_path(base, path)?;
        let rel_str = rel.to_string_lossy();
        if rel_str.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgs("archive path too long"));
        }
        
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(meta.len());
        header.set_mtime(mtime_secs(&meta));
        // Preserve file permissions but they'll be sanitized on extract
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Preserve permissions but remove setuid/setgid bits
            let mode = meta.permissions().mode() & 0o777;
            header.set_mode(mode);
        }
        #[cfg(not(unix))]
        {
            header.set_mode(0o644);
        }
        header.set_cksum();
        let mut f = File::open(path)?;
        builder.append_data(&mut header, &rel, &mut f)?;
        return Ok(());
    }

    Err(Error::Unsupported("vault contains unsupported file type"))
}

fn sanitize_tar_path(p: &Path) -> Result<PathBuf, Error> {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Normal(s) => out.push(s),
            Component::CurDir => return Err(Error::Format("tar path contains '.'")),
            Component::ParentDir => return Err(Error::Format("tar path contains '..'")),
            Component::RootDir | Component::Prefix(_) => {
                return Err(Error::Format("tar path is absolute"))
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err(Error::Format("tar entry has empty path"));
    }
    Ok(out)
}

/// Extract tar archive with security hardening:
/// - Path length limits (zip-bomb protection)
/// - File count limits (zip-bomb protection)
/// - Sanitized permissions (no executable bits, no owner/group preservation)
pub fn extract_to_dir<R: io::Read>(reader: R, out_dir: &Path) -> Result<(), Error> {
    const MAX_PATH_LEN: usize = 4096; // Reasonable limit (most filesystems support 4096)
    const MAX_FILE_COUNT: u64 = 1_000_000; // 1 million files max (zip-bomb protection)
    
    let mut archive = tar::Archive::new(reader);
    let mut file_count = 0u64;
    
    for entry in archive.entries()? {
        file_count += 1;
        if file_count > MAX_FILE_COUNT {
            return Err(Error::Format("too many files in archive (zip-bomb protection)"));
        }
        
        let mut entry = entry?;
        let entry_type = entry.header().entry_type();

        match entry_type {
            tar::EntryType::Directory | tar::EntryType::Regular => {}
            _ => return Err(Error::Unsupported("refusing to extract non-file/non-directory entry")),
        }

        let path = entry.path()?.into_owned();
        
        // Check path length before processing
        let path_str = path.to_string_lossy();
        if path_str.len() > MAX_PATH_LEN {
            return Err(Error::Format("path too long (zip-bomb protection)"));
        }
        
        let rel = sanitize_tar_path(&path)?;
        
        // Check sanitized path length
        let rel_str = rel.to_string_lossy();
        if rel_str.len() > MAX_PATH_LEN {
            return Err(Error::Format("sanitized path too long"));
        }
        
        let dest = out_dir.join(&rel);

        if entry_type == tar::EntryType::Directory {
            fs::create_dir_all(&dest)?;
            continue;
        }

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest)?;
        io::copy(&mut entry, &mut out)?;

        // Sanitize permissions: remove executable bits, set safe defaults
        // We don't preserve owner/group (always use current user)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Remove all executable bits (0o111 = user/group/other execute)
            // Keep only read/write for owner, read for group/others
            // This prevents malicious executables from being extracted
            let safe_mode = 0o644; // rw-r--r-- (no execute bits)
            fs::set_permissions(&dest, fs::Permissions::from_mode(safe_mode))?;
        }
    }
    Ok(())
}

