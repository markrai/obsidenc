use crate::error::Error;
use zeroize::Zeroize;

/// Best-effort memory locking for secrets.
///
/// This reduces exposure to swapping on supported OSes, but it is not a complete mitigation:
/// - Small buffers share pages with other allocations.
/// - Locking may fail due to OS limits; failure is non-fatal.
///
/// This struct owns the data it locks to guarantee lifetime safety.
pub struct MemoryLock {
    data: Vec<u8>,
    locked: bool,
}

impl MemoryLock {
    /// Lock a slice of bytes. The data is cloned into the MemoryLock.
    pub fn lock(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self {
                data: Vec::new(),
                locked: false,
            };
        }
        let data = bytes.to_vec();
        let locked = unsafe {
            lock_region(data.as_ptr(), data.len())
        }.is_ok();
        Self { data, locked }
    }
}

impl Drop for MemoryLock {
    fn drop(&mut self) {
        if self.locked && !self.data.is_empty() {
            let _ = unsafe { unlock_region(self.data.as_ptr(), self.data.len()) };
        }
        // Zeroize the data before dropping
        self.data.zeroize();
    }
}

unsafe fn lock_region(ptr: *const u8, len: usize) -> Result<(), Error> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Memory::VirtualLock;
        let ok = VirtualLock(ptr as *const core::ffi::c_void, len);
        if ok == 0 {
            return Err(Error::Unsupported("memory locking unavailable"));
        }
        return Ok(());
    }
    #[cfg(unix)]
    {
        let rc = libc::mlock(ptr as *const core::ffi::c_void, len);
        if rc != 0 {
            return Err(Error::Unsupported("memory locking unavailable"));
        }
        return Ok(());
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = ptr;
        let _ = len;
        Err(Error::Unsupported("memory locking unsupported on this platform"))
    }
}

unsafe fn unlock_region(ptr: *const u8, len: usize) -> Result<(), Error> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Memory::VirtualUnlock;
        let ok = VirtualUnlock(ptr as *const core::ffi::c_void, len);
        if ok == 0 {
            return Err(Error::Unsupported("memory unlocking unavailable"));
        }
        return Ok(());
    }
    #[cfg(unix)]
    {
        let rc = libc::munlock(ptr as *const core::ffi::c_void, len);
        if rc != 0 {
            return Err(Error::Unsupported("memory unlocking unavailable"));
        }
        return Ok(());
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = ptr;
        let _ = len;
        Err(Error::Unsupported("memory unlocking unsupported on this platform"))
    }
}

