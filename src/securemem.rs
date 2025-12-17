use crate::error::Error;

/// Best-effort memory locking for secrets.
///
/// This reduces exposure to swapping on supported OSes, but it is not a complete mitigation:
/// - Small buffers share pages with other allocations.
/// - Locking may fail due to OS limits; failure is non-fatal.
pub struct MemoryLock {
    ptr: *const u8,
    len: usize,
    locked: bool,
}

impl MemoryLock {
    pub fn lock(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self {
                ptr: std::ptr::null(),
                len: 0,
                locked: false,
            };
        }
        let ptr = bytes.as_ptr();
        let len = bytes.len();
        let locked = unsafe { lock_region(ptr, len) }.is_ok();
        Self { ptr, len, locked }
    }
}

impl Drop for MemoryLock {
    fn drop(&mut self) {
        if self.locked && !self.ptr.is_null() && self.len != 0 {
            let _ = unsafe { unlock_region(self.ptr, self.len) };
        }
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

