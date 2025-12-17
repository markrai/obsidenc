use crate::error::Error;
use std::fmt;
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// Best-effort memory locking for secrets.
///
/// This reduces exposure to swapping on supported OSes, but it is not a complete mitigation:
/// - Small buffers share pages with other allocations.
/// - Locking may fail due to OS limits; failure is non-fatal.
///
/// This struct owns the data it locks to guarantee lifetime safety.
/// The guard pattern ensures the locked data is the data being used.
///
/// # Reallocation Safety
///
/// If `T` is a `Vec<u8>`, avoid calling methods that could trigger reallocation
/// (e.g., `push`, `extend`, `reserve`) as this could leave old copies in heap memory.
/// In practice, the data is typically not mutated after creation, making this safe.
pub struct MemoryLock<T: AsRef<[u8]> + Zeroize> {
    data: T,
    locked: bool,
}

impl<T: AsRef<[u8]> + Zeroize> MemoryLock<T> {
    /// Takes ownership of the data, locks it, and returns the guard.
    /// The locked data can be accessed via Deref/DerefMut.
    pub fn new(data: T) -> Self {
        let slice = data.as_ref();
        let ptr = slice.as_ptr();
        let len = slice.len();
        let locked = if len == 0 {
            false
        } else {
            unsafe { lock_region(ptr, len) }.is_ok()
        };
        Self { data, locked }
    }
}

impl<T: AsRef<[u8]> + Zeroize> Deref for MemoryLock<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]> + Zeroize> DerefMut for MemoryLock<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<T: AsRef<[u8]> + Zeroize> Drop for MemoryLock<T> {
    fn drop(&mut self) {
        if self.locked {
            let slice = self.data.as_ref();
            if !slice.is_empty() {
                let _ = unsafe { unlock_region(slice.as_ptr(), slice.len()) };
            }
        }
        // Zeroize the data before dropping
        self.data.zeroize();
    }
}

impl<T: AsRef<[u8]> + Zeroize> fmt::Debug for MemoryLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryLock")
            .field("locked", &self.locked)
            .field("data", &"***REDACTED***")
            .finish()
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

