//! A simple runtime which can be used to execute emitted instructions.

use core::ffi::c_void;

/// A simple `mmap`ed runtime with executable pages.
pub struct Runtime {
    buf: *mut c_void,
    len: usize,
}

impl Runtime {
    /// Create a new [Runtime].
    pub fn new(code: impl AsRef<[u8]>) -> Runtime {
        // Allocate a single page.
        let len = core::num::NonZeroUsize::new(4096).unwrap();
        let buf = 0 as _;


        Runtime {
            buf,
            len: len.get(),
        }
    }

    /// Reinterpret the block of code as `F`.
    #[inline]
    pub unsafe fn as_fn<F>(&self) -> F {
        unsafe { core::mem::transmute_copy(&self.buf) }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        unsafe {

        }
    }
}
