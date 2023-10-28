use core::alloc::{GlobalAlloc, Layout};
use winapi::ctypes::c_void;

pub struct Allocator;

use crate::syscalls::NtFreeVirtualMemory;
use crate::syscalls::NtAllocateVirtualMemory;

unsafe impl GlobalAlloc for Allocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut address: usize = 0;
        let mut size = layout.size();
        unsafe {
            NtAllocateVirtualMemory(
                -1isize as *mut c_void,
                &mut address as *mut usize as _,
                0,
                &mut size,
                0x1000 | 0x2000, // commit | reserve
                0x4, // page RW
            )
        };
        address as *mut u8
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let mut address: usize = ptr as usize;
        let mut size = layout.size();
        unsafe {
            NtFreeVirtualMemory(
                -1isize as *mut c_void,
                &mut address as *mut usize as _,
                &mut size,
                0x8000, // mem release
            )
        };
    }
}
