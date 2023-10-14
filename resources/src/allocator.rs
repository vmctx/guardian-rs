use core::alloc::{GlobalAlloc, Layout};
use winapi::ctypes::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};
use core::{cmp, ptr};

const HEAP_ZERO_MEMORY: u32 = 0x00000008;
const MIN_ALIGN: usize = 16;

pub struct Allocator;

type HANDLE = *mut c_void;

use crate::syscalls::NtFreeVirtualMemory;

use crate::syscalls::NtAllocateVirtualMemory;

#[inline]
unsafe fn allocate(layout: Layout, zeroed: bool) -> *mut u8 {
    let mut address: usize = 0;
    let mut size = layout.size();
    let result = unsafe {
        NtAllocateVirtualMemory(
            -1isize as *mut c_void,
            &mut address as *mut usize as _,
            0,
            &mut size,
            0x1000 | 0x2000, // commit | reserve
            0x4, // page RW
        )
    };
    address as _
}

unsafe impl GlobalAlloc for Allocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let zeroed = false;
        unsafe { allocate(layout, zeroed) }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let mut address: usize = 0;
        let mut size = layout.size();
        let ret = unsafe {
            NtFreeVirtualMemory(
                1isize as *mut c_void,
                &mut address as *mut usize as _,
                &mut size,
                0x8000, // mem release
            )
        };
    }
}
