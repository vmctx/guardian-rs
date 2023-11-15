use core::alloc::{GlobalAlloc, Layout};
use winapi::ctypes::c_void;

pub struct Allocator;

use crate::syscalls::NtAllocateVirtualMemory;
use crate::syscalls::NtFreeVirtualMemory;

const NT_CURRENT_PROCESS: *mut c_void = -1isize as *mut c_void;

#[repr(u32)]
pub enum Protection {
    ReadWrite = 0x4,
    ReadWriteExecute = 0x40,
}

pub unsafe fn allocate(layout: Layout, protection: Protection) -> *mut u8 {
    let mut address: usize = 0;
    let mut size = layout.size();
    NtAllocateVirtualMemory(
        NT_CURRENT_PROCESS,
        &mut address as *mut usize as _,
        0,
        &mut size,
        0x1000 | 0x2000, // commit | reserve
        protection as u32,
    );
    address as *mut u8
}

pub unsafe fn deallocate(ptr: *mut u8, layout: Layout) {
    let mut address: usize = ptr as usize;
    let mut size = layout.size();
    NtFreeVirtualMemory(
        NT_CURRENT_PROCESS,
        &mut address as *mut usize as _,
        &mut size,
        0x8000, // mem release
    );
}

unsafe impl GlobalAlloc for Allocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocate(layout, Protection::ReadWrite)
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        deallocate(ptr, layout)
    }
}
