use core::arch::global_asm;
use core::ffi::c_void;

type ULong = u32;
type NtStatus = i32;
type PVoid = *mut c_void;
type Handle = PVoid;
type PSizeT = *mut ULongPtr;
type ULongPtr = usize;

// https://j00ru.vexillium.org/syscalls/nt/64/
extern "C" {
    pub fn NtAllocateVirtualMemory(
        process_handle: Handle,
        base_address: *mut PVoid,
        zero_bits: ULongPtr,
        region_size: PSizeT,
        allocation_type: ULong,
        protect: ULong,
    ) -> NtStatus;
    pub fn NtFreeVirtualMemory(
        process_handle: Handle,
        base_address: *mut PVoid,
        region_size: PSizeT,
        free_type: ULong,
    ) -> NtStatus;
}

global_asm!(
    r#"
.macro define_syscall name, id
.global \name
\name:
    mov r10, rcx
    mov eax, \id
    syscall
    ret
.endm

define_syscall NtAllocateVirtualMemory, 0x18
define_syscall NtFreeVirtualMemory, 0x1e
"#
);
