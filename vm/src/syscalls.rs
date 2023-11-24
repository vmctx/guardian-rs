use core::arch::global_asm;
use core::ffi::c_void;

type ULONG = u32;
type NTSTATUS = i32;
type PVOID = *mut c_void;
type HANDLE = PVOID;
type PSIZE_T = *mut ULONG_PTR;
type ULONG_PTR = usize;

// https://j00ru.vexillium.org/syscalls/nt/64/
extern "C" {
    pub fn NtAllocateVirtualMemory(
        process_handle: HANDLE,
        base_address: *mut PVOID,
        zero_bits: ULONG_PTR,
        region_size: PSIZE_T,
        allocation_type: ULONG,
        protect: ULONG,
    ) -> NTSTATUS;
    pub fn NtFreeVirtualMemory(
        process_handle: HANDLE,
        base_address: *mut PVOID,
        region_size: PSIZE_T,
        free_type: ULONG,
    ) -> NTSTATUS;
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
