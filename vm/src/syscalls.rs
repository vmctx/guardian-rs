use core::arch::global_asm;
use winapi::shared::basetsd::{PSIZE_T, ULONG_PTR};
use winapi::shared::ntdef::{HANDLE, NTSTATUS, PVOID, ULONG,
};

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
define_syscall NtProtectVirtualMemory, 0x50

"#
);
