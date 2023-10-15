.global vmenter
.global vmexit

vmenter:
    // &mut Machine
    mov     rax, rcx
    mov     [rax + 0x10], rax
    mov     [rax + 0x18], rcx
    mov     [rax + 0x20], rdx
    mov     [rax + 0x28], rbx
    mov     [rax + 0x30], rsp
    mov     [rax + 0x38], rbp
    mov     [rax + 0x40], rsi
    mov     [rax + 0x48], rdi
    mov     [rax + 0x50], r8
    mov     [rax + 0x58], r9
    mov     [rax + 0x60], r10
    mov     [rax + 0x68], r11
    mov     [rax + 0x70], r12
    mov     [rax + 0x78], r13
    mov     [rax + 0x80], r14
    mov     [rax + 0x88], r15
    // offset_of!(Machine, cpustack) + m.cpustack.len() - 0x100 - std::mem::size_of::<u64>();
    mov     rsp,          r8
    // &mut Machine
    mov     rcx,          rax
    // run fn ptr
    mov     rax,          rdx
    // run(&mut Machine);
    jmp     rax

vmexit:
    mov     rax, [rcx + 0x10]
    mov     rcx, [rcx + 0x18]
    mov     rdx, [rcx + 0x20]
    mov     rbx, [rcx + 0x28]
    mov     rsp, [rcx + 0x30]
    mov     rbp, [rcx + 0x38]
    mov     rsi, [rcx + 0x40]
    mov     rdi, [rcx + 0x48]
    mov     r8,  [rcx + 0x50]
    mov     r9,  [rcx + 0x58]
    mov     r10, [rcx + 0x60]
    mov     r11, [rcx + 0x68]
    mov     r12, [rcx + 0x70]
    mov     r13, [rcx + 0x78]
    mov     r14, [rcx + 0x80]
    mov     r15, [rcx + 0x88]
    jmp rdx