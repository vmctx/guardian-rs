.global vmentry
.global vmexit

// https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170&viewFallbackFrom=vs-2019#callercallee-saved-registers
.macro pushvol
// push    rax
push    rcx
push    rdx
push    r8
push    r9
push    r10
push    r11
.endmacro

.macro popvol
pop     r11
pop     r10
pop     r9
pop     r8
pop     rdx
pop     rcx
// pop     rax
.endmacro

.macro pushnonvol
push    rbx
push    rbp
push    rsi
push    rdi
push    rsp
push    r12
push    r13
push    r14
push    r15
.endmacro

.macro popnonvol
pop     r15
pop     r14
pop     r13
pop     r12
pop     rsp
pop     rdi
pop     rsi
pop     rbp
pop     rbx
.endmacro

vmentry:
   // avoid new_vm call from changing registers like that
    pushvol
    // i need to get value pushed on the stack
    // before pushgp
    // push only accepts 32 bit immediates
    // so it needs to be a relative virtual address
    // push bytecode_location
    // jmp vmentry
    //
    sub rsp, 0xb0 // size_of machine
    mov rcx, rsp
    call new_vm
    add rsp, 0xb0
    mov rax, rcx
    popvol
    jmp vmenter

vmenter:
    // move registers into machines registerswdym
    mov [rax + 0x10], rax
    mov [rax + 0x18], rcx
    mov [rax + 0x20], rdx
    mov [rax + 0x28], rbx
    mov [rax + 0x30], rsp
    mov [rax + 0x38], rbp
    mov [rax + 0x40], rsi
    mov [rax + 0x48], rdi
    mov [rax + 0x50], r8
    mov [rax + 0x58], r9
    mov [rax + 0x60], r10
    mov [rax + 0x68], r11
    mov [rax + 0x70], r12
    mov [rax + 0x78], r13
    mov [rax + 0x80], r14
    mov [rax + 0x88], r15
    // &mut Machine
    mov rcx,          rax
    // pop wouldnt work here, use mov with offset from rsp
    // 14*8 = 112 = 0x70
    // move rdx, [rsp + 0x70]
    // pop would probably work so do that
    // then lea/mov rdx, module_base + rdx
    // or something like that
    // actually its rip relative so rip + 0x47 is that below as exmp
    // pop rdx
    lea rdx, [rip + BYTECODE]
    // run(&mut Machine, program);
    jmp run

vmexit:
    mov rax, [rcx + 0x10]
    mov rdx, [rcx + 0x20]
    // mov rbx, [rcx + 0x28]
    mov rsp, [rcx + 0x30]
    //mov rbp, [rcx + 0x38]
    //mov rsi, [rcx + 0x40]
    //mov rdi, [rcx + 0x48]
    mov r8,  [rcx + 0x50]
    mov r9,  [rcx + 0x58]
    mov r10, [rcx + 0x60]
    mov r11, [rcx + 0x68]
    //mov r12, [rcx + 0x70]
    //mov r13, [rcx + 0x78]
    //mov r14, [rcx + 0x80]
    //mov r15, [rcx + 0x88]
    mov rcx, [rcx + 0x18]
    ret