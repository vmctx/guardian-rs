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
    pushfq // save rflags
    pushvol
    sub rsp, {sizeof_machine}
    mov rcx, rsp
    call new_vm
    add rsp, {sizeof_machine}
    mov rax, rcx
    popvol
    jmp vmenter

vmenter:
    // todo save rflags incase of rentering vm, be
    // aware of instrs modifying rflags
    // move registers into machines registerswdym
    add rsp, 0x10 // because i didnt pop the bytecode ptr and rflags yet
    mov [rax + {rax}], rax
    mov [rax + {rcx}], rcx
    mov [rax + {rdx}], rdx
    mov [rax + {rbx}], rbx
    mov [rax + {rsp}], rsp
    mov [rax + {rbp}], rbp
    mov [rax + {rsi}], rsi
    mov [rax + {rdi}], rdi
    mov [rax + {r8}], r8
    mov [rax + {r9}], r9
    mov [rax + {r10}], r10
    mov [rax + {r11}], r11
    mov [rax + {r12}], r12
    mov [rax + {r13}], r13
    mov [rax + {r14}], r14
    mov [rax + {r15}], r15
    pop rcx // pop rflags into rcx
    mov [rax + {rflags}], rcx
    sub rsp, 8 // fix stack ptr back to be able to pop it
    // &mut Machine
    mov rcx,          rax
    // pop bytecode ptr, add it to image base addr = boom
    mov rax, qword ptr gs:[0x60]
    mov rax, [rax + 0x10]
    pop rdx
    lea rdx, [rax + rdx]
    // run(&mut Machine, program);
    jmp run

vmexit:
    mov rax, [rcx + {rax}]
    mov rdx, [rcx + {rdx}]
    // mov rbx, [rcx + {rbx}] // non vol
    // mov rsp, [rcx + {rsp}] // non vol
    // mov rbp, [rcx + {rbp}] // non vol
    // mov rsi, [rcx + {rsi}] // non vol
    // mov rdi, [rcx + {rdi}] // non vol
    mov r8,  [rcx + {r8}]
    mov r9,  [rcx + {r9}]
    mov r10, [rcx + {r10}]
    mov r11, [rcx + {r11}]
    // mov r12, [rcx + {r12}] // non vol
    // mov r13, [rcx + {r13}] // non vol
    // mov r14, [rcx + {r14}] // non vol
    // mov r15, [rcx + {r15}] // non vol
    mov rcx, [rcx + {rcx}]
    ret