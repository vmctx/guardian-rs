.global vmentry

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

fxsave:
    movaps [rcx + {xmm0}], xmm0
    movaps [rcx + {xmm1}], xmm1
    movaps [rcx + {xmm2}], xmm2
    movaps [rcx + {xmm3}], xmm3
    movaps [rcx + {xmm4}], xmm4
    movaps [rcx + {xmm5}], xmm5
    movaps [rcx + {xmm6}], xmm6
    movaps [rcx + {xmm7}], xmm7
    movaps [rcx + {xmm8}], xmm8
    movaps [rcx + {xmm9}], xmm9
    movaps [rcx + {xmm10}], xmm10
    movaps [rcx + {xmm11}], xmm11
    movaps [rcx + {xmm12}], xmm12
    movaps [rcx + {xmm13}], xmm13
    movaps [rcx + {xmm14}], xmm14
    movaps [rcx + {xmm15}], xmm15
    ret

fxrestore:
    movaps xmm0, [rcx + {xmm0}]
    movaps xmm1, [rcx + {xmm1}]
    movaps xmm2, [rcx + {xmm2}]
    movaps xmm3, [rcx + {xmm3}]
    movaps xmm4, [rcx + {xmm4}]
    movaps xmm5, [rcx + {xmm5}]
    movaps xmm6, [rcx + {xmm6}]
    movaps xmm7, [rcx + {xmm7}]
    movaps xmm8, [rcx + {xmm8}]
    movaps xmm9, [rcx + {xmm9}]
    movaps xmm10, [rcx + {xmm10}]
    movaps xmm11, [rcx + {xmm11}]
    movaps xmm12, [rcx + {xmm12}]
    movaps xmm13, [rcx + {xmm13}]
    movaps xmm14, [rcx + {xmm14}]
    movaps xmm15, [rcx + {xmm15}]
    ret

vmentry:
    // avoid new_vm call from changing registers like that
    pushfq // save rflags
    pushvol
    call {alloc_new_stack}
    add rax, {cpustack_offset}
    sub rax, {sizeof_machine}
    mov rcx, rax
    push rcx
    call {alloc_vm}
    pop rax // pop new_rsp into rax
    mov [rax + {cpustack}], rax
    popvol
    jmp vmenter

vmenter:
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
    sub rsp, 0x10 // fix stack ptr back to be able to pop it
    pop rcx // pop rflags into rcx
    mov [rax + {rflags}], rcx
    // &mut Machine
    mov rcx,          rax
    // save floating point and xmm regs
    call fxsave
    // pop bytecode ptr, add it to image base addr = boom
    mov rax, qword ptr gs:[0x60]
    mov rax, [rax + 0x10]
    pop rdx
    lea rdx, [rax + rdx]
    // change to new stack
    mov rsp, [rcx + {cpustack}]
    // run(&mut Machine, program);
    call run
    mov rcx, rax

vmexit:
    // restore old stack
    mov rsp, [rcx + {rsp}]
    // copy from vm cpu stack to current
    sub rsp, {sizeof_machine} + 8
    mov rdx, rcx
    mov rcx, rsp
    mov r8, {sizeof_machine}
    call memcpy
    mov rcx, rsp
    // dealloc cpu and vmstack
    call {dealloc}
    // restore self ptr
    mov rcx, rsp
    // restore rflags
    mov rax, [rcx + {rflags}]
    push rax
    popfq
    // restore xmm regs
    call fxrestore
    // restore gpr
    mov rax, [rcx + {rax}]
    mov rdx, [rcx + {rdx}]
    mov rbx, [rcx + {rbx}] // non vol
    mov rbp, [rcx + {rbp}] // non vol
    mov rsi, [rcx + {rsi}] // non vol
    mov rdi, [rcx + {rdi}] // non vol
    mov r8,  [rcx + {r8}]
    mov r9,  [rcx + {r9}]
    mov r10, [rcx + {r10}]
    mov r11, [rcx + {r11}]
    mov r12, [rcx + {r12}] // non vol
    mov r13, [rcx + {r13}] // non vol
    mov r14, [rcx + {r14}] // non vol
    mov r15, [rcx + {r15}] // non vol
    mov rcx, [rcx + {rcx}]
    add rsp, {sizeof_machine} + 8
    ret
