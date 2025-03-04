section .text
    global _start

_start:
    ; Compare 1 and 2
    push rbp
    mov    rbp, 0
    jmp    init_for

incr:
    add rbp, 1

init_for:
    cmp rbp, 9
    jle in_loop

in_loop:
    cmp rbp, 5
    jne incr

    mov eax, 0
    jmp exit


exit:
         ; syscall number for sys_exit
    int 0x80            ; call kernel

