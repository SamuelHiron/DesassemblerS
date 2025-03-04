section .text
    global _start

_start:
    mov eax, 1; Compare 1 and 2
main:
    mov ebx, 2          ; Load 2 into EBX
    cmp eax, ebx        ; Compare EAX and EBX
    jmp exit

exit:
    nop    
    jnz main            ; Jump to exit 
    int 0x80