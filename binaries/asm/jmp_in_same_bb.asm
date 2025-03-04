section .text
    global _start

_start:
    ; Compare 1 and 2
    mov eax, 1          ; Load 1 into EAX
    mov ebx, 2          ; Load 2 into EBX
    cmp eax, ebx        ; Compare EAX and EBX
exit:
    nop    
    jnz exit            ; Jump to exit 
    int 0x80