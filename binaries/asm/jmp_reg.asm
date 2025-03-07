section .text
    global _start

_start:
    ; Compare 1 and 2
    mov eax, exit
    add ebx, eax          ; Load 1 into EAX
    mov ebx, eax          ; Load 2 into EBX
    cmp eax, ebx        ; Compare EAX and EBX
    jmp [eax]            ; Jump to exit 


exit:
    ; Exit the program
    mov eax, 1          ; syscall number for sys_exit
    int 0x80            ; call kernel
