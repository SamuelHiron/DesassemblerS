section .text
    global _start

_start:
    mov eax, 0x8049015
    mov ebx, 0x2
    cmp eax, ebx
    jmp [eax]
    mov eax, 0x1
    jmp exit
    db 0xFFFFFF


section .data
    ; Ajout d'une section de données pour séparer les fonctions
    data_section:
        db 0x00, 0x01, 0x02, 0x03, 0x04  ; Exemple de données
        times 10 db 0x00                 ; Ajout de 10 octets de padding

section .text
greater:
    mov eax, 0x0

section .data
    ; Ajout d'une autre section de données pour séparer les fonctions
    data_section2:
        db 0x05, 0x06, 0x07, 0x08, 0x09  ; Exemple de données
        times 10 db 0x00                 ; Ajout de 10 octets de padding

section .text
exit:
    mov ebx, eax
    mov eax, 0x1
    int 0x80