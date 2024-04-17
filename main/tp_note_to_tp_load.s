section .data

section .bss
    taille_arg resb 16
    ma_variable resb 16

section .text
    global _start

_start:

    mov rax, [rbp + 16]  ; Le premier argument est à rbp + 16 sur x86-64
    mov qword[ma_variable], rax

    mov rax, 1
    mov rdi, 1
    mov rsi, [ma_variable]
    mov rdx , 16
    syscall




    ; Code de sortie
    mov rax, 60    
    mov rdi, 0    
    syscall     


