section .data
    msg_error db "Erreur !", 0xa
    msg_error_len equ $ - msg_error
    buffer db 100      ; Buffer pour stocker les données lues

section .bss
    file_name resq 40
    size_file_name resq 1

    file_descriptor resq 1

    offset_tp resq 1

section .text
    global _start

_start:


    pop rax
    cmp rax, 2 ;; nb d'elem
    jne error

    ; on retire le nom du fichier executable
    pop rsi

    ; recuperation de l'argument 1
    pop rax
    mov [file_name], rax

    ; Ouverture du fichier

    mov rax, 2
    mov rdi, [file_name]
    mov rsi, 0
    syscall

    test rax, rax ; verification des erreurs
    js error

    ; Sauvegarde du descripteur de fichier
    mov [file_descriptor], rax

    ; Lecture du fichier
    mov rax, 0          
    mov rdi, [file_descriptor]
    mov rsi, buffer     
    mov rdx, 100        
    syscall             


    xor r9, r9
    mov r9, buffer
    xor rcx, rcx

    check:
    inc rcx
    cmp byte[r9+rcx], 4
    je sortie
    jmp check

    mov [offset_tp], rcx


    ;Affichage des données lues
    mov rax, 1          
    mov rdi, 1          
    mov rsi, buffer     
    syscall             


        



sortie:

    ;fermeture du fichier
    mov rax, 3          
    mov rdi, [file_descriptor]       
    syscall  

    ; Code de sortie
    mov rax, 60    
    mov rdi, 0    
    syscall     


error:
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_error
    mov rdx, msg_error_len
    syscall

    mov rax, 60
    mov rdi, 1
    syscall
