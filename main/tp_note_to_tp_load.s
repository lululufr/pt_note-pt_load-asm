corrige : section .data
    msg_error db "Erreur !", 0xa
    msg_error_len equ $ - msg_error
    buffer db 100      ; Buffer pour stocker les données lues




section .bss
    file_name resq 40
    size_file_name resq 1

    file_descriptor resq 1

    offset_tp resq 1

    tp_load resb 1
    tp_note resb 1

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

    ; Ouverture du fichier en lecture ecriture 
    mov rax, 2
    mov rdi, [file_name]
    mov rsi, 2
    syscall

    ; verification des erreurs
    test rax, rax 
    js error


    ; Sauvegarde du descripteur de fichier
    mov [file_descriptor], rax



    ; Lecture du fichier
    mov rax, 0          
    mov rdi, [file_descriptor]
    mov rsi, buffer     
    mov rdx, 200        
    syscall            

    mov rdi, 1              ; file descriptor 1 is stdout
    mov rax, 1              
    mov rsi, buffer       ; affichage du fic debug  
    syscall 


    ;init
    xor r9, r9
    mov r9, buffer
    xor rcx, rcx
    mov byte[tp_note], 0x04
    mov byte[tp_load], 0x01

    check:
    inc rcx
    cmp dword[r9+rcx], 0x4
    je end_check
    jmp check
    end_check:

    mov [offset_tp], rcx
    
; Déplacement du curseur de lecture/écriture à l'offset spécifié
    mov rax, 8          ; Appel système pour déplacer le curseur de lecture/écriture (sys_lseek)
    mov rdi, [file_descriptor]       
    mov rsi, [offset_tp]     ; Offset ou se déplacer
    mov rdx, 0          ; Origine (0 pour le début du fichier)
    syscall          


    mov rax, 1         
    mov rdi, [file_descriptor]       ; Descripteur de fichier
    mov rsi, tp_load   ; Nouvelles données à écrire
    mov rdx, 1 ; Longueur des nouvelles données à écrire
    syscall             ; Appel système   


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
