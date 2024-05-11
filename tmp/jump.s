
section .text
global _start

_start:




    jmp prout ; Vous pouvez modifier la valeur de l'offset ici

mov rax,rbx 
mov rcx,0

prout:

mov rax,60
mov rdi,0
syscall
