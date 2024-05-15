section .text
global _start

_start:



test rax,rax
mov rax, 2
mov rbx, 3

mov rax,rbx 
mov rcx,0

prout:

mov rax,60
mov rdi,0
syscall
