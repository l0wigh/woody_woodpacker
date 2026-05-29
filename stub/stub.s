format binary
use64


_start:
	call .get_rip			; Sert à récuperer l'adresse mémoire aléatoire
.get_rip:					;
	pop r15					; On fout le rip dans r15
	push rdx
	sub r15, .get_rip		; On soustrait à ce rip, l'adresse de notre label

	; mprotect rwx pour la zone .text
	mov rax, r15
	mov rbx, [to_sub]
	sub rax, rbx
	mov rbx, [text_addr]
	add rax, rbx
	mov rdi, rax
	and rdi, -4096
	; compense la taille avec l'offset du début
	mov rsi, rax
	sub rsi, rdi
	add rsi, [text_size]
	; aligne la taille vers le HAUT (page suivante)
	add rsi, 4095
	and rsi, -4096
	mov rdx, 7
	mov rax, 10
	syscall

	; mprotect rwx pour la zone .rodata
	mov rax, r15
	mov rbx, [to_sub]
	sub rax, rbx
	mov rbx, [rodata_addr]
	add rax, rbx
	mov rdi, rax
	and rdi, -4096
	; compense la taille avec l'offset du début
	mov rsi, rax
	sub rsi, rdi
	add rsi, [rodata_size]
	; aligne la taille vers le HAUT (page suivante)
	add rsi, 4095
	and rsi, -4096
	mov rdx, 7
	mov rax, 10
	syscall

	; Call classique du ...WOODY...
	mov r12, 1464
	sub rsp, 16
	mov rdi, rsp
	mov byte [rdi], '-'		; .
	cmp r12, 12
	je _start.junk
	mov byte [rdi+1], '-'	; .
	add byte [rdi+1], 1
	add byte [rdi], 1
	sub r12, 2345
	add rax, 555
	cmp r12, rax
	je _start.loop_junk
	mov byte [rdi+2], '*'	; .
	add byte [rdi+2], 4
	mov byte [rdi+3], 'R'	; W
	mov byte [rdi+4], 'N'	; O
	mov byte [rdi+5], 'N'	; O
	mov byte [rdi+6], '@'	; D
	add byte [rdi+6], 4
	add byte [rdi+5], 1
	sub r12, -1
	add byte [rdi+4], 1
	mov byte [rdi+7], 'T'	; Y
	add byte [rdi+7], 5
	cmp rax, rax
	jne _start.loop_junk
	mov byte [rdi+8], '-'	; .
	add byte [rdi+8], 1
	mov byte [rdi+9], '-'	; .
	add byte [rdi+9], 1
	mov byte [rdi+10], '*'	; .
	add byte [rdi+10], 4
	add byte [rdi+11], 5
	add byte [rdi+11], 5
	add byte [rdi+3], 5
	mov rax, 1
	mov rdi, 1
	mov rsi, rsp
	mov rdx, 12
	syscall
	add rsp, 16
	jmp _start.junk

.continue:
	mov rax, 22309847
	imul rax, rax
	add rax, 22240700
	test rax, 1
	jz _start.real
	mov al, byte [white_keycard]
	sub byte [rdi], al
	; On applique la blue keycard
	mov al, byte [blue_keycard]
	xor byte [rdi], al
	; On applique la red keycard
	mov al, byte [red_keycard]
	add byte [rdi], al
.real
	mov rax, r15
	mov rbx, [to_sub]		; Load notre entry point
	sub rax, rbx
	mov rbx, [text_addr]
	add rax, rbx
	mov rdi, rax
	mov rcx, [text_size]
.text_loop:
	test rcx, rcx
	jz .rodata
	; On applique la white keycard
	xor rax, rax
	mov al, byte [white_keycard]
	sub byte [rdi], al
	; On applique la blue keycard
	xor rax, rax
	mov al, byte [blue_keycard]
	xor byte [rdi], al
	; On applique la red keycard
	xor rax, rax
	mov al, byte [red_keycard]
	add byte [rdi], al
	inc rdi
	dec rcx
	jmp .text_loop

.rodata:
	xor rax, rax
	xor rbx, rbx
	xor rcx, rcx
	mov rax, r15
	mov rbx, [to_sub]		; Load notre entry point
	sub rax, rbx
	mov rbx, [rodata_addr]
	add rax, rbx
	mov rdi, rax
	mov rcx, [rodata_size]
.rodata_loop:
	test rcx, rcx
	jz .done
	; On applique la blue keycard
	xor rax, rax
	mov al, byte [blue_keycard]
	add byte [rdi], al
	; On applique la white keycard
	xor rax, rax
	mov al, byte [white_keycard]
	xor byte [rdi], al
	; On applique la red keycard
	xor rax, rax
	mov al, byte [red_keycard]
	sub byte [rdi], al
	inc rdi
	dec rcx
	jmp .rodata_loop

.done:
	mov rax, r15			; Début stub
	mov rbx, [to_sub]		; Load notre entry point
	sub rax, rbx			; RAX = virtual base
	mov rbx, [old_entry]	; Récupération du vrai entry point
	add rax, rbx			; Virtualisation

	pop rdx
	jmp rax

.junk:
    mov r12, 1145
.loop_junk:
    mov rax, 1
    mov rdi, 1
    mov rsi, 0
    mov rdx, 0
    syscall
    add rax, r12
    sub rax, r12
    dec r12
    jnz .loop_junk
    jmp .continue

old_entry       dq 0xAAAAAAAAAAAAAAAA
to_sub          dq 0xBBBBBBBBBBBBBBBB
text_addr       dq 0xCCCCCCCCCCCCCCCC
text_size       dq 0xDDDDDDDDDDDDDDDD
rodata_addr     dq 0xEEEEEEEEEEEEEEEE
rodata_size     dq 0xFFFFFFFFFFFFFFFF
blue_keycard    dq 0xCA2DCA2DCA2DCA2D
white_keycard   dq 0xCA2DCA2DCA2DCA2D
red_keycard     dq 0xCA2DCA2DCA2DCA2D
