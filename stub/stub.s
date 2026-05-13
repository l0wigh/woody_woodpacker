format binary
use64


_start:
	call .get_rip			; Sert à récuperer l'adresse mémoire aléatoire
.get_rip:					;
	pop r15					; On fout le rip dans r15
	push rdx
	sub r15, .get_rip		; On soustrait à ce rip, l'adresse de notre label

	mov rax, r15
	mov rbx, [to_sub]
	sub rax, rbx
	mov rbx, [sexion]
	add rax, rbx

	mov rdi, rax
	and rdi, -4096
	mov rsi, [chibre]
	mov rdx, 7
	mov rax, 10
	syscall

	; Call classique du ...WOODY...
	mov rax, 1
	mov rdi, 1
	lea rsi, [woody_str]
	mov rdx, 12
	syscall

	push rcx
	mov rax, r15
	mov rbx, [to_sub]		; Load notre entry point
	sub rax, rbx
	mov rbx, [sexion]
	add rax, rbx
	mov rdi, rax
	mov rcx, [chibre]
	xor rax, rax
	mov al, byte [chatte]
.loop:
	test rcx, rcx
	jz .done
	xor byte [rdi], al
	inc rdi
	dec rcx
	jmp .loop


.done:
	mov rax, r15			; Début stub
	mov rbx, [to_sub]		; Load notre entry point
	sub rax, rbx			; RAX = virtual base
	mov rbx, [old_entry]	; Récupération du vrai entry point
	add rax, rbx			; Virtualisation

	pop rcx
	pop rdx
	jmp rax

woody_str db "...WOODY...", 10, 0
old_entry dq 0xAAAAAAAAAAAAAAAA
to_sub dq 0xBBBBBBBBBBBBBBBB
sexion dq 0xCCCCCCCCCCCCCCCC
chibre dq 0xDDDDDDDDDDDDDDDD
chatte dq 0xEEEEEEEEEEEEEEEE
