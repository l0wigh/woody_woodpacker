format binary
use64


_start:
	call .get_rip			; Sert à récuperer l'adresse mémoire aléatoire
.get_rip:					;
	pop r15					; On fout le rip dans r15
	sub r15, .get_rip		; On soustrait à ce rip, l'adresse de notre label

	; Call classique du ...WOODY...
	mov rax, 1
	mov rdi, 1
	lea rsi, [woody_str]
	mov rdx, 12
	syscall

	mov rax, r15			; Début stub
	mov rbx, [to_sub]		; Load notre entry point
	sub rax, rbx			; RAX = virtual base
	mov rbx, [old_entry]	; Récupération du vrai entry point
	add rax, rbx			; Virtualisation

	push rax				; On push l'adresse
	ret						; Et là ça part dessus

woody_str db "...WOODY...", 10, 0
old_entry dq 0xAAAAAAAAAAAAAAAA
to_sub dq 0xBBBBBBBBBBBBBBBB
