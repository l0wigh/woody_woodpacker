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

	mov rax, r15 	; On copie l'adresse de notre OEP qu'on a choppé au runtime
	; mov rbx, 0xc0000000		; Le décalage mémoire de la zone du packer
	; add rax, r15			; On ajoute l'offset aléatoire récupérer plus tôt
	; sub rax, rbx			; On soustrait le décalage

	push rax				; On push l'adresse
	ret						; Et là ça part dessus

woody_str db "...WOODY...", 10, 0
old_entry dq 0x0000000000000000
