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
	add rax, rbx            ; rax = adresse réelle de .text
	mov rdi, rax
	and rdi, -4096          ; aligne le début vers le bas
	; compense la taille avec l'offset du début
	mov rsi, rax
	sub rsi, rdi            ; offset = adresse originale - adresse alignée
	add rsi, [text_size]    ; taille totale = offset + taille section
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
	add rax, rbx            ; rax = adresse réelle de .rodata
	mov rdi, rax
	and rdi, -4096          ; aligne le début vers le bas
	; compense la taille avec l'offset du début
	mov rsi, rax
	sub rsi, rdi            ; offset = adresse originale - adresse alignée
	add rsi, [rodata_size]    ; taille totale = offset + taille section
	; aligne la taille vers le HAUT (page suivante)
	add rsi, 4095
	and rsi, -4096
	mov rdx, 7
	mov rax, 10
	syscall

	; Call classique du ...WOODY...
	mov rax, 1
	mov rdi, 1
	lea rsi, [woody_str]
	mov rdx, 12
	syscall

	mov rax, r15
	mov rbx, [to_sub]		; Load notre entry point
	sub rax, rbx
	mov rbx, [text_addr]
	add rax, rbx
	mov rdi, rax
	mov rcx, [text_size]
	xor rax, rax
	mov al, byte [xor_key]
.text_loop:
	test rcx, rcx
	jz .rodata
	xor byte [rdi], al
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
	xor rax, rax
	mov al, byte [xor_key]
.rodata_loop:
	test rcx, rcx
	jz .done
	xor byte [rdi], al
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

woody_str db "...WOODY...", 10, 0
old_entry dq 0xAAAAAAAAAAAAAAAA
to_sub    dq 0xBBBBBBBBBBBBBBBB
text_addr dq 0xCCCCCCCCCCCCCCCC
text_size dq 0xDDDDDDDDDDDDDDDD
rodata_addr dq 0xEEEEEEEEEEEEEEEE
rodata_size dq 0xFFFFFFFFFFFFFFFF
xor_key   dq 0xEEEEEEEEEEEEEEEE
