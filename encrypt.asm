;SECTION .data
;msg	db "hey you what up ", 0
;key 	db "BBBBBBBBBBBBBBBB", 0
;len 	equ $ -msg 

GLOBAL encrypt
SECTION .text
;	GLOBAL _start

;	_start:
;	lea rdi, [rel msg]
;	mov rsi, 16
;	lea rdx, [rel key]
;	call encrypt
;
;	movdqu [rdi], xmm1
;	
;	mov rcx, rdi
;	mov rbx, 1 	;fd
;	mov rdx, 16 	;len
;	mov rax, 4 	;syscall
;	int 0x80
;
;	mov rdx, 0
;	mov rax, 1
;	int 0x80


; void *encrypt(void *data, size_t size, void *key)
; rdi data 
; rsi size
; rdx key
	encrypt:
	push rbp
	mov rbp, rsp

	sub rsp, 0xb0
	mov rbx, rsp
	
	movdqu xmm1, [rdx] 	; mov initial key 
	movdqu [rbx], xmm1 	; mov key to stack
	mov rcx, rbx		; mov addr to rcx 
	add rcx, 0x10 		; point to next elem on stack
	call init_keys_round
	call aes
	movdqu [rdi], xmm1
	lea rax, [rdi]
	leave
	ret

	aes:
	movdqu xmm1, [rdi]
	pxor xmm1, [rbx] ; round0 (Whitening round)
	aesenc xmm1, [rbx + 0x10] ; round1
	aesenc xmm1, [rbx + 0x20] ; round2
	aesenc xmm1, [rbx + 0x30] ; round3
	aesenc xmm1, [rbx + 0x40] ; round4
	aesenc xmm1, [rbx + 0x50] ; round5
	aesenc xmm1, [rbx + 0x60] ; round6
	aesenc xmm1, [rbx + 0x70] ; round7
	aesenc xmm1, [rbx + 0x80] ; round8
	aesenc xmm1, [rbx + 0x90] ; round9
	aesenclast xmm1, [rbx + 0xa0] ; round10
	ret

	init_keys_round:
	aeskeygenassist xmm2, xmm1, 0x1
	call key_expansion_128
	aeskeygenassist xmm2, xmm1, 0x2
	call key_expansion_128
	aeskeygenassist xmm2, xmm1, 0x4
	call key_expansion_128
	aeskeygenassist xmm2, xmm1, 0x8
	call key_expansion_128
	aeskeygenassist xmm2, xmm1, 0x10
	call key_expansion_128
	aeskeygenassist xmm2, xmm1, 0x20
	call key_expansion_128
	aeskeygenassist xmm2, xmm1, 0x40
	call key_expansion_128
	aeskeygenassist xmm2, xmm1, 0x80
	call key_expansion_128
	aeskeygenassist xmm2, xmm1, 0x1b
	call key_expansion_128
	aeskeygenassist xmm2, xmm1, 0x36
	call key_expansion_128
	ret

	key_expansion_128:
	pshufd xmm2, xmm1, 0xff
	vpslldq xmm3, xmm1, 0x4
	pxor xmm1, xmm3
	vpslldq xmm3, xmm1, 0x4
	pxor xmm1, xmm3
	vpslldq xmm3, xmm1, 0x4
	pxor xmm1, xmm3
	pxor xmm1, xmm2
	movdqu [rcx], xmm1 ; load res to stack
	add rcx, 0x10 ; point to next elem on stak
	ret
