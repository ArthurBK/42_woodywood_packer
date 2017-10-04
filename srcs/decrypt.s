GLOBAL decrypt
SECTION .text
woody_wood:	db "....WOODY....", 10, 0
key:		db 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
to_decrypt:	db 0, 0, 0, 0, 0, 0, 0, 0
size:		db 0, 0, 0, 0
entrypoint:	db 0, 0, 0, 0, 0, 0, 0, 0

; void *encrypt(void *data, size_t size, void *key)
; rdi data 
; rsi size
; rdx key

decrypt:
push rbp
mov rbp, rsp
push rdi		; push pointer to data to stack

;mov r12, rdi		; mov params
;mov r13, rsi		; for write call
;mov r14, rdx

mov rax, 1		; write syscall
mov rdi, 1		; stdout
lea rsi, [rel woody_wood] ; ptr to str to write
mov rdx, 14		; bytes to write
syscall

;mov rdi, r12		; mov params back
;mov rsi, r13		;
;mov rdx, r14		;

movdqu xmm11, [rel key] 	; save initial key 
call init_keys_round
mov rcx, [rel size]
lea rax, [rel to_decrypt]
sub rax, [rax]
shr rcx, 4		; divide by 16 to get loops nb
and rsi, 0xf
jmp loop_str

loop_str:
cmp rcx, 0
je check_modulo
movdqu xmm14, [rdi]
call aes
movdqu [rdi], xmm14
dec rcx
add rdi, 0x10
jmp loop_str

end:
pop rax
lea rax, [rel entrypoint]
sub rax, [rax]
jmp rax
;leave
;ret


check_modulo:
cmp rsi, 0
je  end
movdqu xmm15, [rdi]	
xorps xmm15, xmm11
movdqu [rdi], xmm15
jmp end


aes:
pxor xmm14, xmm10 ; round0 (Whitening round)
aesdec xmm14, xmm9 ; round1
aesdec xmm14, xmm8 ; round2
aesdec xmm14, xmm7 ; round3
aesdec xmm14, xmm6 ; round4
aesdec xmm14, xmm5 ; round5
aesdec xmm14, xmm4 ; round6
aesdec xmm14, xmm3 ; round7
aesdec xmm14, xmm2 ; round8
aesdec xmm14, xmm1 ; round9
aesdeclast xmm14, xmm0 ; round10
ret





; Fills registers xmm0-10 with the round keys
init_keys_round:

movdqu xmm0, xmm11

aeskeygenassist xmm12, xmm0, 0x1
call key_expansion_128
movdqu xmm1, xmm11

aeskeygenassist xmm12, xmm1, 0x2
call key_expansion_128
movdqu xmm2, xmm11

aeskeygenassist xmm12, xmm2, 0x4
call key_expansion_128
movdqu xmm3, xmm11

aeskeygenassist xmm12, xmm3, 0x8
call key_expansion_128
movdqu xmm4, xmm11

aeskeygenassist xmm12, xmm4, 0x10
call key_expansion_128
movdqu xmm5, xmm11

aeskeygenassist xmm12, xmm5, 0x20
call key_expansion_128
movdqu xmm6, xmm11

aeskeygenassist xmm12, xmm6, 0x40
call key_expansion_128
movdqu xmm7, xmm11

aeskeygenassist xmm12, xmm7, 0x80
call key_expansion_128
movdqu xmm8, xmm11

aeskeygenassist xmm12, xmm8, 0x1b
call key_expansion_128
movdqu xmm9, xmm11

aeskeygenassist xmm12, xmm9, 0x36
call key_expansion_128
movdqu xmm10, xmm11

aesimc xmm1, xmm1
aesimc xmm2, xmm2
aesimc xmm3, xmm3
aesimc xmm4, xmm4
aesimc xmm5, xmm5
aesimc xmm6, xmm6
aesimc xmm7, xmm7
aesimc xmm8, xmm8
aesimc xmm9, xmm9
ret



key_expansion_128:
pshufd xmm12, xmm12, 0xff
vpslldq xmm13, xmm11, 0x4
pxor xmm11, xmm13
vpslldq xmm13, xmm11, 0x4
pxor xmm11, xmm13
vpslldq xmm13, xmm11, 0x4
pxor xmm11, xmm13
pxor xmm11, xmm12
ret

