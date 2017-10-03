;SECTION .data
;msg	db "hey you what up ", 0
;key 	db "BBBBBBBBBBBBBBBB", 0
;len 	equ $ -msg 

GLOBAL encrypt
SECTION .text

; void *encrypt(void *data, size_t size, void *key)
; rdi data 
; rsi size
; rdx key
encrypt:
push rbp
mov rbp, rsp
push rdi
push rsi

mov rbx, rsp

movdqu xmm11, [rdx] 	; save first key

call init_keys_round

mov rcx, rsi
shr rcx, 4 
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

check_modulo:
cmp rsi, 0
je  end
movdqu xmm15, [rdi]	
xorps xmm15, xmm11
movdqu [rdi], xmm15
jmp end

end:
pop rsi
pop rax
leave
ret

aes:
pxor xmm14, xmm0 ; round0 (Whitening round)
aesenc xmm14, xmm1 ; round1
aesenc xmm14, xmm2 ; round2
aesenc xmm14, xmm3 ; round3
aesenc xmm14, xmm4 ; round4
aesenc xmm14, xmm5 ; round5
aesenc xmm14, xmm6 ; round6
aesenc xmm14, xmm7 ; round7
aesenc xmm14, xmm8 ; round8
aesenc xmm14, xmm9 ; round9
aesenclast xmm14, xmm10 ; round10
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

