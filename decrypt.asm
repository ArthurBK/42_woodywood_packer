GLOBAL decrypt
SECTION .text
; void *encrypt(void *data, size_t size, void *key)
; rdi data 
; rsi size
; rdx key

decrypt:
push rbp
mov rbp, rsp

sub rsp, 0xb0
mov rbx, rsp

movdqu xmm1, [rdx] 	; mov initial key 
movdqu [rbx], xmm1 	; mov key to stack
mov rcx, rbx		; mov addr to rcx 
add rcx, 0x10 		; point to next elem on stack
call init_keys_round
mov rcx, 9
mov r8, 0x10
call keys_decrypt
call aes
movdqu [rdi], xmm1
lea rax, [rdi]
leave
ret

aes:
movdqu xmm1, [rdi]
pxor xmm1, [rbx + 0xa0] ; round0 (Whitening round)
aesdec xmm1, [rbx + 0x90] ; round1
aesdec xmm1, [rbx + 0x80] ; round2
aesdec xmm1, [rbx + 0x70] ; round3
aesdec xmm1, [rbx + 0x60] ; round4
aesdec xmm1, [rbx + 0x50] ; round5
aesdec xmm1, [rbx + 0x40] ; round6
aesdec xmm1, [rbx + 0x30] ; round7
aesdec xmm1, [rbx + 0x20] ; round8
aesdec xmm1, [rbx + 0x10] ; round9
aesdeclast xmm1, [rbx] ; round10
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
pshufd xmm2, xmm2, 0xff
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

keys_decrypt:
movdqu xmm1, [rbx + r8]
aesimc xmm1, xmm1
movdqu [rbx + r8], xmm1
dec rcx
add r8, 0x10
cmp rcx, 0
jne keys_decrypt
ret
