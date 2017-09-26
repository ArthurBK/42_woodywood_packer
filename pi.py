str =  "\x9c\x50\x57\x56\x54\x52\x51"                                       # pushf && pusha (7)
str += "\xbf\x01\x00\x00\x00"                                               # mov edi, 0x1 (5)
str += "\x48\x8d\x35\x18\x00\x00\x00"                                       # lea rsi, [rip+0x18] (7)
str += "\xba\x0f\x00\x00\x00"                                               # mov edx, 0x0f (5)
str += "\x48\x89\xf8"                                                       # mov rax, rdi (3)
str += "\x0f\x05"                                                           # syscall (2)
str += "\x59\x5a\x5c\x5e\x5f\x58\x9d"                                       # popa && popf (7)
str += "\xb8\x00\x00\x00\x00"                                               # mov eax, 0x0 (5)
str += "\x5d"                                                               # pop rbp (1)
str += "\xc3"                                                               # ret (1)
str += "\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x2e\x2e\x0a\x00"   # WOODY STR (16)
str += "\x00" * 10                                                          # Used for padding
# TOTAL: 58 + 10
# RUN IT WITH PYTHON2 PLS
print(str)
