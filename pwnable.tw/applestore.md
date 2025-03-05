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
   - The `atoi` function will convert `0x33` (stopping at the first non-numeric character) to the integer `51`.
   - The value `51` corresponds to the **delete item** function (third choice in the menu).
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
