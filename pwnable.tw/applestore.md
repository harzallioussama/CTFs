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
