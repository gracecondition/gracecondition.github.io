---
title: "machsec - detecting XNU binary mitigations"
date: 2025-10-10T14:00:00Z
category: "analysis"
tags: ["example", "analysis"]
summary: "This article explains my new mitigtion detection tool machsec, for iOS/macOS, alongside binary mitigations available on XNU"
---
# What is machsec?
Machsec is a custom tool I wrote to identify security mitigations on MachO binaries on iOS/macOS.
The idea came to mind when i realized there is no "checksec" equivalent for these platforms,
not one that can detect the unique mitigations that are present on these operating systems.
Since the mitigations are super unique, and dont exist in any other operating system.
Writing a tool from scratch was necessary.
Detecting mitigations present in a binary are a crucial step in understanding what kind
of exploits need to be found and abused in order to gain arbitrary code execution in them.
For example, you can not abuse a dangling pointer if all of your pointers are signed.
What are signed pointers? There is no such thing on other platforms? this is exactly the issue
I tried to solve with this program.
# Mitigations 
Every operating system has mitigations put in place to make exploitation
more difficult.
Mitigations usually come in 3 flavors:
* Operating system level (ASLR/KASLR for example)
* Compiler level (Inserting canaries into the stackframe)
* Hardware level + operating system level+compiler level (SMAP/SMEP, PAC)

Most operating systems implement the basic common mitigations that are ubiqiutous,
But macOS and iOS are by far the most mitigation rich operating systems out there.

I will now attempt to break down almost every single major mitigation on XNU systems,
Mostly mitigations that exist on the Compiler Level / Hardware level.
## Stack Canaries 
### What are stack canaries?
Stack canaries is one of the most common mitigations you are going to find on an operating system.
Stack canaries started becoming a thing after the phrack article "Smashing the stack for fun and profit",
where the famous technique "stacksmashing" was popularized, also known by its over name, a stack overflow.
To understand what stack canaries are, it is integral to have a firm grasp on assembly language and how a modern computer works.
I highly recommend reading up on how assembly language works, and returning to this article afterwards, in order for things here
to make sense.
But put simply,
Every function you implement and use in any modern low level programming language, will set up a memory region for itself,
called the "Stack".
Its a Last-in-first-out sort of data structure, where data like variables amongst other interesting things is stored for
functions to make use of.
One of those interesting things is something called the instruction pointer.
I wont go into much detail into what an instruction pointer is,
but basically, its the memory address location of where to go after the function has finished running,
more specifically, its the address of the function that previously called that function.
For example, lets imagine the following:
``function main --(calls)--> function printf()``
If theres more logic in main after the printf, printf would need to know how to return to main.
In the stackframe of printf, the instruction pointer to go back to main is present.
The stack layout of a program's function might look something like this (the stackframe):

(represented as some sort of weird abomination of a stack)
```asm
---- <- $bp (base pointer of stackframe)
int i = 0x1337;
int j = 0x41;
stack canary = 0xr4nd0mnumb3r
instruction pointer = 0x80000 <-- we want to control this
---- <- $sp (stack pointer)
```
A stack buffer overflow occurs when we read way too much data and start overwriting adjacent variables.
The instruction pointer is just techinically another variable on the stack. If were not careful when writing to the
stack, we could accidentally run it over.
The stack canary is there to be intentionally the target of abuse.
Lets take a look at this stack frame after a buffer overflow attack (usually a bunch of A's):
```asm
---- <- $bp (base pointer of stack
int i = 'AAAAAAAAAAAAAAAAAAAAAAA' 
int j = 'AAAAAAAAAAAAAAAAAAAAAAA' 
stack canary = 'AAAAAAAAAA' <--- stack canary hit! abort! abort!
instruction pointer = 0x80000 <-- we want to control this
---- <- $sp (stack pointer)
```
In the actual code of the program, the compiler will insert an additional function
before the function returns (reads from the instruction pointer) to check if the canary on the
stack matches the value of the canary in ``.rodata``, a region of memory in the binary
that the attacker can never write to, since its read only.
Lets compare what the code a developer would see, versus, what would actually get executed
on a lower level.
Heres our code:
```c
#include <stdio.h>

int main()
{
    char buffer[20];
    fgets(buffer,sizeof(buffer)-1,stdin);
    printf("%s", buffer);
    return 0;
}
```
As you can see, pretty clear and cut.
The control flow logic would go like this
``main() --> fgets() --> printf() --> return/end()``
Lets take a look at whats actually happening:
{{< figure src="/images/ida_canary.png" width="80%" >}}
As you can see, a program that should  be clear and cut, now has branches, conditional
checks, and a call to ``__stack_chk_fail``.
The flow looks a little something like this:
```asm
main() --> fgets() --> printf()-->check stack canary()--if still the same end()
                                                    |
                                                    |__> else crash cuz something evil is happening()
```
This clever little mechanism prevents an attacker from controlling where the function goes after finishing execution.
### How to detect them in binaries
There are two easy methods to check if there are canaries.
You can either check the binary for the functions that handle the canary verification:
#### Method 1
```c
    if (!res->canary_enabled && macho) {
        struct symtab_command *symtab = macho_get_symtab(macho);
        if (symtab) {
            struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
            char *strings = (char *)macho->data + symtab->stroff;
            
            for (uint32_t i = 0; i < symtab->nsyms; i++) {
                if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
                    char *name = strings + symbols[i].n_un.n_strx;
                    if (strcmp(name, "___stack_chk_fail") == 0) {
                        res->canary_enabled = true;
                        break;
                    }
                }
            }
        }
    }
```
This will of course not be possible since the symbols (names of functions) vanish
when the program is stripped and statically linked("packing all of the libraries
of the program together into one binary).

#### Method 2
Or you can look for data that looks like the canary getting moved around:
```c
    for (size_t i = 0; i < count; i++) {
        // Look for x86_64 stack canary offset gs:[0x28] on macOS
        if ((strstr(insn[i].op_str, "gs:[0x28]") || strstr(insn[i].op_str, "gs:0x28")) &&
            (strcmp(insn[i].mnemonic, "mov") == 0)) {
            res->canary_enabled = true;
        }

        // Look for x86 32-bit stack canary offset gs:[0x14] on macOS
        if ((strstr(insn[i].op_str, "gs:[0x14]") || strstr(insn[i].op_str, "gs:0x14")) &&
            (strcmp(insn[i].mnemonic, "mov") == 0)) {
            res->canary_enabled = true;
        }

        // Check for canary validation (x86)
        if (strstr(insn[i].op_str, "gs:[0x28]") && strcmp(insn[i].mnemonic, "xor") == 0) {
            res->canary_enabled = true;
        }

        if (strstr(insn[i].op_str, "gs:[0x14]") && strcmp(insn[i].mnemonic, "xor") == 0) {
            res->canary_enabled = true;
        }


```
Since the canary is a very unique data type that resides in a particual 
area of memory, its easy to fingerprint its movement around in the program,
without even having access to function symbols.
99% of the time, if a datatype that looks like a canary is being moved
around, its a canary.
#### Optional method 3
```c
        // ARM64 stack canary detection for iOS devices
        // Look for stack canary loading from thread pointer
        if ((strcmp(insn[i].mnemonic, "ldr") == 0 || strcmp(insn[i].mnemonic, "ldur") == 0) &&
            (strstr(insn[i].op_str, "x18") || strstr(insn[i].op_str, "tpidr_el0"))) {
            res->canary_enabled = true;
        }

        // ARM32 stack canary patterns
        if ((strcmp(insn[i].mnemonic, "ldr") == 0) &&
            (strstr(insn[i].op_str, "pc") && strstr(insn[i].op_str, "___stack_chk_guard"))) {
            res->canary_enabled = true;
        }

        // Check for calls to ___stack_chk_fail (both x86 and ARM)
        if ((strcmp(insn[i].mnemonic, "call") == 0 || strcmp(insn[i].mnemonic, "bl") == 0) && 
            strstr(insn[i].op_str, "___stack_chk_fail")) {
            res->canary_enabled = true;
        }
    }
```
Arm has special mnemonics for calling and reading canaries, since its a more modern
architecture built with security in mind.
usually when you see these mnemonics, interacting with registers
that are desginated for storing canaries, its probably a canary being handled.

## PIE
### What is PIE
PIE, or position independant executable,
is another mitigation commonly found on most operating systems.
The idea is to randomize where program functions are located in memory, during runtime.
This is done to prevent an attacker that might have a stack buffer overflow primitive, 
from having the ability to easily modify the control flow of the program
to suddenly redirect exeuciton to another function.
This is done via randomization, making it so that the attacker either has to 
leak what the address of a function hes interested in is, or via guessing which is
VERY HARD to do.

Heres what a program with and without pie looks like
{{< figure src="/images/after_pie.png" width="80%" >}}
Where 0x40080 is the address before pie, and will always be
0x40080.
And 0x00080 is the address after pie,
where the first few zeros will be randomized at runtime.
The offset is the 80.

### Detecting PIE
Detecting PIE is done via parsing the headers of the machO
binary.
The headers of the binary are essentially metada about the binary.
The metadata being stuff like:
* binary type (ELF/MachO)
* binary architecture (arm/x86)
* which mitigations are enabled (PIE, or NX)
Just by parsing the headers, we can glean a bunch
of info on the binary.
The Mach-O header structure looks like this:

  Key Information:

  1. Magic Numbers: The first 4 bytes identify the file type:
    - 0xfeedface (32-bit Mach-O)
    - 0xfeedfacf (64-bit Mach-O)
    - 0xcafebabe (fat binary containing multiple architectures)
  2. Header Structure (32-bit = 28 bytes, 64-bit = 32 bytes):
```c
  struct mach_header_64 {
      uint32_t magic;      // 0x00: Magic number
      uint32_t cputype;    // 0x04: CPU architecture
      uint32_t cpusubtype; // 0x08: CPU variant
      uint32_t filetype;   // 0x0C: Executable, library, etc.
      uint32_t ncmds;      // 0x10: Number of load commands
      uint32_t sizeofcmds; // 0x14: Size of load commands
      uint32_t flags;      // 0x18: FLAGS INCLUDING MH_PIE!
      uint32_t reserved;   // 0x1C: (64-bit only)
  };
```
  3. PIE Detection: The MH_PIE flag is located in the flags field at offset 0x18. Its value is 0x00200000. When this bit is set, it indicates the binary supports Position Independent Execution.
  4. Detection Process in machsec
```c

bool detect_pie(struct DetectionResults *res, macho_t *macho) {
    uint32_t flags = macho->is_64bit ? macho->header->flags : ((struct mach_header *)macho->data)->flags;
    
    if (flags & MH_PIE) {
        res->pie_enabled = true;
        res->pie_text = "PIE enabled";
        res->pie_status = 0;
        res->pie_color = COLOR_GREEN;
        return true;
    } else {
        res->pie_enabled = false;
        res->pie_text = "No PIE";
        res->pie_status = 2;
        res->pie_color = COLOR_RED;
        return false;
    }
}
```
## No eXecute (NX)
### Whats NX?
NX or no execute is another mitigation, where we mark the 
stack/heap reigion as a non executable area of memory.
The reason this is done, is becauase
attackers used to be able to for example,
abuse a buffer overflow to write a bunch of malicious program logic
(straight up native assembly to the stack) and then just tell the program
to execute the data in the stack memory reigion.
The NX mitigation just straight up marks the entire memory reigion as a read/write memory
region ONLY, meaning attackers can no longer place malicious assembly code on the stack, redirect
execution to it, and expect it to run.
### Detecting NX
In order to detect NX, machsec does the following for the heap and the stack:
1. NX Heap (detect_nx_heap):
    - Looks for __HEAP segment
    - Falls back to SEG_DATA segment if no heap segment
    - Checks if VM_PROT_EXECUTE (0x04) bit is set in initprot
  2. NX Stack (detect_nx_stack):
    - Looks for __STACK segment
    - Checks if VM_PROT_EXECUTE bit is set in initprot
    - Assumes NX enabled if no explicit stack segment (modern macOS default)

And heres how its implemented in the code of machsec, for the stack and the heap respectivley.
Stack:
```c

    // Check stack segments for NX protection
    struct segment_command_64 *stack_seg = macho_find_segment(macho, "__STACK");
    
    bool stack_nx = true;
    
    // Check if stack segment exists and is executable (bad for NX)
    if (stack_seg && (stack_seg->initprot & VM_PROT_EXECUTE)) {
        stack_nx = false;
    }
```
Heap:
```c
    // Check heap segments for NX protection
    struct segment_command_64 *data_seg = macho_find_segment(macho, SEG_DATA);
    struct segment_command_64 *heap_seg = macho_find_segment(macho, "__HEAP");
    
    bool heap_nx = true;
    
    // Check if heap segment exists and is executable (bad for NX)
    if (heap_seg && (heap_seg->initprot & VM_PROT_EXECUTE)) {
        heap_nx = false;
    }
    
    // If no explicit heap segment, check data segment (where heap allocations often go)
    if (!heap_seg && data_seg && (data_seg->initprot & VM_PROT_EXECUTE)) {
        heap_nx = false;
    }
```
## RPATH/RUNPATH
### What is rpath/runpath
Rpath and runpath are the paths where libraries reside on them system,
for the program to use and load, **at runtime**.
The reason these are dangerous is due to the fact an attacker could replace these libraries
with modified libraries and thus control code execution, if the paths
defined are areas where the attacker can write code (the same dir as the binary, folders shared amongst users, etc).
### How to detect rpath/runpath
Detection Process

  1. Iterate Through Load Commands

```c
  struct load_command *cmd = macho->load_commands;
  uint32_t ncmds = macho->is_64bit ? macho->header->ncmds : ((struct mach_header *)macho->data)->ncmds;

  for (uint32_t i = 0; i < ncmds; i++) {

  // The tool walks through all load commands in the Mach-O binary header.

  2. Check for LC_RPATH Commands

  if (cmd->cmd == LC_RPATH) {
      has_rpath = true;
  }
```

  When it finds an LC_RPATH load command, it sets has_rpath = true. This indicates the binary has embedded library search paths.

  3. Check for @rpath Usage in Library Dependencies

```c
  else if (cmd->cmd == LC_LOAD_DYLIB) {
      struct dylib_command *dylib = (struct dylib_command *)cmd;
      char *path = (char *)dylib + dylib->dylib.name.offset;
      if (strstr(path, "@rpath")) {
          has_runpath = true;
      }
  }
```

  For each LC_LOAD_DYLIB command (library dependency), it:
  - Extracts the library path string
  - Checks if the path contains @rpath using strstr()
  - If found, sets has_runpath = true

  What It's Actually Looking For

  1. LC_RPATH entries: Hardcoded search paths like /usr/local/lib, /opt/lib, etc.
  2. @rpath placeholders: Library paths like @rpath/MyFramework.framework/MyFramework

  Example Mach-O Structure

```asm
  Load Commands:
  ├── LC_RPATH: /usr/local/lib        ← Detected as RPATH
  ├── LC_LOAD_DYLIB: @rpath/lib.dylib ← Detected as @rpath usage  
  └── LC_LOAD_DYLIB: /usr/lib/libc.dylib ← Safe, ignored
```
## RELRO
### What is relro
relro, or relocation read only is a mitigation that marks interesting
areas of binary space as read only.
Heres how ctf101.org defines it:

"Relocation Read-Only (or RELRO) is a security measure which makes some binary sections read-only.

There are two RELRO "modes": partial and full.

Partial RELRO
Partial RELRO is the default setting in GCC, and nearly all binaries you will see have at least partial RELRO.

From an attackers point-of-view, partial RELRO makes almost no difference, other than it forces the GOT to come before the BSS in memory, eliminating the risk of a buffer overflows on a global variable overwriting GOT entries.

Full RELRO
Full RELRO makes the entire GOT read-only which removes the ability to perform a "GOT overwrite" attack, where the GOT address of a function is overwritten with the location of another function or a ROP gadget an attacker wants to run.

Full RELRO is not a default compiler setting as it can greatly increase program startup time since all symbols must be resolved before the program is started. In large programs with thousands of symbols that need to be linked, this could cause a noticable delay in startup time. "

What is the GOT? the Global offset Table is a special table that tells the binary where to look up functions from
other libraries.
If an attacker overwrites the entries in this table, they could replace the address of printf() with the address
of any functiony they like, so that the next time printf() is called, their function is called.
### How to detect relro
Just need to read the initprot section of the machO binary.
```c
 // Case 1: Partial RELRO
  if (data_seg && (data_seg->initprot & VM_PROT_WRITE) && !(data_seg->maxprot & VM_PROT_WRITE)) {
      res->relro_text = "Partial RELRO (read-only data)";
      res->relro_status = 1;  // YELLOW
      res->relro_color = COLOR_YELLOW;
  }

  // Case 2: No RELRO  
  else if (data_seg && (data_seg->initprot & VM_PROT_WRITE)) {
      res->relro_text = "No RELRO";
      res->relro_status = 2;  // RED
      res->relro_color = COLOR_RED;
  }

  // Case 3: Unknown
  else {
      res->relro_text = "RELRO unknown";
      res->relro_status = 1;  // YELLOW
      res->relro_color = COLOR_YELLOW;
  }
```

---
## FORTIFY
### What is fortify?
Foritfy is a compiler flag to replace common memory unsafe functions
with functions that have bounds checking.
This mitigation is purely compiler level, and was created by the GNU compiler
later adopted by clang.
The main functions it targets are stuff like ``memcpy()`` and ``memmove()``.
Its a relativley weak mitigation, but still something to be aware of.
### How to detect fortify
This mitigation modifies the way the functions work, which means the way
the code looks at the assembly level is also different from a binary that was
compiled withthout this mitigation.
{{< figure src="/images/foritfy.png" width="80%" >}}
As you can see, the memory unsafe functions like memcpy are now called
``__memcpy_chk()``. Essentially meaning the memcpy function was replaced
on the linking level with a more secure version.
If we just look for these symbols, we can detect this mitigation.
And heres what the code for the detection mechanism looks like:
```c
bool detect_fortify(struct DetectionResults *res, macho_t *macho) {
    struct symtab_command *symtab = macho_get_symtab(macho);
    if (!symtab) {
        res->fortify_text = "No symbols";
        res->fortify_status = 1;
        res->fortify_color = COLOR_YELLOW;
        res->fortified_count = 0;
        return false;
    }
    
    struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
    char *strings = (char *)macho->data + symtab->stroff;
    
    int fortified_count = 0;
    const char *fortified_functions[] = {
        "memcpy_chk", "strcpy_chk", "strcat_chk", "sprintf_chk", "snprintf_chk",
        "vsprintf_chk", "vsnprintf_chk", "gets_chk", "fgets_chk", "memset_chk",
        "stpcpy_chk", "stpncpy_chk", "strncpy_chk", "strncat_chk", "vprintf_chk",
        "printf_chk", "fprintf_chk", "vfprintf_chk", "read_chk", "recv_chk",
        "recvfrom_chk", "readlink_chk", "getwd_chk", "realpath_chk", "wctomb_chk",
        "wcstombs_chk", "mbstowcs_chk", "mbsrtowcs_chk", "wcrtomb_chk", "wcsrtombs_chk"
    };
    
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
            char *name = strings + symbols[i].n_un.n_strx;
            
            // Remove leading underscore if present (common in Mach-O)
            if (name[0] == '_') name++;
            
            // Check against known fortified functions
            for (size_t j = 0; j < sizeof(fortified_functions) / sizeof(fortified_functions[0]); j++) {
                if (strstr(name, fortified_functions[j])) {
                    fortified_count++;
                    break;  // Don't double-count the same symbol
                }
            }
        }
    }
    
    res->fortified_count = fortified_count;
    
    if (fortified_count > 0) {
        char *text_buffer = malloc(64);
        if (text_buffer) {
            snprintf(text_buffer, 64, "FORTIFY enabled (%d functions)", fortified_count);
            res->fortify_text = text_buffer;
        } else {
            res->fortify_text = "FORTIFY enabled";
        }
        res->fortify_status = 0;
        res->fortify_color = COLOR_GREEN;
        return true;
    }
    
    res->fortify_text = "No FORTIFY";
    res->fortify_status = 2;
    res->fortify_color = COLOR_RED;
    return false;
}
```

## UBSAN (Undefined behaviour sanitizer)
### What is UBSAN?
UBSAN is a compiler level mitigation that 
introduces more checks into the program similarly to stack canaries
(We mitigate against exploits by adding checking functions into the code)
UBsan aims to catch undefined behaviors like integer bugs (int overflow, int underflow
signedness bugs).
Amongst other things.
### How to detect ubsan?
{{< figure src="/images/ubsan.png" width="80%" >}}
As you can see, we get a new function inserted into our code,
all we have to do is look for this symbol, and then we will know if ubsan is enabled or not.
Very similar idea to how detecting fortify works.
```c
bool detect_ubsan(struct DetectionResults *res, macho_t *macho) {
    struct symtab_command *symtab = macho_get_symtab(macho);
    if (!symtab) {
        res->ubsan_text = "No symbols";
        res->ubsan_status = 1;
        res->ubsan_color = COLOR_YELLOW;
        return false;
    }
    
    struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
    char *strings = (char *)macho->data + symtab->stroff;
    
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
            char *name = strings + symbols[i].n_un.n_strx;
            
            if (strstr(name, "__ubsan") || strstr(name, "__sanitizer") || strstr(name, "_ubsan_handle")) {
                res->ubsan_text = "UBSan enabled";
                res->ubsan_status = 0;
                res->ubsan_color = COLOR_GREEN;
                return true;
            }
        }
    }
    
    res->ubsan_text = "No UBSan";
    res->ubsan_status = 2;
    res->ubsan_color = COLOR_RED;
    return false;
}
```
## ASAN (Address Sanitizer)
### What is ASAN?
The address sanitizer mitigation is primarily used in conjunction with
fuzzers to try and spot vulnerabilities like the powerful OOBW (Out of Bounds Write)
exploit primitive.
It works in much the same way as the previously discussed mitigations, and can be enabled
with a compiler flag.
However, the tradeoff to using this mitigation is huge since it adds a bunch of checks and functions to the
program, which significatly reduces the performance of the program.
### Detecting ASAN
Detecting ASAN works in much the same way as the previously discussed mitigations
Heres what a binary with the asan checks looks like:
{{< figure src="/images/asan.png" width="80%" >}}
As you can see, a bunch of asan functions get added.
And heres how the code detects asan:
```c
bool detect_asan(struct DetectionResults *res, macho_t *macho) {

    struct symtab_command *symtab = macho_get_symtab(macho);
    if (!symtab) {
        res->asan_text = "No symbols";
        res->asan_status = 1;
        res->asan_color = COLOR_YELLOW;
        return false;
    }
    
    struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
    char *strings = (char *)macho->data + symtab->stroff;
    
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
            char *name = strings + symbols[i].n_un.n_strx;
            
            if (strstr(name, "__asan") || strstr(name, "__sanitizer_cov") || strstr(name, "__interceptor_malloc")) {
                res->asan_text = "ASAN enabled";
                res->asan_status = 0;
                res->asan_color = COLOR_GREEN;
                return true;
            }
        }
    }
    
    res->asan_text = "No ASAN";
    res->asan_status = 2;
    res->asan_color = COLOR_RED;
```
## CFI (Control Flow Integrity)
### What is CFI?
CFI is an attempt at ensuring a programs proper control flow via in program checks much like 
the functions we have seen inserted into programs as part of other mitigations like UBSAN, ASAN
and canaries.
This is the most **costly** software mitigation of them all, since it will massivley increase the binary
size, and the performance pentalty is huge.
Unfortunatley, this mitigation mostly applies to Linux/ELF binaries, since modern macos/xnu machines
just use PAC, which is a hardware based implementation of control flow integrity, which I will discuss later in the post.
### Detecting CFI
Detecting CFI works much like detecting the other previous instrumentation based mitigations, we just read the symbols
from the binary... and were done.
```c
bool detect_cfi(struct DetectionResults *res, macho_t *macho) {
    // CFI is less common on macOS, check for symbols
    struct symtab_command *symtab = macho_get_symtab(macho);
    if (!symtab) {
        res->cfi_text = "No symbols";
        res->cfi_status = 1;
        res->cfi_color = COLOR_YELLOW;
        return false;
    }
    
    struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
    char *strings = (char *)macho->data + symtab->stroff;
    
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
            char *name = strings + symbols[i].n_un.n_strx;
            
            if (strstr(name, "__cfi") || strstr(name, "_cfi_") || strstr(name, "cfi_check")) {
                res->cfi_text = "CFI enabled";
                res->cfi_status = 0;
                res->cfi_color = COLOR_GREEN;
                return true;
            }
        }
    }
    
    res->cfi_text = "No CFI";
    res->cfi_status = 2;
    res->cfi_color = COLOR_RED;
```
## Symbols (Symbol Stripping)
### What is symbol stripping
Symbol stripping is not a mitigation per se, but a redaction of information that makes life for
reverse engineers harder.
When you give a function a name in a piece of code, the compiler doesnt really care/need the function
name in order to use the function, just a memory address of where that function is.
We humans however really need function names since they help us understand what the function does
at a glance without having to read the fun code.
Most programs will have their symbols removed so that a reverse engineer will not have the function names,
and be left with rather puzzling function names like ``func_1234()`` the names of the functions
generated obviously depend on your decompiler of choice.
### Detecting symbol stripping
We detect symbol stripping via detecting if there are no symbols present, which is quite funny since most
mitigations we look for something that exists in the binary, but this one, we look for the nonpresence of something.
You can tell how many symbols are in a binary, aswell as how many symbols are in the binary total, by just reading
the binary headers and metadata
```c
bool detect_symbols(struct DetectionResults *res, macho_t *macho) {
    struct symtab_command *symtab = macho_get_symtab(macho);
    
    if (!symtab || symtab->nsyms == 0) {
        res->symbols_text = "Fully stripped (0 symbols)";
        res->symbols_status = 0;
        res->symbols_color = COLOR_GREEN;
        return false;
    }
    
    // Count different types of symbols
    struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
    uint32_t local_syms = 0, external_syms = 0, undef_syms = 0;
    
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        if (symbols[i].n_type & N_EXT) {
            external_syms++;
        } else if ((symbols[i].n_type & N_TYPE) == N_UNDF) {
            undef_syms++;
        } else {
            local_syms++;
        }
    }
    
    char *text_buffer = malloc(128);
    if (!text_buffer) {
        res->symbols_text = "Memory error";
        res->symbols_status = 1;
        res->symbols_color = COLOR_YELLOW;
        return false;
    }
    
    if (local_syms > 0) {
        snprintf(text_buffer, 128, "Not stripped (%d symbols)", symtab->nsyms);
        res->symbols_text = text_buffer;
        res->symbols_status = 2;
        res->symbols_color = COLOR_RED;
        return true;
    } else if (external_syms > 0 || undef_syms > 0) {
        snprintf(text_buffer, 128, "Partially stripped (%d symbols)", external_syms + undef_syms);
        res->symbols_text = text_buffer;
        res->symbols_status = 1;
        res->symbols_color = COLOR_YELLOW;
        return true;
    } else {
        snprintf(text_buffer, 128, "Fully stripped (0 symbols)");
        res->symbols_text = text_buffer;
        res->symbols_status = 0;
        res->symbols_color = COLOR_GREEN;
        return false;
    }
}
```
## Stack Clashing
### What is stack clashing?
Stack clashing is a very rare and recent exploit method that attempts
to make the stack region and the heap region of the program to intersect thus corrupting
the integral data that lives on the stack, stuff like function pointers, variables, etc.
### Detecting stack clashing
Detecting stack clashing, like most mitigations, is just a bunch of instrumentation the
compiler adds, a bunch of functions to check that the stack region hasnt intersected into
the heap region.
Since its not really a thing on macOS/xnu, we can just assume that if canaries are present,
that check is also probably present.

## Heap cookies
### What are heap cookies?
Heap cookies are the same thing as stack canaries, but in the heap.
They check that heap chuncks havent been overflown.
### Detecting heap cookies
Detecting heap cookies can be done by checking the symbols in the binary.
Heres how to detect them:
```c
bool detect_heap_cookies(struct DetectionResults *res, macho_t *macho) {
    struct symtab_command *symtab = macho_get_symtab(macho);
    if (!symtab) {
        res->heap_cookies_text = "No symbols";
        res->heap_cookies_status = 1;
        res->heap_cookies_color = COLOR_YELLOW;
        return false;
    }
    
    struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
    char *strings = (char *)macho->data + symtab->stroff;
    
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
            char *name = strings + symbols[i].n_un.n_strx;
            
            if (strstr(name, "malloc_zone") || strstr(name, "guard_malloc") || strstr(name, "_malloc_check")) {
                res->heap_cookies_text = "Heap hardening enabled";
                res->heap_cookies_status = 0;
                res->heap_cookies_color = COLOR_GREEN;
                return true;
            }
        }
    }
    
    res->heap_cookies_text = "No heap hardening";
    res->heap_cookies_status = 2;
    res->heap_cookies_color = COLOR_RED;
    return false;
}
```
## Integer overflow
### What is Integer overflow
Integer overflow protection is another instrumentation based mitigation, where we add a bunch of functions
to the program to make sure that integers have not exceeded their limits and wrapped around to another value.
### Detecting Integer Overflow
Quite like the other mitigations, you can just check for the presence of certain symbols:
```c
bool detect_integer_overflow(struct DetectionResults *res, macho_t *macho) {
    struct symtab_command *symtab = macho_get_symtab(macho);
    if (!symtab) {
        res->integer_overflow_text = "No symbols";
        res->integer_overflow_status = 1;
        res->integer_overflow_color = COLOR_YELLOW;
        return false;
    }
    
    struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
    char *strings = (char *)macho->data + symtab->stroff;
    
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
            char *name = strings + symbols[i].n_un.n_strx;
            
            if (strstr(name, "__muloti4") || strstr(name, "__addoti4") || 
                strstr(name, "__ubsan_handle_add_overflow") || strstr(name, "__wrap_")) {
                res->integer_overflow_text = "Integer overflow protection enabled";
                res->integer_overflow_status = 0;
                res->integer_overflow_color = COLOR_GREEN;
                return true;
            }
        }
    }

```
## Sandbox (XNU exclusive)
### What is sandboxing?
In general, sandboxing is creating a restricted environment where a binary has limited
access to the underlying operating system.
In the case of XNU and mitigations, this mitigation does a couple of things:
* Filter syscalls (A bit like seccomp on linux) using a kernel feature called seatbelt
* Check entitlements (what is the binary allowed to access, what kind of hardware etc...)
* Apply a sandboxing profile based on the entitlements and the syscalls being filtered.
### Detecting sandboxing
We can detect sandboxing either via the symbols present, by checking if the binary is signed, which is also
a strong indicator that the binary is sandboxed, and also checking for strings that have to do with entitlements.
```c
bool detect_sandbox(struct DetectionResults *res, macho_t *macho) {
    bool has_sandbox_symbols = false;
    bool has_code_signature = false;
    bool has_entitlements = false;
    
    // Check for sandboxing symbols
    struct symtab_command *symtab = macho_get_symtab(macho);
    if (symtab) {
        struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
        char *strings = (char *)macho->data + symtab->stroff;
        
        for (uint32_t i = 0; i < symtab->nsyms; i++) {
            if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
                char *name = strings + symbols[i].n_un.n_strx;
                
                // Check for macOS/iOS sandboxing symbols
                if (strstr(name, "sandbox_") || 
                    strstr(name, "_sandbox_init") ||
                    strstr(name, "sandbox_check") ||
                    strstr(name, "sandbox_free_error") ||
                    strstr(name, "container_") ||
                    strstr(name, "_container_create")) {
                    has_sandbox_symbols = true;
                    break;
                }
            }
        }
    }
    
    // Check for code signature and entitlements
    struct load_command *cmd = macho->load_commands;
    uint32_t ncmds = macho->is_64bit ? macho->header->ncmds : ((struct mach_header *)macho->data)->ncmds;
    
    for (uint32_t i = 0; i < ncmds; i++) {
        if (cmd->cmd == LC_CODE_SIGNATURE) {
            has_code_signature = true;
            
            // Try to parse the code signature for entitlements
            struct linkedit_data_command *sig_cmd = (struct linkedit_data_command *)cmd;
            
            // Look for entitlement data in the signature
            if (sig_cmd->datasize > 0) {
                char *sig_data = (char *)macho->data + sig_cmd->dataoff;
                
                // Look for common sandbox entitlement strings
                if (sig_cmd->datasize > 20) {  // Minimum size check
                    // Search for sandbox-related entitlement keys
                    if (search_memory(sig_data, sig_cmd->datasize, "com.apple.security.app-sandbox", 31) ||
                        search_memory(sig_data, sig_cmd->datasize, "platform-application", 20) ||
                        search_memory(sig_data, sig_cmd->datasize, "sandbox", 7)) {
                        has_entitlements = true;
                    }
                }
            }
        }
        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }
    
    // Determine sandbox status based on evidence
    if (has_sandbox_symbols) {
        res->sandbox_text = "Sandbox enabled (symbols)";
        res->sandbox_status = 0;
        res->sandbox_color = COLOR_GREEN;
        return true;
    } else if (has_entitlements) {
        res->sandbox_text = "Sandbox enabled (entitlements)";
        res->sandbox_status = 0;
        res->sandbox_color = COLOR_GREEN;
        return true;
    } else if (has_code_signature) {
        // Check if this is a system binary (likely sandboxed)
        uint32_t flags = macho->is_64bit ? macho->header->flags : ((struct mach_header *)macho->data)->flags;
        if (flags & MH_PIE) {  // System binaries are typically PIE
            res->sandbox_text = "Likely sandboxed (system binary)";
            res->sandbox_status = 1;
            res->sandbox_color = COLOR_YELLOW;
            return true;
        } else {
            res->sandbox_text = "Code signed (may be sandboxed)";
            res->sandbox_status = 1;
            res->sandbox_color = COLOR_YELLOW;
            return true;
        }
    } else {
        res->sandbox_text = "No sandbox";
        res->sandbox_status = 2;
        res->sandbox_color = COLOR_RED;
        return false;
    }
}
```
## Hardened runtime + SIP  + AMFI (XNU Exclusive) 
This is a suite of operating system/binary level mitigations
unique to macOS, some of them even unique to only iOS
### What is Hardened runtime?
The hardened runtime is another mitigation set in place by XNU, set to mitigate against
library injection at runtime, debugging, injection of any unsigned code at runtime,
dynamic instrumentation, and the like, on a per process basis.
aswell as adding some unique runtime mitigations.
Heres a breakdown of some of the things it will do:
* ``CS_RESTRICT``, a machO header in the binary, part of the codesigning section of the binary metadata.
blocks ``task_for_pid()``, essentially making the program not attachable by debugger, unless they have the right entitlements
*  ``cs_kill`` kernel kills the process if ay any point during runtime signatures do not match
* Library validation checks that all binaries are signed and have not been modified.
* JIT Restricition - Just In Time compilation requries a memory region to be writeable & executable, which is a security risk. This mitigation will not allow ``mmap()``ing a memory region thats both write and execute, unless a specfici entitlement is set: ``com.apple.security.cs.allow-jit``
* Debugging - blocks ptrace() unless there is a specfic entitlement:
``com.apple.security.get-task-allow``
### What is SIP (System Integrity Protection)
SIP is a suite of these mitigations, that ensures the operating
system continues to operate whilst being resilient to malware, exploits, 
and a stupid user accidentally deleting their entire filesystem because someone told them to ``rm --rf /``
SIP can be disabled on macOS via the following command:
``csrutil -disable``
And is a must if you want to do any sort of offensive security like
dynamically instrumenting a program with FRIDA,
run a cracked program with the license validation libraries patched, etc.
### Binary Encryption (AMFI)
Apple Mobile File Inegrity or AMFI 
Is another mitigation that exists on XNU, specifically on iOS.
The mitigation consists of two components working in tandem:
* amfid (System Daemon)
* kernel module (AppleMobileFileIntegrity.kext)
Together these two preform the following functions
* Decrypt encrypted binaries:
Binaries have their ``__TEXT`` section encrypted, need to have the
section decrypted to run properly. 
The Mach-O header has a ``LC_ENCRYPTION_INFO`` load command with:
```md
cryptid=1 (encrypted)
cryptoff (offset to encrypted data)
cryptsize (size of encrypted region)
```
Where the kernel does the signature verification,
amfid verifies cert chains, provisioning profiles, etc.


### Detecting SIP/Hardened runtime
Detecting if SIP is enabled on the operating system level is out of the scope, of machsec, but its safe to assume every XNU based operating system will have it enabled by default.
However, not all binaries will have a hardened runtime enabled, so we can definetly check for that in the binary.
We can check for the headers in the binary, which tell the kernel how to handle the binary. The same information that helps the kernel, helps us.
```c
bool detect_hardened_runtime(struct DetectionResults *res, macho_t *macho) { // Check for LC_CODE_SIGNATURE load command (both macOS and iOS)
    struct load_command *code_sig = macho_find_command(macho, LC_CODE_SIGNATURE);
    
    // Also check for iOS-specific security features
    //uint32_t flags = macho->is_64bit ? macho->header->flags : ((struct mach_header *)macho->data)->flags;
    bool has_ios_security = false;
    
    // Check for iOS App Store binaries (encrypted)
    struct load_command *encryption = macho_find_command(macho, LC_ENCRYPTION_INFO);
    if (!encryption && macho->is_64bit) {
        encryption = macho_find_command(macho, LC_ENCRYPTION_INFO_64);
    }
    
    if (encryption) {
        has_ios_security = true;
    }
    
    if (code_sig || has_ios_security) {
        if (has_ios_security) {
            res->hardened_runtime_text = "iOS Security enabled";
        } else {
            res->hardened_runtime_text = "Hardened Runtime enabled";
        }
        res->hardened_runtime_status = 0;
        res->hardened_runtime_color = COLOR_GREEN;
        return true;
    } else {
        res->hardened_runtime_text = "No security hardening";
        res->hardened_runtime_status = 2;
        res->hardened_runtime_color = COLOR_RED;
        return false;
    }
}
```
## Code signing
### What is code signing?
Similarly to windows, binaries distributed by known organizations/companies can get a digital signature from Apple, that helps an apple device tell
if a piece of software is a genuine copy from the software vendor, if the piece of software has been tampered with, etc.
### How does code signing work?

Code signing appends a signature blob at the end of the binary,
and there's a CodeDirectory (a structure containing metadata like flags 
and an array of SHA256 hashes, one per 4KB page of executable code) with 
precomputed hashes of every page that will get loaded into the __TEXT segment.

At runtime, the kernel verifies pages lazily via page faults - when 
an executable page is first accessed, the kernel hashes it and compares 
against the CodeDirectory. If hashes don't match, the process is killed.

Note: Only the __TEXT segment (executable code) is signed. 
The following are NOT signed:
* Stack
* Heap  
* __DATA (writable data)
* __DATA_CONST (may be signed in some cases)
* __LINKEDIT
* Dynamically allocated memory

### Detecting code signing
Its once again as simple as just parsing the binary headers.
```c
bool detect_code_signing(struct DetectionResults *res, macho_t *macho) {
    struct load_command *code_sig = macho_find_command(macho, LC_CODE_SIGNATURE);
    
    if (code_sig) {
        res->code_signing_text = "Code signed";
        res->code_signing_status = 0;
        res->code_signing_color = COLOR_GREEN;
        return true;
    } else {
        res->code_signing_text = "Not code signed";
        res->code_signing_status = 2;
        res->code_signing_color = COLOR_RED;
        return false;
    }
}
```

## PAC (ARM Exclusive)
### What is PAC?
PAC or pointer authentication codes is a unique mitigation only available on ARM hardware.  
Its a mitigation that signs control-flow pointers (function pointers and return addresses) cryptographically, thus making control flow hijacking very hard.  
Since at the end of the day, most memory corruption attacks want to hijack the control flow of the program, this is one of the most powerful mitigations available to us on ARM-based platforms, which happen to be what Apple uses for their phones and recently, laptops.

### How does PAC Work?
PAC works by adding the following:  
* Custom Instructions to ARM assembly which preform the pointer auth.  
* Custom accelerator circuits into the processor to assist in the cryptographic calculations necessary for PAC to work. This helps the security feature not be a burden on performance.  
* Custom Registers to the CPU, where keys are stored. Each register is 128 bits in size and inaccessible to user code.  
* Custom Encryption - Uses a new method of hasing called QARMA designed specifically to be more fast, less secure.

PAC works by utilizing the unused bits of pointer addresses (no computer ever has 2^64, or 16 exabytes of memory).  
So by default, pointers look a little something like this:

``0x00000002fa89efa8zz``

Where there are a bunch of zeros that remain unused.  
PAC makes use of this to insert a little signature, so a signed pointer might look something like this:

``0xA123A312fa89efa8``


This hash gets computed using the following equation:

```math
truncate(hmac(key, ptr || context))
```
Where:

Truncate - we cannot fit the whole result into the few bits we have, so we truncate to the 16 or 24 bits available.

hmac - hash-based message authentication code.

key - secret key sitting in registers which can only be set by the kernel.

context - current value of the stack pointer, so that the function pointer can only be called within the context of the stackframe it resides in. This prevents just reusing a signed pointer from somewhere else in the program. The signed pointer will not work outside the proper stackframe (execution context); the signature calculated won’t match, and the process will crash.

However, it’s important to note that *PAC ONLY SIGNS INSTRUCTION POINTERS AND RETURN ADDRESSES (AND SOME BASIC VARIABLES)*.
Unfortunately, due to the way the C spec is defined, it’s impossible to sign all the pointers without completely breaking everything.
Since C allows you to do things like pointer arithmetic and interact with pointers as a datatype, any interaction with a pointer as a datatype would cause an exception in the way PAC works.

Thus, only pointers that are generally not going to be messed around with by a C program, things like instruction pointers, we can safely sign them, since they are not going to be modified intentionally by program logic.

### Detecting PAC
Heres a picture of what PAC looks like in a program (``/bin/ls``).
{{< figure src="/images/pac.png" width="80%" >}}
As you can see, we get new cool arm instructions like
*  PACZIA (Sign pointer with context of "0")
*  AUTIBSP (Auth Pointer using key B)

So the detection mechanism just needs to detect the new instructions.
Or if the dissassembler hasnt been updated with handling these new instrucitons, we can just resort back to symbols.
```c
bool detect_pac(struct DetectionResults *res, macho_t *macho) {
    // PAC (Pointer Authentication Code) is available on ARM64 devices
    uint32_t cputype = macho->is_64bit ? macho->header->cputype : ((struct mach_header *)macho->data)->cputype;
    
    // PAC is only available on ARM64
    if (cputype != CPU_TYPE_ARM64) {
        res->pac_text = "N/A (not ARM64)";
        res->pac_status = 1;
        res->pac_color = COLOR_YELLOW;
        return false;
    }
    
    // Check for PAC-related symbols
    struct symtab_command *symtab = macho_get_symtab(macho);
    if (symtab) {
        struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
        char *strings = (char *)macho->data + symtab->stroff;
        
        for (uint32_t i = 0; i < symtab->nsyms; i++) {
            if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
                char *name = strings + symbols[i].n_un.n_strx;
                
                // Check for PAC-related symbols
                if (strstr(name, "_ptrauth") || 
                    strstr(name, "pac_") ||
                    strstr(name, "_auth_") ||
                    strstr(name, "pointer_auth")) {
                    res->pac_text = "PAC enabled";
                    res->pac_status = 0;
                    res->pac_color = COLOR_GREEN;
                    return true;
                }
            }
        }
    }
    
    // Check CPU subtype for PAC capability
    uint32_t cpusubtype = macho->is_64bit ? macho->header->cpusubtype : ((struct mach_header *)macho->data)->cpusubtype;
    
    // Mask out feature flags to get the actual subtype
    uint32_t actual_subtype = cpusubtype & ~CPU_SUBTYPE_MASK;
    
    // Apple Silicon and newer ARM64 chips support PAC
    if (actual_subtype == CPU_SUBTYPE_ARM64E) {
        // Check if this binary has the PAC ABI flag set
        if (cpusubtype & CPU_SUBTYPE_PTRAUTH_ABI) {
            res->pac_text = "PAC enabled (ARM64E with PtrAuth ABI)";
        } else {
            res->pac_text = "PAC capable (ARM64E)";
        }
        res->pac_status = 0;
        res->pac_color = COLOR_GREEN;
        return true;
    } else if (actual_subtype == CPU_SUBTYPE_ARM64_V8) {
        res->pac_text = "PAC capable (ARM64)";
        res->pac_status = 0;
        res->pac_color = COLOR_GREEN;
        return true;
    }
    
    // Default: ARM64 device but no PAC detected
    res->pac_text = "No PAC detected";
    res->pac_status = 2;
    res->pac_color = COLOR_RED;
    return false;
}
```
MTE (ARM Exclusive)

## What is EMTE/MTE/MIE

MTE or Memory Tagging Extension is a brand new mitigation (as of time of writing) that Apple/ARM developed to protect the pointers that PAC cannot. They both use the principle that there are unused bits in each pointer's address we can utilize, but that's about where the similarities end.

## How MTE Works

A randomly generated 4-bit tag from hardware RNG is added to both the pointer and stored in tag memory for that allocation. Let's give a practical example of how MTE would stop a UAF Bug. Here's our piece of code:
```c
char *ptr = malloc(64); // alloc chunk on heap size 64
ptr[0] = 'A'; // set value
free(ptr); //mark chunk as empty
ptr[0] = 'B';  // UAF bug (continuing the use of the chunk after it was freed, could be populated with anything now...)
```

Here's what's happening on the assembly level:
```asm
MOV x0, #64 // move size 64 to argument register for malloc()
BL malloc // call function malloc
```

This is our chunk allocation. Let's assume everything worked and we get the following heap address `0x0000001234567890`, moved into register `x0`.
```asm
IRG x0, x0
```

IRG stands for "Insert Random Tag", this is the part that generates the random tag, and puts it in the unused bits of our pointer.
Here's what our pointer looks like now:
```
0x0300001234567890
```

Now, we need to tag the memory itself.
```asm
STG x0, [x0]
```

This is accomplished by writing the tag to a special section of RAM metadata called tag memory, that's separate from the memory accessible to userspace. Tag memory at address `0x1234567890` now stores tag `3`.

Now let's write to the heap:
```asm
MOV w1, #'A'
STRB w1, [x0]
```

Now that we wrote A to the memory area tagged with 3, everything is ready! Let's see what happens when we free:
```asm
IRG x1, x0          ; generate new random tag in x1
STG x1, [x0]        ; write new tag to tag memory
BL free
```

A few things just happened:
* The memory allocation is marked as free.
* The tagged pointer to the chunk, `0x0300001234567890` remains the same.
* Tag memory at address `0x1234567890` gets rewritten with a new random tag, for example, `0xA`.

Now let's see what happens when the UAF is happening on the assembly level.
```asm
MOV w1, #'B'
STRB w1, [x0]
```

The `STRB` alongside other instructions like `LDR` automagically perform the tag check in the background. As you can see, in the UAF, there is no tag generation. And the old tag that was assigned to that heap chunk no longer matches the tag in the pointer. STRB instruction will now crash due to tag mismatch with a synchronous exception.

### Detecting MTE
Detecting MTE took a bit work research, since, its a new mitigtation.
I had to extract the JavaScriptCore engine from iOS 26.1 on the new iphone since that the only thing that has that mitigation right now.
```c
bool detect_mie(struct DetectionResults *res, cs_insn *insn, size_t count, macho_t *macho) {
    // MIE (Memory Integrity Enforcement) / EMTE (Enhanced Memory Tagging Extension)
    // is only available on ARM64 devices
    uint32_t cputype = macho->is_64bit ? macho->header->cputype : ((struct mach_header *)macho->data)->cputype;

    if (cputype != CPU_TYPE_ARM64) {
        res->mie_text = "N/A (not ARM64)";
        res->mie_status = 1;
        res->mie_color = COLOR_YELLOW;
        return false;
    }

    bool has_mte_instructions = false;
    bool has_mte_symbols = false;
    int mte_instruction_count = 0;

    // Check for MTE/EMTE instructions in disassembly
    if (insn && count > 0) {
        for (size_t i = 0; i < count; i++) {
            // Check for MTE-specific ARM64 instructions
            // IRG - Insert Random Tag
            if (strcmp(insn[i].mnemonic, "irg") == 0) {
                has_mte_instructions = true;
                mte_instruction_count++;
            }
            // STG - Store Allocation Tag
            else if (strcmp(insn[i].mnemonic, "stg") == 0) {
                has_mte_instructions = true;
                mte_instruction_count++;
            }
            // ST2G - Store Allocation Tags (double)
            else if (strcmp(insn[i].mnemonic, "st2g") == 0) {
                has_mte_instructions = true;
                mte_instruction_count++;
            }
            // STZ2G - Store Allocation Tags and Zero (double)
            else if (strcmp(insn[i].mnemonic, "stz2g") == 0) {
                has_mte_instructions = true;
                mte_instruction_count++;
            }
            // STZG - Store Allocation Tag and Zero
            else if (strcmp(insn[i].mnemonic, "stzg") == 0) {
                has_mte_instructions = true;
                mte_instruction_count++;
            }
            // LDG - Load Allocation Tag
            else if (strcmp(insn[i].mnemonic, "ldg") == 0) {
                has_mte_instructions = true;
                mte_instruction_count++;
            }
            // ADDG - Add with Tag
            else if (strcmp(insn[i].mnemonic, "addg") == 0) {
                has_mte_instructions = true;
                mte_instruction_count++;
            }
            // SUBG - Subtract with Tag
            else if (strcmp(insn[i].mnemonic, "subg") == 0) {
                has_mte_instructions = true;
                mte_instruction_count++;
            }
            // GMI - Tag Mask Insert
            else if (strcmp(insn[i].mnemonic, "gmi") == 0) {
                has_mte_instructions = true;
                mte_instruction_count++;
            }
            // SUBP/SUBPS - Subtract Pointer (used with MTE)
            else if (strcmp(insn[i].mnemonic, "subp") == 0 || strcmp(insn[i].mnemonic, "subps") == 0) {
                has_mte_instructions = true;
                mte_instruction_count++;
            }
        }
    }

    // Check for MTE/EMTE-related symbols
    struct symtab_command *symtab = macho_get_symtab(macho);
    if (symtab) {
        struct nlist_64 *symbols = (struct nlist_64 *)((char *)macho->data + symtab->symoff);
        char *strings = (char *)macho->data + symtab->stroff;

        for (uint32_t i = 0; i < symtab->nsyms; i++) {
            if (symbols[i].n_un.n_strx > 0 && symbols[i].n_un.n_strx < symtab->strsize) {
                char *name = strings + symbols[i].n_un.n_strx;

                // Check for MTE/EMTE-related symbols (be specific to avoid false positives)
                if (strstr(name, "_mte_") ||
                    strstr(name, "_emte_") ||
                    strstr(name, "memory_tagging") ||
                    strstr(name, "__hwasan") ||  // Hardware-assisted AddressSanitizer uses MTE
                    strstr(name, "hwaddress") ||
                    (strstr(name, "tagged") && strstr(name, "ptr")) ||  // tagged_ptr but not just any "tagged"
                    strstr(name, "_irg") ||  // MTE instruction functions
                    strstr(name, "_stg") ||
                    strstr(name, "_ldg") ||
                    strstr(name, "_addg") ||
                    strstr(name, "_subg")) {
                    has_mte_symbols = true;
                    break;
                }
            }
        }
    }

    // Determine MIE/EMTE status
    if (has_mte_instructions) {
        char *text_buffer = malloc(128);
        if (text_buffer) {
            snprintf(text_buffer, 128, "MIE/EMTE enabled (%d MTE instructions)", mte_instruction_count);
            res->mie_text = text_buffer;
        } else {
            res->mie_text = "MIE/EMTE enabled";
        }
        res->mie_status = 0;
        res->mie_color = COLOR_GREEN;
        return true;
    } else if (has_mte_symbols) {
        res->mie_text = "MIE/EMTE enabled (symbols)";
        res->mie_status = 0;
        res->mie_color = COLOR_GREEN;
        return true;
    } else {
        res->mie_text = "No MIE/EMTE detected";
        res->mie_status = 2;
        res->mie_color = COLOR_RED;
        return false;
    }
}
```
As you can see, I had to use a two pronged approach, looking for symbols
and the actual disassembly from the disassembler. 
This detection method is activley looking for instructions in arm64
that are related to memory tagging. These instructions are brand new, and thus some dissassemblers dont support them and cant parse them.
But this is the best method of detecting it.

## ARC (ObjectiveC)
### What is ARC?
ARC, or Automatic Reference Counting, is a mitigation available in the swift/objectiveC programming langs, that does referene counting
in order to make UAF's harder in objC and swift, since all of the higher level objects and datastructures let you create, are stored in the heap.
