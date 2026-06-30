---
title: "DirtySlide - root on macOS from one missing bounds check"
date: 2026-06-25T12:00:00Z
draft: false
category: "research"
image: "/images/dirtyslide/dirtyslide.png"
image_fit: "contain"
tags: ["xnu", "vulnerability", "privilege escalation", "macos"]
summary: "Unprivileged to root on macOS 26.5, no entitlements, Developer Mode off, through one unbounded loop in the dyld shared-cache slide walker. Fixed in macOS 26.5.2."
---

{{< figure src="/images/dirtyslide/dirtyslide.png" width="70%" align="center" >}}

> Note: This bug was disclosed to apple and someone had beat me to it. However, You might find the way I exploited it insightful. Exploit is VM only, due to SPTM/TXM locking page tables on physical Apple Silicon.

**PoC:** [github.com/gracecondition/DirtySlide](https://github.com/gracecondition/DirtySlide)

# One missing `if`

The bug is in `vm_shared_region_slide_page_v5()`, in `osfmk/vm/vm_shared_region.c`.

That function takes a page of the dyld shared cache and applies the ASLR slide to it. It walks a chain of pointers inside the page and rebases each one. Other places in XNU that walk an attacker-influenced chain like this check, on every step, that the pointer is still inside the page before they dereference it. The v4 path checks. The dyld chained-fixup pager checks. The v5 path does not.

## Why there are five of these

`vm_shared_region_slide_page()` is a dispatcher. It reads the `version` field from the cache's slide-info and calls one of five routines, `vm_shared_region_slide_page_v1()` through `..._v5()`:

```c
switch (si->si_slide_info_entry->version) {
case 1: return vm_shared_region_slide_page_v1(si, vaddr, pageIndex);
case 2: return vm_shared_region_slide_page_v2(si, vaddr, pageIndex);
case 3: return vm_shared_region_slide_page_v3(si, vaddr, uservaddr, pageIndex, jop_key);
case 4: return vm_shared_region_slide_page_v4(si, vaddr, pageIndex);
case 5: return vm_shared_region_slide_page_v5(si, vaddr, uservaddr, pageIndex, jop_key);
default: return KERN_FAILURE;
}
```

There are five because the format dyld uses to encode which words on a page are pointers, and how to get from one to the next, has changed across architectures and OS releases. The kernel has to handle every format a live cache might be built with:

- **v1**: a table-of-contents plus a bitmap marking which slots need sliding. No chaining.
- **v2**: compressed delta chains for 64-bit caches. Each page has a start offset, and each pointer's spare bits encode the delta to the next one.
- **v3**: the arm64e variant. It adds PAC-signed pointers, so chain entries carry ptrauth key and diversity metadata and the kernel re-signs each pointer as it rebases it.
- **v4**: a v2-shaped scheme for small (<= 1 GB) 32-bit caches, with narrower chains.
- **v5**: the modern arm64 format. Each slot is a `dyld_chained_ptr`-style word: a 34-bit runtime offset, an 8-bit high byte, an optional auth bit, and an 11-bit `next` field giving the 8-byte stride to the following pointer. This is the format whose `page_starts[]` and chain bytes the attacker supplies.

All five walk an attacker-influenced chain. The question is which of them check that the walk stays inside the page on each step. v1 through v4 and the chained-fixup pager do. v5 did not.

{{< mermaid >}}
flowchart TD
    D["vm_shared_region_slide_page()<br/>reads version, dispatches"]
    D --> V1["v1 · ToC + bitmap"]
    D --> V2["v2 · delta chains"]
    D --> V3["v3 · arm64e + PAC"]
    D --> V4["v4 · small 32-bit"]
    D --> V5["v5 · modern arm64"]
    V1 --> OK1["bound-checked ✓"]
    V2 --> OK2["bound-checked ✓"]
    V3 --> OK3["bound-checked ✓"]
    V4 --> OK4["bound-checked ✓"]
    V5 --> BAD["no page bound ✗<br/>walks off the page"]
    OK1 --> SAFE["stays inside the page"]
    OK2 --> SAFE
    OK3 --> SAFE
    OK4 --> SAFE
    BAD --> OOB["8-byte OOB read+write<br/>into the next frame"]
    style BAD fill:#5a1414,stroke:#ff5a5a,color:#ffd7d7
    style OOB fill:#5a1414,stroke:#ff5a5a,color:#ffd7d7
{{< /mermaid >}}

# What the slide walker is for

> New to the dyld shared cache? The primer is Apple's own source: the [dyld repository](https://github.com/apple-oss-distributions/dyld), and the [`dyld_cache_format.h`](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h) header, where every `dyld_cache_slide_info` version is defined.

When a process launches, dyld maps the shared cache (one blob of all the system libraries) and the kernel slides it to a random base. The pointers baked into the cache can't be absolute, so they are stored as a chain: each page carries a starting offset, and at that offset is a value whose high bits encode the distance to the next pointer to fix up. The kernel walks the chain, adds the slide amount to each pointer, and writes it back. When the chain ends, the page is done.

The metadata that drives this is the slide-info. Version 5 is the arm64 one, and its layout is what an unprivileged caller supplies. This is the real definition from `osfmk/vm/vm_shared_region_xnu.h`:

```c
struct vm_shared_region_slide_info_entry_v5 {
    uint32_t    version;        // currently 5
    uint32_t    page_size;      // 16384
    uint32_t    page_starts_count;
    uint64_t    value_add;
    uint16_t    page_starts[] /* page_starts_count */;
};
```

`page_starts[i]` is where the walk begins on page `i`. It is a raw `uint16_t` copied in from userspace.

# The guard that isn't there

This is the rebase loop, verbatim from the `xnu-12377.120.72` source (`vm_shared_region_slide_page_v5`, ptrauth bitfield comments removed for length):

```c
uint8_t* rebaseLocation = page_content;
uint64_t delta = page_entry;                 // page_starts[pageIndex], attacker-controlled u16
do {
    rebaseLocation += delta;
    uint64_t value;
    memcpy(&value, rebaseLocation, sizeof(value));
    delta = ((value & 0x7FF0000000000000ULL) >> 52) * sizeof(uint64_t);

    uint64_t    high8 = (value << 22) & 0xFF00000000000000ULL;
    bool        isAuthenticated = (value & (1ULL << 63)) != 0;

    value = (value & 0x3FFFFFFFFULL) + value_add + slide_amount;
    if (isAuthenticated) {
        /* ... PAC re-sign, then ... */
        memcpy(rebaseLocation, &value, sizeof(value));
    } else {
        value += high8;
        memcpy(rebaseLocation, &value, sizeof(value));
    }
} while (delta != 0);
```

`rebaseLocation` starts at `page_content`. The first `delta` is `page_starts[pageIndex]`, attacker-controlled. Every later `delta` is decoded from the eight bytes the loop just read, and those bytes live in the page I supplied, so they are attacker-controlled too. Nothing in the loop checks that `rebaseLocation` is still inside `[page_content, page_content + PAGE_SIZE)`.

So I can put the first hop near the end of the page, set a value whose high bits say "keep going", and the loop steps `rebaseLocation` past the page and does its read-modify-write in whatever kernel frame sits next door. That is an out-of-bounds read and write, 8 bytes at a time, into adjacent kernel memory, with the written value mostly under my control.

For comparison, the chained-fixup pager (`osfmk/vm/vm_dyld_pager.c`, `fixupPage64`) does the bound check, verbatim:

```c
if ((uintptr_t)chain < contents || (uintptr_t)chain + sizeof(*chain) > end_contents) {
    printf("%s(): chain 0x%llx out of range 0x%llx..0x%llx\n", __func__,
        (long long)chain, (long long)contents, (long long)end_contents);
    return KERN_FAILURE;
}
```

That is the bug. v5 was missing this `if`.

# Reaching the bug unprivileged

The first time I drove this path, it was through a route only the development kernel exposes. That proves the bug exists but says nothing about reachability on a stock machine, so on its own it is not an unprivileged bug. The part that makes it unprivileged came after: an ordinary, ad-hoc-signed, unentitled process can reach the same code by shimming out libSystem.

The slide walker is reachable from syscall `536`, `shared_region_map_and_slide_2_np`, in `bsd/vm/vm_unix.c`. There is no `suser` check, no `priv_check`, and no entitlement gate. It `copyin()`s the slide-info from the caller, and in the vulnerable build it only checks the structure, never the `page_starts[]` values against the page. Any process can call it.

There is one catch. `vm_shared_region_map_file()` only accepts a mapping into a region whose `sr_first_mapping == -1`, a fresh region that nothing has populated. A normally-launched process already inherited a cache-populated region, so its `536` bounces. I needed a process that reaches the syscall with a fresh region.

The way to do that is to make dyld never map the real cache. The PoC spawns its child with two shim dylibs, a hand-rolled `fake_libdyld.cpp` (just enough of the dyld4 ABI to satisfy the loader) and a minimal `fake_libsystem.c`, and points `DYLD_SHARED_CACHE_DIR` at a path that doesn't exist. dyld resolves libSystem and libdyld from the shims, finds no cache to map, and leaves the reslide region empty. Spawning the child with `_POSIX_SPAWN_RESLIDE` makes its own call to `536` land in a fresh region, and the OOB fires.

The child is a plain, ad-hoc-signed binary with no entitlements. No debugger, no `task_for_pid`, no Developer Mode.

# From 8 bytes to all of physical memory

An 8-byte OOB write into the next frame is not root by itself. You have to decide what is in that frame and make the write count.

On arm64 the target is a page-table page. If I groom the kernel so a leaf page-table page lands physically adjacent to the slide destination, the OOB write lands on a page-table entry instead of on data. A PTE I control maps a virtual page I own onto a physical frame I choose.

So: groom until a page-table page is the neighbour, build the v5 slide-info so the OOB write forges a controlled PTE, and now one of my virtual pages points at arbitrary physical RAM. Rewrite that PTE repeatedly, moving the aperture across physical memory in 32 MB windows, and I have read/write over all of physical memory through one virtual page.

{{< mermaid >}}
flowchart TB
    subgraph SP["my slide page (attacker-supplied)"]
        direction TB
        start["page_starts[i] · first hop"] --> chain["chain value<br/>next bits say 'keep going'"]
    end
    subgraph PT["neighbour frame: a leaf page table"]
        direction TB
        p0["PTE"] --> p1["PTE"] --> forged["⟪ forged PTE ⟫"] --> p2["PTE …"]
    end
    chain -->|"walk steps off the end of the page"| forged
    forged -->|"maps a vaddr I own onto"| phys["arbitrary physical frame"]
    style forged fill:#5a4412,stroke:#ffb000,color:#ffe9b0
    style chain fill:#143a5a,stroke:#5aa8ff,color:#d7ecff
{{< /mermaid >}}

# The exploit, end to end

A full run is nine steps:

1. **Reach the syscall.** Spawn a child with the shim dylibs (`fake_libdyld` / `fake_libsystem`) and `DYLD_SHARED_CACHE_DIR` pointed at a path that doesn't exist, so dyld maps no real cache and the reslide region stays empty. The child is plain, ad-hoc-signed, unentitled.
2. **Get a fresh region.** Spawn with `_POSIX_SPAWN_RESLIDE` so the child's call to `536` (`shared_region_map_and_slide_2_np`) lands in a region whose `sr_first_mapping == -1`.
3. **Slide off the page.** Build v5 slide-info whose `page_starts[i]` puts the first hop near the end of the page, with a chain value carrying a non-zero `next`, so the walker steps `rebaseLocation` past `page_content + PAGE_SIZE` and does its read-modify-write in the next frame.
4. **Make the neighbour a page table.** Groom kernel allocations so a leaf page-table page lands physically adjacent to the slide destination.
5. **Forge a PTE.** Pick the written value so the clobbered PTE maps a virtual page I own onto a physical frame I choose.
6. **Get full physical R/W.** Rewrite that PTE, moving the aperture across physical memory in 32 MB windows.
7. **Find the credential.** Sweep physical RAM through the aperture for the `posix_cred` with my `uid == ruid == svuid == 501`.
8. **Set uid 0.** Zero the uid/gid fields in place.
9. **Hold the win.** Park the corrupted process in `select()` so its pmap is never torn down, and `chown` + `chmod 04755` a clean `suidwrap` helper so a fresh process can exec a root shell.

{{< mermaid >}}
flowchart TD
    A["shim out libSystem<br/>(fake dyld, no cache)"] --> B["_POSIX_SPAWN_RESLIDE<br/>→ fresh shared region"]
    B --> C["syscall 536 · v5 slide-info<br/>first hop near page end"]
    C --> D["walk steps off the page<br/>8-byte OOB read+write"]
    D --> E["groom: leaf page table<br/>is the neighbour frame"]
    E --> F["OOB write forges a PTE<br/>→ controlled mapping"]
    F --> G["march PTE in 32 MB windows<br/>→ full physical R/W"]
    G --> H["scan RAM for my posix_cred<br/>(uid==ruid==svuid==501)"]
    H --> I["zero uid/gid in place<br/>→ uid 0"]
    I --> J["park in select(); chmod 04755 suidwrap<br/>→ clean root shell"]
    style D fill:#5a1414,stroke:#ff5a5a,color:#ffd7d7
    style F fill:#5a4412,stroke:#ffb000,color:#ffe9b0
    style I fill:#14401e,stroke:#4ad06a,color:#cdf5d6
    style J fill:#14401e,stroke:#4ad06a,color:#cdf5d6
{{< /mermaid >}}

The grooming primitive, spray counts, PTE bit layout, and window-stepping loop for steps 4 to 6 are in the exploit source. I am not transcribing offsets into prose here.

# Finding the credential

With physical read/write, the target is small: my own process credential. On XNU that is a [`posix_cred`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ucred.h), the `cr_posix` sub-structure of `struct ucred`, and mine has `uid == ruid == svuid == 501`, the default first user on macOS.

I scan physical RAM through the PTE aperture, 32 MB at a time, for the credential matching that uid triple. When the scan finds it, I zero the uid and gid fields in place. The process is now uid 0. The PoC prints `oracle post getuid=0x0000000000000000`.

# Keeping root without panicking

By the time the write lands, my address space is corrupt. I have forged PTEs in my pmap for hundreds of writes; the moment the process exits, execs, or unmaps anything, the kernel walks that pmap to tear it down, reads a forged entry as a real PTE, and panics. Winning and touching anything are the same action.

Two things solve it. First, the winning process does not tear itself down: it calls `select(0, NULL, NULL, NULL, NULL)` and blocks, holding its pmap open. Second, the root shell goes to a clean process. While briefly uid 0, the exploit `chown`s and `chmod 04755`s a small staged helper (`suidwrap`), making it setuid-root on disk. A fresh uid-501 process that execs that helper gets a real root credential from the kernel, with none of the corruption.

```
sh-3.2# id
uid=0(root) gid=0(wheel) groups=0(wheel),1(daemon),...,204(_developer)...
sh-3.2# uname -a
Darwin ... root:xnu-12377.120.72.0.4~13/RELEASE_ARM64_VMAPPLE arm64
```

# (Un)Reliability 

The trigger itself is reliable and the uid-0 cred patch is reproducible. The physical scan is not: it rewrites a live PTE hundreds of times and reads arbitrary frames, which destabilizes the pmap and panics on about half of runs. End to end, an attempt lands about one time in eight.

The reason is that the exploit runs blind. It never learns a real kernel address. It grooms until a page table is probably the neighbour, fires the OOB write where it should be, and sweeps physical memory for the credential. Each of those guesses is a place a run can panic. The missing primitive is an information leak: anything that returns a real kernel pointer, or tells me where a page-table page landed. With a leak to aim by, the grooming collapses into one deterministic write at a known target, and one-in-eight becomes close to certain.
An additional kernel infoleak primitive would massivley improve reliability.

There is also collateral in the panics. The slide spray leaves my marker value in the empty slots of other page tables, and an async kernel walk occasionally reads one as a malformed compressed PTE and panics at `pmap.c:5189`. While I hold physical R/W I also scrub: sweep RAM and zero every qword equal to the marker before it is misread. The value is a `-0x4000` sentinel, so nothing live looks like it.

# The fix Apple shipped

I checked `26.5.2` (`25F84`, `xnu-12377.121.10`) by pulling the release kernelcache with [`ipsw`](https://github.com/blacktop/ipsw) and reversing the slide path out of the stripped binary. The bug is closed in two places.

**The per-step bound, now in the walk.** This is the v5 walk as it ships in `26.5.2`, verbatim reverse-engineered Hex-Rays output (locals renamed, otherwise unedited):

```c
delta = *page_starts_ptr;
if ( delta != 0xFFFF )
{
    page_offset = 0;
    value_add_slide = *(_QWORD *)(slide_info + 16) + *si;
    kva_to_uva = uservaddr - page_content;
    while ( 1 )
    {
        page_offset += delta;
        if ( page_offset > 0x3FF8 )           // 0x4000 (16K page) - 8
            return 5;                         // KERN_FAILURE
        rebaseLocation = (unsigned __int64 *)(page_content_base + (int)page_offset);
        if ( page_offset != (int)page_offset )
            rebaseLocation = (unsigned __int64 *)((page_content_base + page_offset) & 0xFFFFFFFFFFFFLL
                                                | 0x2BAD000000000000LL);
        value = *rebaseLocation;
        rebased = value_add_slide + (*rebaseLocation & 0x3FFFFFFFFLL);
        if ( (*rebaseLocation & 0x8000000000000000LL) != 0 )
        {
            // ... auth / PAC re-sign branch ...
            *rebaseLocation = rebased;
        }
        else
        {
            *rebaseLocation = rebased + (value >> 34 << 56);
        }
        delta = (value >> 49) & 0x3FF8;       // next hop
        if ( !delta )
            break;
    }
}
```

`page_offset` is the running distance from the start of the page. It is checked against `0x3FF8` (`PAGE_SIZE - 8`) before every dereference. As soon as the chain tries to step past the last 8-byte slot, the walker returns `KERN_FAILURE`. The v3 path got the same treatment, bounded against `0xFF8` for its 4 KB page.

**The `page_starts[]` check at map time.** `vm_shared_region_slide_sanity_check_v5` now iterates the start table and rejects any entry that points out of the page or is misaligned, before the walker runs. Heres The IDA output:

```c
page_starts_count = (unsigned int)slide_buf[2];
if ( 2 * page_starts_count + 24 > slide_info_size )
{
    printf("vm_shared_region_slide_sanity_check_v5: required_size != slide_info_size 0x%llx != 0x%llx\n");
    goto LABEL_61;
}
if ( (_DWORD)page_starts_count )
{
    for ( j = 0; page_starts_count != j; ++j )
    {
        start = *((unsigned __int16 *)slide_buf + j + 12);
        if ( start != 0xFFFF )
        {
            if ( start >= 0x3FF9 )            // must point inside the 16K page
            {
                printf("vm_shared_region_slide_sanity_check_v5: page_starts[%u] exceeds valid range. %u > %lu\n");
                goto LABEL_61;
            }
            if ( (start & 7) != 0 )           // must be 8-byte aligned
            {
                printf("vm_shared_region_slide_sanity_check_v5: page_starts[%u] is not aligned. %u\n");
                goto LABEL_61;
            }
        }
    }
}
```

Neither check exists in the vulnerable source, and neither string is in the `xnu-12377.120.x` / `.121.6` kernels I tested. Both appear for the first time in the `25F84` kernelcache. The walk bound alone closes the OOB; the `page_starts[]` check rejects a bad first hop before the walk starts.

# Beaten to the patch

I reported this to Apple Product Security on 6/20, report `OE1106480813741`, "Kernel: LPE via physmap OOB-write in `vm_shared_region_slide_page_v5`".

{{< figure src="/images/dirtyslide/apple-report.png" width="100%" align="center" caption="Apple closed the report as already fixed: 'it was fixed in the beta before your report.'" >}}

Apple could not reproduce it on the macOS 26.6 betas and asked for proof on a current build. There was none. It was already patched. Someone reported the same unbounded v5 walk before me, and it was fixed in a beta that shipped before my report. No CVE, no credit, beyond "it was fixed in the beta before your report."

A single missing `if` in a well-trodden file is the kind of thing two people find in the same window. The reachability work and the page-table weaponization are mine. The bug had a shorter shelf life than the exploit.

{{< mermaid >}}
flowchart TD
    A["≤ 26.5 beta · 25F5042g<br/>xnu-12377.120.72 · vulnerable"] --> B["26.5.2 · 25F84<br/>xnu-12377.121.10 · fixed<br/>(built Jun 9)"]
    B --> C["6/20 · I file OE1106480813741"]
    C --> D["6/22 · Apple: can't repro on 26.6 beta"]
    D --> E["6/23 · me: looks already patched.<br/>did someone beat me to it?"]
    E --> F["6/23 · Apple: fixed in a beta<br/>before your report"]
    F --> G["6/30 · Fix released today "]
    style A fill:#5a1414,stroke:#ff5a5a,color:#ffd7d7
    style B fill:#14401e,stroke:#4ad06a,color:#cdf5d6
    style F fill:#3a2f12,stroke:#d9b45c,color:#f0e9d8
{{< /mermaid >}}

# Why it happened

The page-table weaponization leans on an EL1 page-table write that works on the VMAPPLE guest and may be rejected on physical Apple Silicon, where SPTM/PPL hold page tables read-only. The bug itself is the unbounded slide: an OOB read and write into adjacent kernel data frames, which exists regardless of how you cash it out. Where page-table writes are blocked, the same primitive is still usable through data victims.

Five routines do the same job. Four of them, and the chained-fixup pager, carry the "is `rebaseLocation` still inside the page?" check. v5, the newest and the one a live arm64 cache uses, shipped without it. A format gets a new version, the new walker is written fresh, and the one invariant the older siblings enforce does not make it into the copy. The fix puts it back.

# Can this be used to jailbreak the iPhone?

In its current state, probably not. Triggering `536` in the vulnerable context needs an application sandbox bypass.

It also needs an [SPTM](https://support.apple.com/guide/security/operating-system-integrity-sec8b776536b/web) (Secure Page Table Monitor) bypass, and there is little public information on bypassing SPTM. Even before the patch, this exploit only worked on macOS virtual machines.

---

*Vulnerable build exploited: macOS 26.5 beta (`25F5042g`), `xnu-12377.120.72.0.4~13/RELEASE_ARM64_VMAPPLE`, arm64. Fix verified in: macOS 26.5.2 (`25F84`), `xnu-12377.121.10`. 
