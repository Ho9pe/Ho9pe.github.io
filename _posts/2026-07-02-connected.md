---
title: "connected: talking to a simulated network of oracles"
date: 2026-07-02 14:00:00 +0600
series: "crackmes.one"
platform: "crackmes.one"
summary: "A small C++ network simulator. The orchestrator wants a message whose checksum lands on one constant, so I brute-forced an 8-byte palindrome."
description: "A small C++ network simulator. The orchestrator wants a message whose checksum lands on one constant, so I brute-forced an 8-byte palindrome."
tags: ["rev", "linux"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
## 1) Recon

At runtime the binary prompts for two lines:

- `what:` (a message)
- `where:` (an IPv4 address)

So the program is effectively: **send message → to destination IP → print whatever comes back**.

## 2) Finding the interesting code in the decompilation

Searching the decompilation for the prompt strings leads directly to `main()`:

- It prints `what:` and reads a full line via `std::getline`.
- It prints `where:` and reads another line.
- It parses `where` with `str_to_ip()` (`sscanf("%d.%d.%d.%d")` into a 32-bit IP).
- It builds a `packet` containing the message and the destination IP, then calls `net_pc::send_packet()`.

The code is set up as a small “network simulator”: many `net_pc` objects with different IPs and handler lambdas.

## 3) Enumerating the hosts

In the decompilation, the PCs are instantiated with constants like:

- `0x260fc72a` → `38.15.199.42`
- `0x260fc729` → `38.15.199.41`
- `0x260fc728` → `38.15.199.40`

- `0x64191a0a` → `100.25.26.10`
- `0x64191a0b` → `100.25.26.11`
- `0x64191a0f` → `100.25.26.15`

- `0x400e0319` → `64.14.3.25`
- `0x400e031d` → `64.14.3.29`

- `0x53305c05` → `83.48.92.5`
- `0x53305c08` → `83.48.92.8`

A quick dynamic probe (send `HELLO` to each) shows which hosts are “oracles” and which host is the orchestrator.

Notably:

- `100.25.26.10` replies with a generic rejection unless the message matches a required format.
- `64.14.3.25` replies with a small integer (turns out to be just the message length in the tested paths).
- `64.14.3.29` replies with a larger integer (a checksum-like function of the message).

## 4) The orchestrator logic (the real check)

The important handler is the one serving requests that ultimately lead to the flag.

From the decompilation, the orchestrator host expects the payload to start with a 4-byte magic prefix:

```c
memcmp(payload, DAT_00117051, 4)
```

To recover `DAT_00117051`, dump `.rodata` around the address (this binary is PIE; `.rodata` begins at `0x17000`):

```bash
readelf -S connected | grep -E "\\.rodata"
objdump -s --start-address=0x17040 --stop-address=0x17080 connected
```

The dump contains:

- `"msg_"`

So the message must begin with:

- `msg_`

After stripping that 4-byte prefix, the orchestrator stores the remaining bytes and causes other hosts to compute values from it.

Eventually the orchestrator checks a condition of the form:

- one stored string parses with `stoi(...)` to `8`
- another stored value’s first character is `'1'`
- another stored string parses with `stoi(...)` to `0x6022e46`

That last constant is:

```text
0x6022e46 = 100806214
```

When all conditions pass, the orchestrator sends a packet that ends up printed as the final `received:` line (the flag).

## 5) The key oracle: 64.14.3.29 produces 100806214

The host at `64.14.3.29` (handler lambda #8 in the decompilation) computes a number from the **bytes it receives**.

### 5.1) The “cipher” step

Before the math, there is a hop that XORs bytes by `0x42` and rejects payloads that contain a literal `0x42` byte.

You can observe this behavior in the decompilation (a handler does):

- if any byte equals `0x42` (`'B'`), it responds with `"..."`
- else it transforms each byte: `byte ^= 0x42`

This is why when you test `HELLO` against `64.14.3.29` you get `400`: internally the math is applied to the XORed bytes.

Example:

- `HELLO` XOR `0x42` becomes bytes: `0a 07 0e 0e 0d`
- the oracle’s “sum” function on those bytes equals `400` → that’s exactly what the binary prints.

### 5.2) The math

For payload bytes `b[i]` (treated as signed chars in one place), the oracle computes:

- `adler32(payload)`
- `fletcher16(payload)`
- `S(payload) = Σ ((int8)b[i] << (i & 31))`
- `palindrome = (payload == reversed(payload))`

Then:

- if `palindrome` is true: `out = S(payload) ^ (adler32(payload) ^ fletcher16(payload))`
- else: `out = S(payload)`

It then returns `out` as a decimal string.

We need that decimal string to parse to **100806214**.

## 6) Solving for the required message bytes

From the orchestrator check we need the oracle to output:

- `100806214`

Constraints we must satisfy (from the XOR hop + later logic):

- payload cannot contain `'B'` (byte `0x42`), because that short-circuits to `"..."`
- easiest path is to force the oracle to take the palindrome branch (more freedom), so choose a palindrome
- keep bytes printable-ish to avoid other “sanity” checks in the network

A convenient approach is to brute-force an 8-byte palindrome:

```
a b c d d c b a
```

over a small allowed alphabet (printable even ASCII excluding `'B'`). That’s about 4-5 million candidates - fast in Python.

### 6.1) Brute-force script

```python
import itertools
import zlib

TARGET = 100_806_214

# printable 0x21..0x7e, even-valued, excluding 'B' (0x42)
allowed = [c for c in range(0x21, 0x7f) if (c % 2 == 0 and c != 0x42)]

MOD_ADLER = 0xfff1

def adler32_bytes(bs):
    a = 1
    b = 0
    for x in bs:
        a = (a + x) % MOD_ADLER
        b = (b + a) % MOD_ADLER
    return (b << 16) | a

def fletcher16(bs):
    s1 = 0
    s2 = 0
    for x in bs:
        s1 = (s1 + x) % 0xff
        s2 = (s2 + s1) % 0xff
    return ((s2 << 8) | s1) & 0xffff

for a, b, c, d in itertools.product(allowed, repeat=4):
    bs = bytes([a, b, c, d, d, c, b, a])

    # S(payload) with unsigned bytes (the values here are < 0x80 anyway)
    S = sum((x << i) for i, x in enumerate(bs)) & 0xffffffff

    out = S ^ (adler32_bytes(bs) ^ fletcher16(bs))
    if out == TARGET:
        print(bs)
        print(bs.decode('ascii'))
        break
```

This finds:

- `:"*$$*":`

## 7) Final input (and why it works)

The full `what` string must include the magic prefix:

- `msg_` + `:"*$$*":`

So the final inputs are:

- **what:** `msg_:"*$$*":`
- **where:** `100.25.26.10`

When you run it, the orchestrator’s chained checks pass and the program prints:

- `received: CMO{secret_code_v9hcdkd2}`

## 8) One-liner solve

```bash
printf 'msg_:"*$$*":\n100.25.26.10\n' | ./connected
```
{% endraw %}
