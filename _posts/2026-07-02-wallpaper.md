---
title: "wallpaper: meet-in-the-middle on a 1 KB state machine"
date: 2026-07-02 16:00:00 +0600
series: "crackmes.one"
platform: "crackmes.one"
summary: "A syscall-only ELF checks a 37-digit base-4 password through an invertible state machine. A forward BFS and a backward DFS meet in the middle."
description: "A syscall-only ELF checks a 37-digit base-4 password through an invertible state machine. A forward BFS and a backward DFS meet in the middle."
tags: ["rev", "linux", "algorithms"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
## 1) Initial recon

Quick fingerprint:

- `file wallpaper` → **ELF64**, statically linked, stripped.
- It prints `enter password` and then either `wrong password` or `good job, validate with CMO{your_input}`.
- There’s no libc; it uses raw syscalls.

The binary is extremely small (~1 KB), so disassembling the whole `.text` is feasible.

## 2) What input does it accept?

Right after reading the 0x26 bytes, the program loops over them and checks each byte with a `bt` (bit test) against a constant mask.

In the disassembly:

- It reads into a fixed buffer at `0x400297`.
- For each byte `al`, it does `bt rdx, rax` with:

`rdx = 0x000f000000000400`

Interpreting that as a bitset over ASCII codes:

- bit 10 set → `\n` allowed
- bits 48..51 set → `'0'..'3'` allowed

So the “password” is a base-4 string (digits 0–3), and it’s okay if the last byte is `\n`.

**Important detail:** it reads **38 bytes**, but the later processing loop runs for **37 iterations** (it increments an index and terminates once bit 37 is reached). So:

- bytes 0..36 affect the check
- byte 37 just needs to be in the allowed set (newline is easiest)

## 3) The success condition

After the 37 iterations, the code does:

```text
rbx = 0x0123456789abcdef
rax ^= rbx
rbx = 0x1111111111111111
rax ^= rbx
rbx = 0xeeeeeeeeeeeeeeee
rax ^= rbx
if (rax != 0) -> fail
```

Combine the XOR constants:

`0x0123456789abcdef ^ 0x1111111111111111 ^ 0xeeeeeeeeeeeeeeee = 0xfedcba9876543210`

So the *real* condition is:

- final `RAX` must equal `0xfedcba9876543210`

The transformation starts from:

- initial `RAX = 0xb6fd071e9c8a3425`

(both constants are visible in the disassembly).

## 4) The per-character transform (state machine)

Each of the 37 digits is processed in a loop. The code first finds the **lowest nibble** (4-bit chunk) of `RAX` that is zero.

Let:

- `n` = index of the first zero nibble in `RAX` (from 0 to 15)
- `rcx = 4*n`

Then it reads one input digit and uses a bitmap:

- `BITMAP = 0x3bb97ffd7ffd6eec`
- it checks `BITMAP[(4*n + digit) mod 64] == 1`

So at each step, the allowed next digits depend on the current state via `n`.

If the digit is allowed, it runs a small sequence of rotates and low-byte nibble manipulation. The effect is deterministic, and can be modeled exactly.

I validated my understanding by comparing a real execution in `gdb` after one step versus my Python emulator (breakpoint around `0x4001d1`).

## 5) Why not a classic “pwn” exploit?

Despite being tagged as PWN, there’s no obvious memory corruption here:

- no stack frame / no `ret` gadgets to smash
- no dynamic linking / GOT to overwrite
- tiny syscall-only program

This is effectively a “compute the right password” task: RE the transform and solve for an input that produces the target state.

## 6) Solving strategy

### Naive forward search explodes

At each step there are typically 2–3 valid digits. A naive forward BFS grows very fast (millions of states by depth ~20).

### Key observation: the step is invertible (on reachable states)

In the forward step, the code does:

- rotate
- capture low nibble (`sil`)
- **clear** low nibble
- more rotates
- OR low nibble back in

On reachable states, right before the OR, the low nibble is always 0, so the OR is effectively “set nibble to `sil`” and is invertible.

That lets us implement an exact `step_inverse(next_state, n, digit) -> prev_state`.

### Meet-in-the-middle + backward DFS

Even with an inverse, a full 37-step reverse BFS still grows too large.

So I used meet-in-the-middle:

1. **Forward BFS** from `INIT_RAX` for `k = 18` steps, storing `state -> prefix_digits`.
2. **Backward DFS** from `TARGET_RAX` for `l = 19` steps using `step_inverse`, with memoization of failed `(state, remaining)`.
3. The DFS stops as soon as it reaches any `state` present in the forward frontier.

This avoids building the entire backward frontier and finds a valid path quickly.

The final password is:

- `prefix_digits (18)` + `suffix_digits (19)` = 37 digits

The solver stores digits compactly as a base-4 integer during the BFS, then decodes it at the end.

## 7) Reproducing

**solve_wallpaper.py**:

```python
#!/usr/bin/env python3
import subprocess


BITMAP = 0x3BB97FFD7FFD6EEC
INIT_RAX = 0xB6FD071E9C8A3425
TARGET_RAX = 0xFEDCBA9876543210

MASK64 = (1 << 64) - 1
CONST_BY_DIGIT = (0xF0, 0xFC, 0x10, 0x04)


def ror(x: int, r: int) -> int:
    r &= 63
    return ((x >> r) | ((x << (64 - r)) & MASK64)) & MASK64


def rol(x: int, r: int) -> int:
    r &= 63
    return (((x << r) & MASK64) | (x >> (64 - r))) & MASK64


def first_zero_nibble_index(x: int) -> int | None:
    for n in range(16):
        if ((x >> (4 * n)) & 0xF) == 0:
            return n
    return None


def digit_allowed(n: int, d: int) -> bool:
    return ((BITMAP >> ((4 * n + d) & 63)) & 1) == 1


def step_forward(rax: int, digit: int) -> int | None:
    n = first_zero_nibble_index(rax)
    if n is None:
        return None
    if not digit_allowed(n, digit):
        return None
    c = CONST_BY_DIGIT[digit] & 0xFF
    rcx = 4 * n
    tmp = ror(rax, (rcx + c) & 0xFF)
    sil = tmp & 0xF
    tmp &= 0xFFFFFFFFFFFFFFF0  # clear low nibble
    tmp = ror(tmp, (64 - rcx) & 0xFF)
    tmp = ror(tmp, (rcx - c) & 0xFF)
    tmp = (tmp & 0xFFFFFFFFFFFFFF00) | ((tmp & 0xFF) | sil)
    tmp = ror(tmp, (64 - rcx) & 0xFF)
    return tmp


def step_inverse(rax_next: int, n: int, digit: int) -> int:
    c = CONST_BY_DIGIT[digit] & 0xFF
    rcx = 4 * n
    # Undo the final ror by (64-rcx): equivalent to ror by rcx.
    tmp4 = ror(rax_next, rcx)
    sil = tmp4 & 0xF
    # Before the OR, reachable states always have low nibble == 0, so undo by clearing.
    tmp3 = tmp4 & 0xFFFFFFFFFFFFFFF0
    # Undo ror(tmp2, rcx-c)  => tmp2 = rol(tmp3, rcx-c)
    tmp2 = rol(tmp3, (rcx - c) & 0xFF)
    # Undo ror(tmp1, 64-rcx) => tmp1 = ror(tmp2, rcx)
    tmp1 = ror(tmp2, rcx)
    # Restore the cleared nibble from sil.
    rot1 = (tmp1 & 0xFFFFFFFFFFFFFFF0) | sil
    # Undo rot1 = ror(prev, rcx+c) => prev = rol(rot1, rcx+c)
    return rol(rot1, (rcx + c) & 0xFF)


def decode_base4(code: int, length: int) -> str:
    out = ["0"] * length
    for i in range(length - 1, -1, -1):
        out[i] = str(code & 3)
        code >>= 2
    return "".join(out)


def recover_digits() -> str:
    # Meet-in-the-middle with forward BFS and backward DFS (early-exit):
    # - Forward BFS builds all states after k steps.
    # - Backward DFS searches for any split state reachable in (37-k) steps from TARGET.
    k = 18
    l = 37 - k
    allowed_by_n = [tuple(d for d in range(4) if digit_allowed(n, d)) for n in range(16)]
    def step_forward_known_n(rax: int, n: int, digit: int) -> int:
        c = CONST_BY_DIGIT[digit] & 0xFF
        rcx = 4 * n
        tmp = ror(rax, (rcx + c) & 0xFF)
        sil = tmp & 0xF
        tmp &= 0xFFFFFFFFFFFFFFF0
        tmp = ror(tmp, (64 - rcx) & 0xFF)
        tmp = ror(tmp, (rcx - c) & 0xFF)
        tmp = (tmp & 0xFFFFFFFFFFFFFF00) | ((tmp & 0xFF) | sil)
        tmp = ror(tmp, (64 - rcx) & 0xFF)
        return tmp
    front_f: dict[int, int] = {INIT_RAX: 0}
    for _ in range(k):
        nxt: dict[int, int] = {}
        for state, code in front_f.items():
            n = first_zero_nibble_index(state)
            if n is None:
                continue
            for d in allowed_by_n[n]:
                ns = step_forward_known_n(state, n, d)
                if ns not in nxt:
                    nxt[ns] = (code << 2) | d
        front_f = nxt
    memo_fail: set[tuple[int, int]] = set()

    def dfs(cur: int, remaining: int) -> tuple[int, list[int]] | None:
        key = (cur, remaining)
        if key in memo_fail:
            return None
        if remaining == 0:
            return (cur, []) if cur in front_f else None
        for n in range(16):
            for d in allowed_by_n[n]:
                prev = step_inverse(cur, n, d)
                if first_zero_nibble_index(prev) != n:
                    continue
                # Inverse derivation should be exact, but keep a cheap sanity check
                # to avoid wandering into unreachable states.
                if step_forward_known_n(prev, n, d) != cur:
                    continue
                sub = dfs(prev, remaining - 1)
                if sub is not None:
                    split_state, digits = sub
                    digits.append(d)
                    return split_state, digits
        memo_fail.add(key)
        return None
    res = dfs(TARGET_RAX, l)
    if res is None:
        raise RuntimeError("No solution found (unexpected)")
    split_state, suffix_digits = res
    left_code = front_f[split_state]
    left_digits = decode_base4(left_code, k)
    right_digits = "".join(str(d) for d in suffix_digits)
    return left_digits + right_digits


def main() -> None:
    digits = recover_digits()
    # The program reads 38 bytes but only processes the first 37; the last byte just
    # needs to be one of {\n, '0', '1', '2', '3'}. Use newline for convenience.
    password = (digits + "\n").encode()
    proc = subprocess.run(["./wallpaper"], input=password, stdout=subprocess.PIPE)
    print(proc.stdout.decode(errors="replace"), end="")
    print("password:", digits)


if __name__ == "__main__":
    main()
```

- Solve + verify locally:

```bash
python3 solve_wallpaper.py
```

It prints the program output and the recovered password. The password printed by the solver is the part you place into the flag format:

`CMO{your_input}`

## 8) Final answer

Password:

`1001223210123010301233322110103321001`

Flag:

`CMO{1001223210123010301233322110103321001}`
{% endraw %}
