---
title: "wrong-instruction: undoing four anti-disassembly tricks in IDA"
date: 2026-08-20 20:00:00 +0600
series: "AlpacaHack Daily"
platform: "AlpacaHack"
summary: "A misaligned jump, a return-address trampoline, disguised code and an opaque predicate hide a one-line per-byte check."
description: "A misaligned jump, a return-address trampoline, disguised code and an opaque predicate hide a one-line per-byte check."
tags: ["rev", "anti-disassembly"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
## Overview

The binary reads a 60-character string and validates it through `is_correct`.
The function is obfuscated with four classic **anti-disassembly** techniques
that confuse IDA's linear-sweep disassembler:

| #   | Trick                   | Location        | Effect on IDA                                                            |
| --- | ----------------------- | --------------- | ------------------------------------------------------------------------ |
| 1   | Misaligned jump         | `0x11D4`        | `jmp $-1` hides `call rax` behind its own operand byte                   |
| 2   | Return-address mutation | `sub_1204`      | `[rsp] += 5` skips 5 dead bytes; IDA never sees the real entry point     |
| 3   | Data-blob disguise      | `0x11D8-0x11EB` | Real loop instructions hidden inside `dq` blobs                          |
| 4   | Opaque predicate        | `0x11EC-0x11EF` | `je`/`jnz` pair always branches to the same target, faking a conditional |

---

## Step 1: Initial Reconnaissance

```
$ file wrong-instruction
wrong-instruction: ELF 64-bit LSB pie executable, x86-64, dynamically linked

$ checksec wrong-instruction
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

$ ./wrong-instruction
Input > AAAA
Incorrect...
```

---

## Step 2: Reading `main`

Open the binary in IDA and let auto-analysis finish. The decompiler gives:

```c
int main(int argc, const char **argv, const char **envp)
{
    char s[72];
    unsigned __int64 canary = __readfsqword(0x28u);
    printf("Input > ");
    __isoc23_scanf("%s", s);
    if ( strlen(s) == 60
         && !(unsigned int)(is_correct)(s, &encoded, 60) )
    {
        printf("Correct! The flag is %s\n", s);
        return 0;
    }
    puts("Incorrect...");
    return 1;
}
```

Two constraints are immediately clear:
- Input must be **exactly 60 characters**.
- `is_correct(input, &encoded, 60)` must return **0**.

Double-click `encoded` to see the validation target at `.rodata:0x2020`:

```
78 AB B7 B0 BA C0 E2 C3  DF E4 FA F4 F6 0C 0C 23
1F 2E 2B 42 36 40 59 54  56 62 68 7B 83 84 8B 8E
98 AD BB B8 84 C3 D0 E2  D8 F2 FA F4 04 01 13 28
16 33 2C 32 3F 4D 50 60  6C 64 7A 8C
```

60 bytes - one per input character.

---

## Step 3: First Look at `is_correct`

Navigating to `is_correct`, IDA initially shows:

```asm
is_correct:
    endbr64
    lea     rax, sub_1204

loc_11D4:
    jmp     short near ptr loc_11D4+1   ; jumps to 0x11D5
; -------------------------------------------------------------------
    dw 0FD0h
    dq 49D2314DC181C30Bh
    dq 4A170CB60F4AD389h
    dq 27504741614B60Fh
    dq 2837D14C8D42B948h
    dq 394DC2FF49C808D1h
; -------------------------------------------------------------------
    fidivr  dword ptr [rdi+rbx*8-3Dh]   ; completely wrong

sub_1204:
    add     qword ptr [rsp+0], 5
    xor     eax, eax
    retn
```

The `dq` blobs and `fidivr` are not real - they are a symptom of IDA failing
to follow the misaligned jump. Four patching passes are needed.

---

## Step 4: Understanding the Tricks (Before Patching)

### Trick 1: Misaligned jump at `0x11D4`

Raw bytes at `0x11D4`:

```
0x11D4:  EB FF   →   jmp short -1   (destination = next_pc - 1 = 0x11D6 - 1 = 0x11D5)
```

IDA correctly decodes the `jmp` but then **linearly disassembles from `0x11D6`**
(the byte after the instruction), treating the `FF` operand and whatever follows
as a new instruction stream - producing garbage.

What actually executes when CPU reaches `0x11D5`:

```
0x11D5:  FF D0   →   call rax       (rax already = address of sub_1204)
```

The `FF` byte at `0x11D5` is simultaneously the *operand* of the `jmp` above
and the *opcode* of `call r/m64` when landed on directly.

### Trick 2: Return-address mutation in `sub_1204`

```asm
sub_1204:
    48 83 04 24 05    add  qword ptr [rsp], 5   ; mutate saved return address
    31 C0             xor  eax, eax              ; return value = 0
    C3                ret
```

When `call rax` at `0x11D5` executes:

```
call pushes:  return address = 0x11D7   (next byte after FF D0)
sub_1204:     [rsp] += 5
              return address is now 0x11D7 + 5 = 0x11DC
              eax = 0
              ret  →  jumps to 0x11DC,  NOT 0x11D7
```

Bytes `0x11D7-0x11DB` are **never executed** - they exist only to mislead
IDA into disassembling them as code.

### Trick 3: Data-blob disguise (`0x11D8-0x11EB`)

The five `dq` values IDA shows are the real loop instructions, correctly decoded
only when IDA starts from `0x11DC` (the true entry point).

### Trick 4: Opaque predicate (`0x11EC-0x11EF`)

```
0x11EC:  74 04   je  +4  →  0x11F2
0x11EE:  75 02   jnz +2  →  0x11F2
```

Both branches target `0x11F2`. Since the Zero Flag is always either set or
clear, one of the two jumps always fires - this is an **unconditional jump**
disguised as two conditional ones.

The secondary effect: `jnz +2` has its own next-PC at `0x11F0`, so IDA plants
label `loc_11F0` there and disassembles from that address instead of `0x11F2`,
consuming the real `lea`/`sub`/`or` instructions inside a fake
`mov rcx, imm64`.

---

## Step 5: Patch 1: Fix the Misaligned Jump (`0x11D4`)

**Goal:** expose `call rax` at `0x11D5` as a real instruction.

1. Press **`G`**, go to `0x11D4`.
2. **Edit → Patch program → Change byte**: change `EB` → `90` (NOP).
3. Press **`U`** to undefine, then **`C`** to reanalyze as code.

IDA now shows:

```asm
0x11D4:  90        nop
0x11D5:  FF D0     call    rax          ; calls sub_1204
0x11D7:  0F 0B     ud2                  ; first of the 5 dead bytes
```

---

## Step 6: Patch 2: NOP the Five Dead Bytes (`0x11D7-0x11DB`)

**Goal:** let IDA flow from `call rax` into the real loop at `0x11DC`.

Open **Edit → Patch program → Change byte** and apply:

| Address | Old | New |
|---------|-----|-----|
| `0x11D7` | `0F` | `90` |
| `0x11D8` | `0B` | `90` |
| `0x11D9` | `C3` | `90` |
| `0x11DA` | `81` | `90` |
| `0x11DB` | `C1` | `90` |

Press **`U`** on `0x11D7`, then **`C`** to reanalyze. Then press **`C`** again
at `0x11DC` to uncover the loop initialization:

```asm
0x11D7-0x11DB:  nop (×5)           ; patched dead bytes

0x11DC:  4D 31 D2    xor  r10, r10  ; i = 0
0x11DF:  49 89 D3    mov  r11, rdx  ; r11 = 60
```

---

## Step 7: Patch 3: Fix the Opaque Predicate (`0x11EC-0x11EF`)

**Goal:** replace the `je`/`jnz` pair with a single unconditional jump so IDA
follows the branch directly to `0x11F2` without creating `loc_11F0`.

Apply these bytes:

| Address | Old | New | Reason |
|---------|-----|-----|--------|
| `0x11EC` | `74` | `90` | NOP - remove `je` opcode |
| `0x11ED` | `04` | `90` | NOP - remove `je` operand |
| `0x11EE` | `75` | `EB` | `jmp short` - replace `jnz` |
| `0x11EF` | `02` | `02` | Keep - offset +2 already targets `0x11F2` |
| `0x11F0` | `48` | `90` | NOP - kill dead byte 1 of the fake `mov rcx` |
| `0x11F1` | `B9` | `90` | NOP - kill dead byte 2 of the fake `mov rcx` |

> **Why NOP `0x11F0-0x11F1`?**  
> `jmp short +2` from `0x11EE` has its next-PC at `0x11F0`, making those
> two bytes unreachable dead code. They are the first two bytes of the
> `mov rcx, imm64` IDA was incorrectly decoding. Patching them to NOP
> prevents IDA from picking them up as a stray code stream.

Press **`U`** on `0x11EC`, then **`C`** to reanalyze.

---

## Step 8: Clean Up Residual `db` Bytes

After the first three patches, IDA may still show raw `db` bytes at two spots
where old `dq` definitions were never fully removed.

### `0x11E7-0x11EF` (shows as `db 4Ah, 0Fh, ...`)

1. Select bytes `0x11E7` through `0x11EF`.
2. Press **`U`** to undefine.
3. Press **`C`** at `0x11E7`.

### `0x11F9` + `0x11FA-0x11FD` (shows as `db 8` + garbage `enter`)

The `enter` instruction (`C8 49 FF C2`) at `0x11FA` is a leftover artefact.
`0x11F9` byte `08` combined with `0x11FA` byte `C8` should be `or al, cl`:

1. Press **`U`** on `0x11F9` (the `db 8`).
2. Press **`U`** on `0x11FA` (the `enter`).
3. Press **`C`** at `0x11F9`.

IDA decodes `08 C8` → `or al, cl` and cascades correctly through to `retn`.

---

## Step 9: Final Disassembly

After all patches and cleanup, `is_correct` reads cleanly:

```asm
is_correct:
    F3 0F 1E FA           endbr64
    48 8D 05 30 00 00 00  lea   rax, sub_1204
    90                    nop                      ; Patch 1: was EB (jmp opcode)
    FF D0                 call  rax                ; → sub_1204: eax=0, ret to 11DC
    90 90 90 90 90        nop (×5)                 ; Patch 2: dead bytes skipped by +5
    4D 31 D2              xor   r10, r10           ; i = 0
    49 89 D3              mov   r11, rdx           ; r11 = 60

loc_11E2:
    4A 0F B6 0C 17        movzx rcx, [rdi+r10]     ; rcx = input[i]
    4A 0F B6 14 16        movzx rdx, [rsi+r10]     ; rdx = encoded[i]
    90                    nop                      ; Patch 3: was 74 (je opcode)
    90                    nop                      ; Patch 3: was 04 (je operand)
    EB 02                 jmp   short loc_11F2     ; Patch 3: unconditional
    90                    nop                      ; Patch 3: dead (was 48)
    90                    nop                      ; Patch 3: dead (was B9)

loc_11F2:
    42 8D 4C D1 37        lea   ecx, [rcx+r10*8+37h]   ; ecx = input[i] + i*8 + 0x37
    28 D1                 sub   cl, dl                 ; cl -= encoded[i]
    08 C8                 or    al, cl                 ; accumulate differences
    49 FF C2              inc   r10                    ; i++
    4D 39 DA              cmp   r10, r11               ; i vs 60
    7C DF                 jl    short loc_11E2
    C3                    retn                         ; return al
```

---

## Step 10: Algorithm Analysis

### What `sub_1204` really does

`sub_1204` is not a regular helper. It is a **setup trampoline** that does two
things when called from `call rax`:

1. **Redirects return:** `[rsp] += 5` makes `ret` land at `0x11DC` (the real
   loop start) instead of `0x11D7` (the dead bytes).
2. **Initializes accumulator:** `xor eax, eax` sets `al = 0` before the loop.

### The validation loop as C

```c
int is_correct(char *input, uint8_t *encoded, int len) {
    uint8_t al = 0;                        // initialized by sub_1204
    for (int i = 0; i < len; i++) {
        uint8_t cl = (input[i] + i*8 + 0x37) - encoded[i];
        al |= cl;                          // non-zero if any char is wrong
    }
    return al;                             // 0 = all chars matched
}
```

`al` is OR'd with every difference. It stays zero only if **every single
difference is zero** - i.e., every character matched perfectly.

### Correctness condition

```
(input[i] + i×8 + 0x37) mod 256  ==  encoded[i]    for all i ∈ [0, 59]
```

### Inversion

```
input[i]  =  (encoded[i] − i×8 − 0x37) mod 256
```

---

## Step 11: Solve Script

```python
#!/usr/bin/env python3

encoded = [
    0x78, 0xAB, 0xB7, 0xB0, 0xBA, 0xC0, 0xE2, 0xC3,
    0xDF, 0xE4, 0xFA, 0xF4, 0xF6, 0x0C, 0x0C, 0x23,
    0x1F, 0x2E, 0x2B, 0x42, 0x36, 0x40, 0x59, 0x54,
    0x56, 0x62, 0x68, 0x7B, 0x83, 0x84, 0x8B, 0x8E,
    0x98, 0xAD, 0xBB, 0xB8, 0x84, 0xC3, 0xD0, 0xE2,
    0xD8, 0xF2, 0xFA, 0xF4, 0x04, 0x01, 0x13, 0x28,
    0x16, 0x33, 0x2C, 0x32, 0x3F, 0x4D, 0x50, 0x60,
    0x6C, 0x64, 0x7A, 0x8C,
]

flag = ''.join(chr((e - i*8 - 0x37) % 256) for i, e in enumerate(encoded))
print(flag)

assert len(flag) == 60
assert all(0x20 <= ord(c) < 0x7F for c in flag)
```

Output:

```
Alpaca{These_methods_are_called_anti-disassembly_techniques}
```

---

## IDA Patch Ledger (Quick Reference)

| Address | Old bytes | New bytes | Trick fixed |
|---------|-----------|-----------|-------------|
| `0x11D4` | `EB` | `90` | Misaligned jump - expose `call rax` |
| `0x11D7` | `0F` | `90` | Dead byte 1 of 5 (skipped by `[rsp]+5`) |
| `0x11D8` | `0B` | `90` | Dead byte 2 |
| `0x11D9` | `C3` | `90` | Dead byte 3 |
| `0x11DA` | `81` | `90` | Dead byte 4 |
| `0x11DB` | `C1` | `90` | Dead byte 5 |
| `0x11EC` | `74` | `90` | Opaque predicate - remove `je` |
| `0x11ED` | `04` | `90` | Opaque predicate - remove `je` operand |
| `0x11EE` | `75` | `EB` | Opaque predicate - `jnz` → `jmp short` |
| `0x11EF` | `02` | `02` | Keep - correct offset to `0x11F2` |
| `0x11F0` | `48` | `90` | Dead preamble of fake `mov rcx` |
| `0x11F1` | `B9` | `90` | Dead preamble of fake `mov rcx` |

After the patches, manually press **`U`** then **`C`** at `0x11E7` and
`0x11F9` to clear any residual `db` definitions left over from the original
`dq` blobs.

---

## Anti-Disassembly Techniques Summary

```
┌──────────────────────────┬────────────┬─────────────────────────────────────┐
│ Technique                │ Location   │ Mechanism                           │
├──────────────────────────┼────────────┼─────────────────────────────────────┤
│ Misaligned jump          │ 0x11D4     │ jmp lands on its own operand byte;  │
│                          │            │ FF at 0x11D5 is both jmp operand    │
│                          │            │ and call r/m64 opcode               │
├──────────────────────────┼────────────┼─────────────────────────────────────┤
│ Return-address mutation  │ sub_1204   │ [rsp] += 5 skips 5 dead bytes;      │
│                          │ 0x1204     │ IDA never sees the real entry at    │
│                          │            │ 0x11DC                              │
├──────────────────────────┼────────────┼─────────────────────────────────────┤
│ Data-blob disguise       │ 0x11D8-    │ IDA shows dq objects; actual x86-64 │
│                          │ 0x11EB     │ instructions when decoded from the  │
│                          │            │ real entry point 0x11DC             │
├──────────────────────────┼────────────┼─────────────────────────────────────┤
│ Opaque predicate         │ 0x11EC-    │ je + jnz both target 0x11F2;        │
│ (je / jnz)               │ 0x11EF     │ unconditional but looks conditional;│
│                          │            │ loc_11F0 label causes IDA to decode │
│                          │            │ real instructions as a fake         │
│                          │            │ mov rcx, imm64                      │
└──────────────────────────┴────────────┴─────────────────────────────────────┘
```
{% endraw %}
