---
title: "xorshift521: skipping 521^271441 iterations with linear algebra"
date: 2026-06-20 20:00:00 +0600
series: "AlpacaHack Daily"
platform: "AlpacaHack"
summary: "The generator is a linear map over GF(2), so the impossible loop becomes one matrix power with a reduced exponent."
description: "The generator is a linear map over GF(2), so the impossible loop becomes one matrix power with a reduced exponent."
tags: ["crypto", "math"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
## 1. Challenge Overview

We are given a Python script that:
1. Takes a flag as input
2. Runs a pseudorandom state transition function an astronomically large number of times
3. XORs the resulting keystream with the flag
4. Compares it to a known ciphertext (`expected`)

Our goal is to **recover the flag** by figuring out what the state is after that massive number of iterations - without actually running the loop.

---

## 2. Understanding the Code

```python
n = 521
mask = (1 << n) - 1  # 521-bit all-ones mask
expected = bytes.fromhex("01dadc95cc4ad53980f0bfa25eb55bbea8590cc11c12f9922fd3783e0b4ba33846cd11520a0a3fb8b4905c996d")

def next(state):
    state ^= state << (5*21) & mask   # left shift by 105
    state ^= state >> (52+1)          # right shift by 53
    state ^= state << (0o521) & mask  # left shift by 337 (0o521 is octal!)
    return state

def main():
    flag = input("flag > ").strip().encode()
    state = 521
    for i in range((521**521)**521):   # ← astronomically large!
        state = next(state)
    for i in range(len(expected)):
        if (flag[i] ^ (state & 0xFF)) != expected[i]:
            print("Incorrect...")
            exit(1)
        state = next(state)
    print("Correct!")
```

### Key Parameters

| Detail | Value |
|---|---|
| State size | 521 bits |
| Initial state | `521` |
| Left shift 1 | `5 * 21 = 105` |
| Right shift | `52 + 1 = 53` |
| Left shift 2 | `0o521 = 337` (octal!) |
| Number of pre-iterations | `(521**521)**521 = 521**(521²) = 521**271441` |


### How the Flag is Encrypted

After `(521**521)**521` applications of `next`, the state is used as a keystream generator. Each byte of the flag is XORed with the **lowest 8 bits** of the current state:

```
ciphertext[i] = flag[i] XOR (state & 0xFF)
state = next(state)
```

Since XOR is its own inverse, decryption is identical:

```
flag[i] = ciphertext[i] XOR (state & 0xFF)
```

---

## 3. The Core Problem

The loop runs `(521**521)**521` times. Let's appreciate how absurdly large this number is:

```
521**271441  ≈  10^(271441 × log₁₀(521))
             ≈  10^(271441 × 2.717)
             ≈  10^737,500
```

This number has roughly **737,500 digits**. The fastest computers in the world could not iterate this loop even in the lifetime of the universe. We need a completely different approach.

---

## 4. Mathematical Background

### 4.1 GF(2): The Field with Two Elements

GF(2) (also written ℤ/2ℤ) is the simplest possible field, containing only `{0, 1}`:

| Operation | Rule | Equivalent |
|---|---|---|
| Addition | `0+0=0, 0+1=1, 1+0=1, 1+1=0` | **XOR** |
| Multiplication | `0×0=0, 0×1=0, 1×0=0, 1×1=1` | **AND** |

The key insight: **XOR is addition over GF(2)**.

### 4.2 Representing a 521-bit Integer as a Vector

A 521-bit integer can be thought of as a **521-dimensional vector** over GF(2), where each component is one bit:

```
state = b₀·2⁰ + b₁·2¹ + b₂·2² + ... + b₅₂₀·2⁵²⁰

         ↕  (isomorphism)

v = [b₀, b₁, b₂, ..., b₅₂₀]  ∈  GF(2)^521
```

### 4.3 The `next` Function is a Linear Map

Each operation in `next` is linear over GF(2):

- **Left shift by s**: moves bit at position `i` to position `i+s`, i.e., maps `bᵢ → bᵢ₋ₛ`
- **Right shift by s**: maps `bᵢ → bᵢ₊ₛ`
- **XOR with self (shifted)**: vector addition over GF(2)

Because all three operations are linear, their composition is also linear. This means there exists a **521×521 matrix M** over GF(2) such that:

```
next(v)  =  M · v         (matrix-vector multiplication over GF(2))
```

This is the central insight of the entire solution.

### 4.4 Applying `next` k Times = Matrix Power

If `next` is a linear map represented by matrix `M`, then applying it `k` times is:

```
next(next(v))    = M · (M · v) = M² · v
next applied k times  =  Mᵏ · v
```

So instead of iterating `521**271441` times, we just need:

```
final_state  =  M^(521**271441)  ·  v₀
```

where `v₀` is the vector for the initial state `521`.

### 4.5 LFSR Periodicity: The Period Makes Exponents Manageable

The `next` function is an **xorshift LFSR** (Linear Feedback Shift Register). Every LFSR has a **period** `T`: after exactly `T` steps, the state returns to where it started. In matrix terms:

```
M^T  =  I     (identity matrix)
```

This means exponents are periodic:

```
M^k  =  M^(k mod T)
```

So we only need to compute `k mod T`, which can be done with modular arithmetic in milliseconds - no matter how large `k` is.

### 4.6 What is the Period T?

For an n-bit maximal-period xorshift LFSR, the period is:

```
T  =  2ⁿ - 1
```

For our 521-bit LFSR:

```
T  =  2^521 - 1
```

This is a **Mersenne-like** number. An LFSR achieves this maximal period when its characteristic polynomial is **primitive** over GF(2) - meaning the matrix `M` generates the full multiplicative group of GF(2^521).

> **Note**: 521 is prime, which is a favorable condition for primitivity. The specific shift amounts (105, 53, 337) in this challenge are chosen to produce a primitive polynomial, giving the full period `2^521 - 1`.

### 4.7 Bringing It All Together

```
Mᵏ · v₀    where k = 521^271441

= M^(k mod T) · v₀     since M^T = I

= M^(pow(521, 271441, 2^521-1)) · v₀    ← entirely computable!
```

---

## 5. Solution Strategy

```
Goal: Compute M^k · v₀  where k = 521^271441, v₀ = vector(521)
```

### The Plan

```
Step 1: Build M                      (521×521 matrix over GF(2))
            ↓
Step 2: Set T = 2^521 - 1            (period of the LFSR)
            ↓
Step 3: k' = pow(521, 271441, T)     ← fast modular exponentiation
            ↓
Step 4: Mᵏ' = M ** k'                 ← fast matrix exponentiation in SageMath
            ↓
Step 5: result = Mᵏ' · v₀             ← one matrix-vector multiply
            ↓
Step 6: XOR keystream with expected   →  FLAG
```

### Complexity Comparison

| Step | Naive approach | Smart approach |
|---|---|---|
| Running `next` k times | `521^271441` iterations - impossible | - |
| Reducing exponent | - | `pow(521, 271441, T)` - milliseconds |
| Matrix exponentiation | - | O(log(k') × n^2.376) - feasible |
| Total | Heat death of the universe | A few seconds |

---

## 6. Step-by-Step Solution

### Step 1: Build the Transition Matrix

For each standard basis vector `eᵢ` (the integer `1 << i`, with only bit `i` set), apply `next` and record which output bits are set. The result is **column `i`** of matrix `M`.

```python
F = GF(2)
n = 521
mask = (1 << n) - 1

cols = []
for i in range(n):
    state = 1 << i             # basis vector eᵢ
    state ^= (state << 105) & mask
    state ^= (state >> 53)
    state ^= (state << 337) & mask
    col = [(state >> j) & 1 for j in range(n)]
    cols.append(col)

# cols[i] is the i-th column of M
M = Matrix(F, n, n, lambda i, j: cols[j][i])
```

**Why this works**: By linearity, `M · eᵢ = next(eᵢ)`. The output bits of `next(eᵢ)` directly give us column `i` of `M`. Do this for all 521 basis vectors and you have the full matrix.

### Step 2: Determine the Period T

```python
# Assume maximal period (verify with minpoly if needed)
T = 2**521 - 1

# To verify rigorously in SageMath:
# minpoly = M.minpoly()
# assert minpoly.degree() == 521        # full degree = primitive
# assert minpoly.is_irreducible()       # irreducible over GF(2)
```

For the competition, `T = 2^521 - 1` is correct because the xorshift parameters (105, 53, 337) were chosen to yield a primitive characteristic polynomial.

### Step 3: Reduce the Exponent

```python
# k = (521**521)**521
#   = 521**(521 * 521)
#   = 521**271441

# Compute k mod T using Python's fast built-in pow
k = pow(521, 271441, T)
# Result is a number < 2^521, computed in milliseconds
```

Python's built-in `pow(base, exp, mod)` uses **fast modular exponentiation** (repeated squaring), so even though `271441` is large, this is instant.

### Step 4: Compute M^k via Fast Matrix Exponentiation

```python
Mk = M ** k   # SageMath handles this with repeated squaring
```

SageMath computes this with `O(log k)` matrix multiplications. Each multiplication of two 521×521 matrices over GF(2) is fast because GF(2) arithmetic can be done with bitwise operations. The total time is feasible (typically a few minutes).

### Step 5: Apply the Matrix to the Initial State

```python
# Convert the integer 521 to a GF(2) vector
state_vec = vector(F, [(521 >> i) & 1 for i in range(n)])

# Apply M^k
result_vec = Mk * state_vec

# Convert the result vector back to an integer
state = sum(int(result_vec[i]) * (1 << i) for i in range(n))
```

The integer `521` in binary is `...001000001001`, so most bits of `state_vec` are 0.

### Step 6: Decrypt the Flag

```python
expected = bytes.fromhex(
    "01dadc95cc4ad53980f0bfa25eb55bbea8590cc11c12f9922fd3783e0b4ba33846cd11520a0a3fb8b4905c996d"
)

def next_fn(s):
    s ^= (s << 105) & mask
    s ^= (s >> 53)
    s ^= (s << 337) & mask
    return s

flag = []
for byte in expected:
    flag.append(byte ^ (state & 0xFF))   # XOR lowest byte with ciphertext
    state = next_fn(state)

print(bytes(flag).decode())
```

---

## 7. Full SageMath Code

```python
from sage.all import *

n = 521
mask = (1 << n) - 1
expected = bytes.fromhex(
    "01dadc95cc4ad53980f0bfa25eb55bbea8590cc11c12f9922fd3783e0b4ba33846cd11520a0a3fb8b4905c996d"
)

# ── Step 1: Build the 521×521 transition matrix over GF(2) ────────────────────
F = GF(2)
cols = []
for i in range(n):
    state = 1 << i
    state ^= (state << (5 * 21)) & mask   # 105
    state ^= (state >> (52 + 1))           # 53
    state ^= (state << (0o521)) & mask     # 337 (octal literal!)
    col = [(state >> j) & 1 for j in range(n)]
    cols.append(col)

M = Matrix(F, n, n, lambda i, j: cols[j][i])
print("[+] Transition matrix M built (521×521 over GF(2))")

# ── Step 2: Set the period T = 2^521 - 1 ─────────────────────────────────────
T = 2**521 - 1
print("[+] Period T = 2^521 - 1")

# ── Step 3: Reduce the exponent mod T ─────────────────────────────────────────
# (521**521)**521 = 521**(521*521) = 521**271441
k = pow(521, 271441, T)
print(f"[+] Reduced exponent k = 521^271441 mod T = {k}")

# ── Step 4: Fast matrix exponentiation ────────────────────────────────────────
Mk = M ** k
print("[+] M^k computed via repeated squaring")

# ── Step 5: Apply to initial state 521 ────────────────────────────────────────
state_vec = vector(F, [(521 >> i) & 1 for i in range(n)])
result_vec = Mk * state_vec
state = ZZ(sum(int(result_vec[i]) * (1 << i) for i in range(n)))
print(f"[+] State after k iterations recovered")

# ── Step 6: Decrypt the flag ───────────────────────────────────────────────────
def next_fn(s):
    s ^= (s << (5 * 21)) & mask
    s ^= (s >> (52 + 1))
    s ^= (s << (0o521)) & mask
    return s

flag = []
for byte in expected:
    flag.append(byte ^ (state & 0xFF))
    state = next_fn(state)

print("[+] Flag:", bytes(flag).decode())
```

---

## Summary

```
Problem:  Apply next() to state=521 exactly 521^271441 times - impossible directly.

Key Insight #1:  next() is a linear map over GF(2)^521
                 → Represent it as a 521×521 matrix M over GF(2)
                 → Applying k times = computing Mᵏ

Key Insight #2:  The xorshift LFSR has period T = 2^521 - 1
                 → Mᵀ = I, so Mᵏ = M^(k mod T)

Key Insight #3:  k mod T = pow(521, 271441, 2^521-1) runs instantly
                 → Fast matrix exponentiation gives Mᵏ efficiently

Solution:  Mᵏ · v₀  gives the keystream start state
           flag = expected XOR keystream
```

### Concepts Used

| Concept | Role in Solution |
|---|---|
| GF(2) linear algebra | Models bitwise XOR and shifts as matrix operations |
| LFSR theory | Guarantees periodicity of the state transition |
| Primitive polynomials | Ensures the period is maximal: `2^521 - 1` |
| Modular exponentiation | Reduces a 737,500-digit exponent to a small number |
| Matrix exponentiation | Computes `M^k` in `O(log k)` multiplications |
| XOR decryption | Inverts the flag encryption using the recovered keystream |
{% endraw %}
