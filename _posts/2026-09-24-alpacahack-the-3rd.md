---
title: "The 3rd: ECDLP over a modulus with a secret prime"
date: 2026-09-24 20:00:00 +0600
series: "AlpacaHack Daily"
platform: "AlpacaHack"
summary: "The secret third prime never matters. Two small public primes, CRT and a known flag format pin the scalar down exactly."
description: "The secret third prime never matters. Two small public primes, CRT and a known flag format pin the scalar down exactly."
tags: ["crypto", "ecc"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
## Challenge

```python
import os

flag = os.environ["FLAG"].encode()

assert len(flag) == 14
assert flag.startswith(b"Alpaca{") and flag.endswith(b"}")

p = 577131489751
q = 604663433347
r = Integer(os.environ["SECRET_PRIME"])
assert all(s.is_prime() for s in [p, q, r])
assert len({p, q, r}) == 3

E = EllipticCurve(Zmod(p * q * r), [2, 3])
S = E(47472880544948864957374958450616147, 15718905651315016723553161697283736)
T = int.from_bytes(flag) * S
print(f"T = ({T[0]}, {T[1]})")
```

Output:

```
T = (299503460090901935082824843431273729, 5022588709750132765941314121276972)
```

### What we know

| Item        | Value                                        |
| ----------- | -------------------------------------------- |
| Curve       | `y^2 = x^3 + 2x + 3` over `Z/(pqr)`          |
| `p`, `q`    | public (about 39-40 bits each)               |
| `r`         | **secret** prime                             |
| `S`         | public base point                            |
| `T = m*S`   | public, where `m = int.from_bytes(flag)`     |
| Flag format | `Alpaca{` + 6 unknown bytes + `}` (14 bytes) |
|             |                                              |

The goal is to recover the scalar `m` from `T = m*S`, which is an elliptic curve discrete logarithm problem (ECDLP).

## Analysis

Solving an ECDLP on a curve over a ~120-bit composite modulus looks infeasible at first. The structure of the modulus changes that.

By the Chinese Remainder Theorem, the ring `Z/(pqr)` splits as `F_p x F_q x F_r`, and therefore

```
E(Z/pqr)  ~=  E(F_p) x E(F_q) x E(F_r)
```

Points reduce coordinate-wise, and the group law and scalar multiplication are computed independently in each component. So from `T = m*S` we get, for every prime `ell` in `{p, q, r}`:

```
(T mod ell) = m * (S mod ell)    in E(F_ell)
```

We do not know `r`, so we cannot use the third component. But we do not need it. `p` and `q` are public, so we can reduce `S` and `T` mod each of them and attack two small, independent ECDLPs.

Each prime is about 2^39, so each curve group has about 2^39 elements. A generic algorithm (baby-step giant-step, or Pollard rho, combined with Pohlig-Hellman if the order is smooth) needs about `sqrt(2^38) = 2^19` steps, which takes well under a second. PARI/GP's `elllog` does this.

A discrete log `k` with `T_p = k * S_p` is only determined modulo `ord(S_p)`. So we learn:

```
m = k_p (mod ord_p)
m = k_q (mod ord_q)
```

If `ord_p` and `ord_q` are coprime, CRT gives `m` modulo `L = ord_p * ord_q`, about 77 bits.

The flag is 14 bytes with a known 7-byte prefix and a known 1-byte suffix. As an integer:

```
m = int("Alpaca{") * 2^56  +  (6 unknown bytes) * 2^8  +  0x7d
```

So `m = base + x`, where

```
base = int.from_bytes(b"Alpaca{" + b"\x00"*6 + b"}", "big")
0 <= x < 2^56
```

The candidates form a window of size `2^56` (about `7.2e16`), whereas `L` is about `8.7e22`. A window smaller than `L` contains at most one integer in any given residue class mod `L`. So the congruence from step 2.3 determines the flag **uniquely**, with no brute force over the flag space.

Note that the unknown 6 bytes occupy bits 8 to 55, **not** bits 0 to 47, because the closing `}` takes the lowest byte. Searching only `x < 2^48` finds nothing.

## Solution

### Per-prime discrete log

For `ell` in `{p, q}`:

1. Build `E_ell = EllipticCurve(F_ell, [2, 3])`.
2. Reduce `S` and `T` mod `ell` and check that they lie on the curve.
3. Compute `o = order(S mod ell)`.
4. Solve `k = log_{S mod ell}(T mod ell)` in `E_ell`, giving `m = k (mod o)`.

Results (obtained by running the script below):

|Prime|Group order `#E(F_ell)`|`ord(S)`|`m mod ord(S)`|
|---|---|---|---|
|`p = 577131489751`|577132018192|288566009096|223318757821|
|`q = 604663433347`|not needed|302331052781|247372533797|

For `p`, the order of `S` is exactly half the group order.

### CRT

Combining the two congruences:

```
m = 79804514606681471562309   (mod 87242465326805302095976)
```

The modulus equals `ord_p * ord_q` (the orders are coprime) and has 77 bits.

### Recover the flag

```
x = (a - base) mod L          # smallest non-negative offset
m = base + x                  # valid if x < 2^56
```

Decoding the 14 bytes of `m` gives:

```
Alpaca{prprpr}
```

### Full solution

```python
#!/usr/bin/env python3
from cypari import pari
from sympy.ntheory.modular import solve_congruence

# --- challenge data ---
p = 577131489751
q = 604663433347
A, B = 2, 3
S = (47472880544948864957374958450616147, 15718905651315016723553161697283736)
T = (299503460090901935082824843431273729, 5022588709750132765941314121276972)

# --- step 1: discrete log of T base S in E(F_p) and E(F_q) ---
def dlog_mod(n):
    pari(f"E=ellinit([{A},{B}],{n})")
    s = f"[{S[0] % n},{S[1] % n}]"
    t = f"[{T[0] % n},{T[1] % n}]"
    assert pari(f"ellisoncurve(E,{s})") == 1
    assert pari(f"ellisoncurve(E,{t})") == 1
    order = int(pari(f"ellorder(E,{s})"))
    k = int(pari(f"elllog(E,{t},{s},{order})"))
    return k, order

congruences = [dlog_mod(n) for n in (p, q)]
for (k, o), n in zip(congruences, (p, q)):
    print(f"mod {n}: m = {k} (mod {o})")

# --- step 2: CRT ---
a, L = solve_congruence(*congruences)
a, L = int(a), int(L)
print(f"m = {a} (mod {L}), L has {L.bit_length()} bits")

# --- step 3: flag = "Alpaca{" + 6 unknown bytes + "}" ---
base = int.from_bytes(b"Alpaca{" + b"\x00" * 6 + b"}", "big")
x = (a - base) % L
while x < 2**56:                      # unknown bytes sit in bits 8..55
    cand = (base + x).to_bytes(14, "big")
    print("flag candidate:", cand.decode(errors="replace"))
    x += L
```

```
mod 577131489751: m = 223318757821 (mod 288566009096)
mod 604663433347: m = 247372533797 (mod 302331052781)
m = 79804514606681471562309 (mod 87242465326805302095976), L has 77 bits
flag candidate: Alpaca{prprpr}
```

### Equivalent Sage version

```python
p = 577131489751
q = 604663433347
S = (47472880544948864957374958450616147, 15718905651315016723553161697283736)
T = (299503460090901935082824843431273729, 5022588709750132765941314121276972)

res, mods = [], []
for n in (p, q):
    E = EllipticCurve(GF(n), [2, 3])
    Sn, Tn = E(S[0] % n, S[1] % n), E(T[0] % n, T[1] % n)
    o = Sn.order()
    res.append(discrete_log(Tn, Sn, o, operation='+'))
    mods.append(o)

a = crt(res, mods) # sage's crt handles non-coprime moduli if consistent
L = lcm(mods)

base = int.from_bytes(b"Alpaca{" + b"\x00" * 6 + b"}", "big")
x = (int(a) - base) % int(L)
while x < 2**56:
    print((base + x).to_bytes(14, "big"))
    x += int(L)
```
{% endraw %}
