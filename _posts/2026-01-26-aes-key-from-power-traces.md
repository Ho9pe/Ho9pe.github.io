---
title: "DPA4Baby: recovering an AES key from power traces"
date: 2026-01-26 20:00:00 +0600
summary: "Correlation power analysis turns a 2^128 key search into 16 × 256 guesses. Hamming-weight predictions, correlated against 10,000 power traces, recover the AES key one byte at a time."
description: "Correlation power analysis turns a 2^128 key search into 16 × 256 guesses. Hamming-weight predictions, correlated against 10,000 power traces, recover the AES key one byte at a time."
tags: ["hardware", "crypto"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
A hardware CTF challenge: the files are power-consumption traces captured while a device ran AES, plus the plaintext for each encryption. The goal is the secret key. AES itself is fine here. The leak is physical: the chip's power draw depends on the data it is processing, and that is enough to pull the key out one byte at a time.

## What we're given

```python
import numpy as np

data = np.load("sca1.npz")
for k in data.files:
    print(f"{k}: {data[k].shape}, {data[k].dtype}")
```

```
traces: (100000, 640), float64
plaintexts: (100000, 16), int64
```

That's 100,000 encryptions, each a 640-sample power trace with its 16-byte plaintext.

![Mean power trace across all encryptions](/assets/img/posts/sca-mean-power-trace.png)

Averaging the traces shows nothing you could read by eye: no visible AES rounds, just jitter around 0.5. That's the point of the attack below. The key-dependent signal is far too small to see in a plot, but it shows up clearly in a correlation.

## Why power leaks the key

CMOS logic draws power when bits switch, so a value with more `1` bits tends to cost slightly more to process. The usual model of that is the **Hamming weight** (HW), the number of set bits: `HW(0b00001111) = 4`, `HW(0xFF) = 8`.

The attack targets the first round of AES:

```
plaintext ──► AddRoundKey (⊕ key) ──► SubBytes (S-box) ──► ShiftRows ──► …
                                          ▲
                              attack point: SBOX[p ⊕ k]
```

After the first SubBytes, byte *i* of the state is `SBOX[plaintext[i] ⊕ key[i]]`. The plaintext is known, and the value depends on **one key byte only**. So each byte can be guessed on its own: 16 × 256 = 4,096 guesses instead of 2¹²⁸.

## Correlation power analysis

For one key byte:

1. For every guess `k` in 0–255, predict the intermediate value of each trace: `v = SBOX[p ⊕ k]`.
2. Turn the predictions into predicted power: `HW(v)`.
3. At every time sample, compute the Pearson correlation between the predicted power and the measured power across all traces.
4. The right guess is the one whose correlation peaks highest, at the moment the device actually handles that byte.

With a wrong guess, the predictions are effectively random with respect to the real data, so the correlation stays near zero. With the right one, the predictions track what the chip really computed.

## Implementation

`SBOX` is the standard 256-entry AES S-box.

```python
def hamming_weight(n):
    return bin(n).count('1')

def cpa_attack_byte(traces, plaintexts, byte_index, num_traces=None):
    if num_traces is None:
        num_traces = len(traces)
    traces = traces[:num_traces]
    plaintexts = plaintexts[:num_traces]

    num_samples = traces.shape[1]
    max_corr, best_key = 0, 0

    for key_guess in range(256):
        intermediate = np.array([SBOX[plaintexts[i, byte_index] ^ key_guess]
                                 for i in range(num_traces)])
        hw = np.array([hamming_weight(v) for v in intermediate])

        correlations = np.zeros(num_samples)
        for sample in range(num_samples):
            correlations[sample] = abs(np.corrcoef(hw, traces[:, sample])[0, 1])

        if correlations.max() > max_corr:
            max_corr, best_key = correlations.max(), key_guess

    return best_key, max_corr
```

The full attack runs this for all 16 bytes on the first 10,000 traces (of the 100,000 available):

```python
recovered_key = []
for byte_idx in range(16):
    key_byte, corr = cpa_attack_byte(data["traces"], data["plaintexts"], byte_idx, num_traces=10000)
    recovered_key.append(key_byte)
    print(f"byte {byte_idx:2d}: 0x{key_byte:02x}  corr {corr:.4f}")

print(bytes(recovered_key).hex(), bytes(recovered_key).decode())
```

## Result

```
byte  0: 0x44  corr 0.1117
byte  1: 0x50  corr 0.0854
byte  2: 0x41  corr 0.0959
byte  3: 0x34  corr 0.0839
byte  4: 0x42  corr 0.0851
byte  5: 0x61  corr 0.0996
byte  6: 0x62  corr 0.0958
byte  7: 0x79  corr 0.0911
byte  8: 0x47  corr 0.0930
byte  9: 0x6f  corr 0.0917
byte 10: 0x67  corr 0.0833
byte 11: 0x6f  corr 0.0830
byte 12: 0x47  corr 0.0875
byte 13: 0x61  corr 0.1037
byte 14: 0x67  corr 0.1011
byte 15: 0x61  corr 0.1055
4450413442616279476f676f47616761 DPA4BabyGogoGaga
```

The key is printable ASCII, and it is the flag: **`DPA4BabyGogoGaga`**. "DPA" is differential power analysis, and "Baby" marks it as the warm-up.

The winning correlations are only 0.08–0.11, which looks weak. But the usual rule of thumb puts the noise floor at about 4/√N, which is 0.04 for 10,000 traces. Every correct byte sits at roughly twice that, and the key decodes to readable text, which confirms it. The run took about nine minutes, almost all of it in the per-sample `np.corrcoef` loop. Computing all 640 correlations at once with matrix operations would cut that to seconds.

## How devices defend against this

- **Masking:** randomise intermediate values (compute on `x ⊕ m` with a fresh random mask `m`), so power no longer correlates with the real data. Higher-order masking defends against attacks that combine several samples.
- **Hiding:** random delays, dummy operations and shuffled S-box order smear the leak across time, so many more traces are needed.
- **Hardware:** dual-rail logic, which balances power consumption, plus on-chip noise generators and shielding.

The broader lesson is that a cipher can be mathematically sound and still leak its key through the hardware that runs it.

## Further reading

- P. Kocher, J. Jaffe, B. Jun, "Differential Power Analysis," CRYPTO 1999.
- E. Brier, C. Clavier, F. Olivier, "Correlation Power Analysis with a Leakage Model," CHES 2004.
- S. Mangard, E. Oswald, T. Popp, *Power Analysis Attacks*, Springer 2007.
- ChipWhisperer, an open-source platform for side-channel experiments.
{% endraw %}
