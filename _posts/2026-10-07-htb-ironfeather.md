---
title: "IronFeather: reversing a drone's custom KDF to rebuild its crash"
date: 2026-10-07 15:00:00 +0600
series: "HTB Sherlocks"
platform: "HTB Holmes CTF 2026"
summary: "A Holmes CTF 2026 Sherlock: a stripped PX4 binary hides a 384-round ARX key derivation. Reimplementing it decrypts the mission store and the flight log, which show the payload release, an injected motor failure and the crash site."
description: "A Holmes CTF 2026 Sherlock: a stripped PX4 binary hides a 384-round ARX key derivation. Reimplementing it decrypts the mission store and the flight log, which show the payload release, an injected motor failure and the crash site."
tags: ["rev", "crypto", "forensics"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
**Challenge:** `IronFeather.zip`: a PX4 SITL binary, an encrypted dataman store and an encrypted flight log.

## 1. Overview

The zip holds three files:

| File | Size | What it is |
|---|---|---|
| `px4` | 9.4 MB | Stripped x86-64 PIE ELF: PX4 SITL with OpenSSL statically linked |
| `dataman.encrypted` | 1.2 MB | Encrypted PX4 dataman store (missions, geofence, safe points) |
| `flight.ulg.encrypted` | 66 MB | Encrypted PX4 ULog flight recording |

The solve chain is linear:

1. Triage the ciphertexts: two 8-byte magics and a 60-byte header.
2. Find the crypto in the stripped binary by searching for the magic as an immediate operand.
3. Reverse the custom KDF: a 384-round ARX mixer feeding PBKDF2.
4. Reimplement the KDF and derive the key (both files share one salt, so one key opens both).
5. Decrypt to a raw dataman blob and a valid ULog.
6. Rebuild the dataman region map to find the live mission bank, then decode the mission.
7. Run forensics on the ULog: takeoff, release, failure injection, crash, disarm.
8. Geolocate the crash site.

## 2. Environment

```bash
sudo apt-get install -y binutils
pip3 install cryptography pyulog pyproj numpy
# only needed for the optional emulation cross-check in section 5:
pip3 install unicorn
mkdir -p ~/ctf && cd ~/ctf && unzip -o /path/to/IronFeather.zip
```

`xxd` is missing on minimal images. `od -A x -t x1z -v` is the portable substitute.

## 3. Container triage

```bash
od -A x -t x1z -v dataman.encrypted    | head -4
od -A x -t x1z -v flight.ulg.encrypted | head -4
```

```
000000 50 58 34 44 4d 45 4e 43 01 00 00 00 d0 70 12 00  >PX4DMENC.....p..<
000010 60 c2 00 30 9e 3f 46 4c 11 d1 46 45 a3 55 bf e8  >`..0.?FL..FE.U..<
000000 50 58 34 55 4c 45 4e 43 01 00 00 00 9b 3b 1a 04  >PX4ULENC.....;..<
000010 60 c2 00 30 9e 3f 46 4c 11 d1 46 45 a3 55 bf e8  >`..0.?FL..FE.U..<
```

The two magics are `PX4DMENC` (datastore) and `PX4ULENC` (log). **Q1 = `PX4DMENC`**, since the question asks about the datastore.

Bytes 12-16 hold a little-endian length. Comparing it against the file sizes:

```
dataman.encrypted:    size=1208528  file=1208588  overhead=60
flight.ulg.encrypted: size=68828059 file=68828119 overhead=60
```

Both files have exactly 60 bytes of overhead, so the field is the plaintext length and the header is 60 bytes. Bytes `0x10-0x20` are identical in both files (`60c200309e3f464c11d14645a355bfe8`). A reused GCM nonce would be catastrophic, so this is far more likely a KDF salt shared by both files. Bytes `0x20-0x2c` differ per file, which fits a per-file nonce.

Triage can't say where the tag sits or what is authenticated. That comes from the binary.

## 4. Finding the crypto in the stripped binary

**File offsets equal RVAs**, which matters for Q3:

```
readelf -S px4 | grep -A1 -E ' \.text| \.rodata'
  [14] .text    PROGBITS 0000000000110000  00110000
  [16] .rodata  PROGBITS 00000000006a0080  006a0080
```

`strings` won't find `PX4DMENC`. Eight bytes are materialised as a 64-bit immediate (`movabs`), so search the raw bytes:

```python
d = open('px4','rb').read()
for pat in (b'PX4DMENC', b'AES-256-GCM'):
    hits, s = [], 0
    while (i := d.find(pat, s)) >= 0: hits.append(hex(i)); s = i + 1
    print(pat, hits)
```

The magic appears at `0x16ff20` (reader) and `0x170444` (writer). OpenSSL is statically linked with dynamic symbols intact, so `objdump` names the crypto calls even though the PX4 code is stripped:

```bash
objdump -d -M intel --start-address=0x1703d0 --stop-address=0x170780 px4
```

The annotated writer:

```
17043d: mov  BYTE PTR [rsp+0x58], 1               ; version = 1
170442: movabs rax, 0x434e454d44345850            ; "PX4DMENC" (little-endian)
170451: mov  DWORD PTR [rsp+0x5c], ebx            ; plaintext size at hdr+0x0c
170463: call RAND_bytes                           ; 16-byte salt (generated once)
1704a0: call RAND_bytes                           ; 12-byte nonce -> hdr+0x20
1704d9: call 170af0                               ; <<< custom KDF (salt -> 32-byte key)
1704ff: call EVP_aes_256_gcm                      ; <<< cipher
1706d9: call EVP_EncryptUpdate                    ; rsi=NULL, r8d=0x2c: AAD = 44 bytes
1706f8: call EVP_EncryptUpdate                    ; the plaintext
170748: call EVP_CIPHER_CTX_ctrl                  ; GET_TAG, 16 bytes -> hdr+0x2c
1707b1: mov  r12d, 0x3c                           ; write the 60-byte header first
```

**Q2 = `AES-256-GCM`.** The header struct is written before the ciphertext, and the AAD is only its first `0x2c` = 44 bytes:

| Offset | Size | Field |
|---|---|---|
| 0x00 | 8 | magic |
| 0x08 | 4 | version |
| 0x0c | 4 | plaintext size |
| 0x10 | 16 | PBKDF2 salt |
| 0x20 | 12 | GCM nonce |
| 0x2c | 16 | GCM tag |

On disk: `[0,44)` header (AAD), `[44,60)` tag, `[60,EOF)` ciphertext. The tag is not appended, which is why the usual `ct||tag` guess fails.

## 5. Reversing the custom KDF

The call at `0x1704d9` takes `rdi` = salt and `rsi` = a 32-byte output buffer. **Q3 = `0x170af0`.**

```bash
objdump -d -M intel --start-address=0x170af0 --stop-address=0x170d90 px4
```

The function has four phases.

**Phase 1: setup.** A 104-byte passphrase buffer is zeroed (`rep stos`, 13 qwords). The state is eight u32 words loaded from `0x6edf80`. Tables are at `0x6f0a40` (48-byte S-box), `0x6f0a80` (T1, 32 dwords) and `0x6f0b00` (T2, 32 dwords). Seeds: `eax=0x6d657461`, `ecx=0x4a`, `esi=0xde3814a6`, `r15d=0x8de43612`, `r10d=0x9e3779b9`, `r11d=0xb`. The compiler rotated the loop, so the first iteration jumps into the body at `0x170c02` and skips the preamble.

**Phase 2: the 384-round mixing loop.**

```
; body @0x170c02, i in edx
mov r8d,r10d ; xor r8d,esi ; xor r8d,r15d        ; t ^ T1val ^ T2val
add eax,r9d                                       ; acc += S-box byte
rol r8d,cl   (cl = (c&0xf)+3)                     ; rotate A
add r8d,eax
rol r8d,cl   (cl = ((esi>>27)&0xf)+5)             ; rotate B
mov [rsp+rax*4+0x20], r8d                         ; state[i&7] = r8
rol r8d,cl   (cl = i%19 + 1)                      ; rotate C (imul/sar = signed /19)
xor r8d,[state[(i+2)&7]] ; store back
add [state[(i+6)&7]], (c*0x01010101) ^ r8
cmp edx,0x17f ; jne preamble                      ; exit when i == 383

; preamble @0x170ba0 prepares round i+1
r15 = T2[(5*(i+1) + state[(i+4)&7]) & 0x1f]
esi = T1[((state[((i+1)+5)&7] >> 27) + r11) & 0x1f] ; r11 += 11
eax = state[(i+1)&7]                              ; <<< 0x170bf8, easy to miss
ecx = SBOX[((r15>>24) + (i+1)) % 48]
```

i runs 0..383 inclusive. **Q4 = 384.** It's an add-rotate-xor design over an eight-word state with a golden-ratio round constant (`0x9e3779b9`, subtracted as `0x61c88647`).

**Phase 3: whitening.** `out[0] = state[0] ^ 0x33020b01`, then for k=0..6: `out[k+1] = T2[(0x10+7k)&0x1f] ^ state[k+1] ^ rol(T1[(0x11+13k)&0x1f], k+2)`. `OPENSSL_cleanse` wipes the state. The remaining 72 bytes are a hard-coded pepper: 64 bytes from `0x6edfa0` plus the qword `0x6fb14a9923de7508`.

**Phase 4: PBKDF2.**

```
170d50: call EVP_sha256
170d57: mov r8d, 0x2000        ; iterations = 8192
170d60: push 0x20              ; dklen = 32
170d6a: mov ecx, 0x10          ; salt length = 16
170d6f: mov esi, 0x68          ; password length = 104
170d74: call PKCS5_PBKDF2_HMAC
```

**Q5 = PBKDF2** (HMAC-SHA256, 8192 iterations). The custom stage takes nothing from the file, so the passphrase is a constant. Only the salt varies, and it's shared, hence one key for both files.

**Expected passphrase** (104 bytes):
`696a8765f43ab74975728e713ecdd6d21cff4e65ae186769e854709fd0b61c877413d92ea8650cf13b9742cd58e6218ab40f73da369c51e217e249832cb5610ed8349f7205c15aed6813a74df02b965ebc410ad37f25e98456ab30c71d926bf40875de23994ab16f`

### Two ways to get it

**A. Pure-Python port**: `mix()` in the appendix script. **B. Emulation cross-check**, which is more robust if you hand-port a variant. Map the file at address 0, run the function in Unicorn, skip the `OPENSSL_cleanse` call and read the passphrase from `rdi` at `0x170d74`:

```python
from unicorn import *; from unicorn.x86_const import *
d = open('px4','rb').read(); mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0, ((len(d)+0xfff)&~0xfff) + 0x1000); mu.mem_write(0, d)
mu.mem_map(0x40000000, 0x100000); mu.mem_map(0x50000000, 0x10000)   # stack, TLS
mu.reg_write(UC_X86_REG_FS_BASE, 0x50000000)                         # stack canary read
sp = 0x40000000 + 0x80000 - 8; mu.mem_write(sp, (0xdead0000).to_bytes(8,'little'))
mu.reg_write(UC_X86_REG_RSP, sp)
mu.reg_write(UC_X86_REG_RDI, 0x50001000); mu.reg_write(UC_X86_REG_RSI, 0x50002000)
mu.hook_add(UC_HOOK_CODE, lambda uc,a,s,_: uc.reg_write(UC_X86_REG_RIP, 0x170d04) if a == 0x170cff else None)
mu.emu_start(0x170af0, 0x170d74)
passphrase = bytes(mu.mem_read(mu.reg_read(UC_X86_REG_RDI), 0x68))
```

The port and the emulation agree byte for byte.

### Porting pitfalls

- **The loop is rotated.** Treating `0x170ba0` as the loop head gives 383 rounds and a wrong key.
- **The accumulator is reloaded from state** in the preamble (`mov eax,[rsp+rdi*4+0x20]` at `0x170bf8`). It is easy to miss. Omitting it still gives 384 rounds and a plausible-looking wrong passphrase, and the first four output words come out wrong.
- **`sar` is not `>>`.** The `imul`/`sar` pair is the signed division-by-19 idiom. It only matches `i % 19` because `i >= 0`.
- **Rotate counts** are masked to 5 bits by `rol`.
- **`lea ecx,[rax+r14]` zero-extends** to 64 bits before the mod-48 reduction, so it is a 32-bit sum.

## 6. Key and decryption

```python
key = hashlib.pbkdf2_hmac('sha256', PASSPHRASE, salt, 8192, 32)
AESGCM(key).decrypt(nonce, ct + tag, aad)   # aad = b[:44]; nonce = b[32:44]; tag = b[44:60]; ct = b[60:]
```

**Q6 = `a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce`**. A successful GCM decrypt is proof of the key, nonce, AAD and tag placement. `flight.ulg` then starts with `ULog\x01\x12\x35`.

## 7. Dataman: which bank is live

`dataman.bin` is a flat, fixed-offset store with no index. Rebuild the region map from the size and max-index tables in `.rodata`:

```python
import struct
d = open('px4','rb').read()
print(struct.unpack('<10Q', d[0x6f09a0:0x6f09a0+80]))   # (60,60,12,36,36,12,60,60,44,12)
print(struct.unpack('<10I', d[0x6f0a00:0x6f0a00+40]))   # (32,32,1,64,64,1,10000,10000,1,1)
```

Multiplying size by max index and accumulating gives the layout below. The total is exactly 1,208,528, the plaintext length, which validates the map.

| Key | Offset | Length | Populated |
|---|---|---|---|
| SAFE_POINTS_0/1, SAFE_STATS | 0x000000 | 0xf0c | stats only |
| FENCE_POINTS_0/1, FENCE_STATS | 0x000f0c | 0x120c | stats only |
| **WAYPOINTS_OFFBOARD_0** | **0x002118** | 600000 | **yes** |
| WAYPOINTS_OFFBOARD_1 | 0x0948d8 | 600000 | all zero |
| MISSION_STATE | 0x127098 | 44 | yes |
| COMPAT | 0x1270c4 | 12 | yes |

**Q7 = 0.** The `MISSION_STATE` payload (at `0x12709c`, after a 4-byte sector header) confirms it:

```
timestamp 500.336 s | current_seq 18 | land_start 23 | land_index 23
mission_id 3864311617 | geofence_id 0 | safe_points_id 0 | count 24
```

`mission_id` and `count` match the log's `mission_result`, so this is the mission that was flown.

## 8. Decoding the mission

Each record is a 4-byte sector header plus a 56-byte `mission_item_s`, so the stride is 60. Fields used: `lat`/`lon` (doubles at +0/+8), `params[0]` (+16), `altitude` (+40), `nav_cmd` (u16 at +44).

| Item | Command | Notes |
|---|---|---|
| 0 | NAV_TAKEOFF (22) | 51.4997000, -0.1608000, 15 m |
| 9 | NAV_WAYPOINT (16) | hover, 2 m relative, 3 s dwell |
| **10** | **DO_SET_ACTUATOR (187)** | **param1 = 1.0: payload release** |
| 11 | NAV_DELAY (93) | 2 s |
| 12 | DO_SET_ACTUATOR (187) | param1 = 0.0: actuator reset |
| 23 | NAV_LAND (21) | 51.4997000, -0.1608000 |

Item 24 is a zero sector header, so **Q8 = 24 items**. **Q9 = 10**: item 12 is the same command with param1 = 0, a tempting wrong answer. **Q10 = `51.49970,-0.16080`**, agreeing with `land_index` = 23. The drone never got there: `current_seq` stalled at 18.

## 9. Flight-log forensics

### Timeline (from `vehicle_command`, `vehicle_land_detected`, `vehicle_status`, `sensor_combined`)

| t (s) | Event |
|---|---|
| 285.26 | Armed |
| 287.072 | Liftoff (`landed` clears) |
| 446.656 | Release: `DO_SET_ACTUATOR` param1 = 1 |
| 517.208-517.988 | Low-battery warning, Hold failsafe |
| **520.764** | **Command 420 injected** (`MAV_CMD_INJECT_FAILURE`, unit 101 = motor, type 1 = off) |
| 520.772 | Control allocator: "Stopping motors" |
| 525.852 | Impact (peak accelerometer spike, about 1229 m/s²) |
| 576.968 | "Disarmed by internal command" |

**Q13 = `MAV_CMD_INJECT_FAILURE`.** The injected command comes from source system/component 0/0, unlike every other command (system 1 or 255). **Q16 = 576.968.**

### Choosing the right measurement

The log has several position sources: `home_position`, `vehicle_global_position` (the EKF estimate), `vehicle_global_position_groundtruth` (simulator truth) and `vehicle_gps_position`. They agree to a few centimetres, but 7-decimal answers are only about 1 cm resolution, so the choice matters. The accepted answers all follow one rule: **use `vehicle_global_position` (the EKF) at the event time**.

- **Q11 takeoff:** EKF at liftoff (t=287.072 s) gives `51.4996987,-0.1607999`. `home_position` (`51.4996985,-0.1607997`) is the arming-time estimate and is not accepted.
- **Q12 release:** EKF at 446.656 s gives `51.5035602,-0.1608417`.
- **Q15 crash:** EKF at the impact instant (525.852 s) gives `51.5016938,-0.1620929`. The ground-truth topic gives `51.5016942,-0.1620927`, which is not accepted.
- **Q14 distance:** "how far did the drone travel" is **path length**: the sum of horizontal steps between release (446.656 s) and injection (520.764 s). That is 276.7 m from `vehicle_local_position`, so **277**. The straight-line displacement between the two points is about 224 m and is not accepted.

The decoded values, from `solve.py`:

```
Q11 takeoff 51.4996987,-0.1607999
Q12 release 51.5035602,-0.1608417
Q14 path    277 (276.71 m)
Q15 crash   51.5016938,-0.1620929
Q16 disarm  576.968
```

## 10. Nearest road (Q17)

The crash site is in Hyde Park's south edge. To identify the road, query OpenStreetMap (this step needs internet):

```
[out:json];way(around:60,51.5016938,-0.1620929)["highway"];out geom tags;
```

Pick the way whose geometry is closest to the point. It is the A315, **Knightsbridge**, about 5.5 m from the carriageway centreline. **Q17 = `Knightsbridge`.**

## Appendix: `solve.py`

Run from a directory containing `px4`, `dataman.encrypted` and `flight.ulg.encrypted`. It prints every value above except the OSM lookup.

```python
#!/usr/bin/env python3
"""IronFeather solver. Run in a dir containing px4, dataman.encrypted, flight.ulg.encrypted."""
import struct, hashlib
import numpy as np
from pyproj import Geod
from pyulog import ULog
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

M = 0xFFFFFFFF
rol = lambda v, c: ((v << (c & 31)) | (v >> (32 - (c & 31)))) & M if c & 31 else v & M
px4 = open('px4', 'rb').read()

# ---------- KDF (reimplementation of px4!0x170af0) ----------
SBOX = px4[0x6f0a40:0x6f0a40 + 48]
T1 = struct.unpack('<32I', px4[0x6f0a80:0x6f0a80 + 128])
T2 = struct.unpack('<32I', px4[0x6f0b00:0x6f0b00 + 128])
INIT = px4[0x6edf80:0x6edf80 + 32]
TAIL = px4[0x6edfa0:0x6edfa0 + 64] + struct.pack('<Q', 0x6fb14a9923de7508)

def mix():
    st = list(struct.unpack('<8I', INIT))
    i, esi, r15, r10, r11, ecx, eax = 0, 0xde3814a6, 0x8de43612, 0x9e3779b9, 0xb, 0x4a, 0x6d657461
    rounds = 0
    while True:                                   # body @0x170c02
        rounds += 1
        r9 = ecx & 0xff; edi = i & 7
        r8 = r10 ^ esi ^ r15
        esi = (esi >> 27) & 0xf
        eax = (eax + r9) & M
        r10 = (r10 - 0x61c88647) & M
        r8 = rol(r8, (ecx & 0xf) + 3)             # rotate A
        r8 = (r8 + eax) & M
        r8 = rol(r8, esi + 5)                     # rotate B
        st[edi] = r8
        r9 = (r9 * 0x1010101) & M
        r8 = rol(r8, i % 19 + 1)                  # rotate C
        r8 ^= st[(edi + 2) & 7]; st[(edi + 2) & 7] = r8
        st[(edi + 6) & 7] = (st[(edi + 6) & 7] + (r9 ^ r8)) & M
        if i == 0x17f: break                      # cmp edx,0x17f
        n = i + 1; j = n & 7                      # preamble @0x170ba0
        r15 = T2[(5 * n + st[(i + 4) & 7]) & 0x1f]
        esi = T1[((st[(j + 5) & 7] >> 27) + r11) & 0x1f]
        r11 = (r11 + 0xb) & M
        eax = st[j]                               # 0x170bf8: accumulator reloaded from state
        ecx = SBOX[((r15 >> 24) + n) % 48]
        i = n
    return st, rounds

st, ROUNDS = mix()
out = [st[0] ^ 0x33020b01] + [T2[(0x10 + 7*k) & 0x1f] ^ st[k+1] ^ rol(T1[(0x11 + 13*k) & 0x1f], k + 2) for k in range(7)]
PASSPHRASE = struct.pack('<8I', *out) + TAIL       # 104 bytes
derive = lambda salt: hashlib.pbkdf2_hmac('sha256', PASSPHRASE, salt, 8192, 32)

# ---------- decrypt ----------
def dec(src):
    b = open(src, 'rb').read()
    key = derive(b[16:32])
    return key, AESGCM(key).decrypt(b[32:44], b[60:] + b[44:60], b[:44])   # AAD = b[:44], tag at 44..60

key, dm = dec('dataman.encrypted'); _, ulg = dec('flight.ulg.encrypted')
open('dataman.bin', 'wb').write(dm); open('flight.ulg', 'wb').write(ulg)
print('rounds', ROUNDS); print('key', key.hex())

# ---------- dataman ----------
BANK0, BANK1 = 0x2118, 0x948d8
z = lambda o: not any(dm[o:o + 600000])
print('bank0 empty?', z(BANK0), '| bank1 empty?', z(BANK1))
items = []
for n in range(32):
    o = BANK0 + n * 60
    if dm[o] == 0: break
    lat, lon = struct.unpack('<dd', dm[o+4:o+20]); alt = struct.unpack('<f', dm[o+44:o+48])[0]
    cmd = struct.unpack('<H', dm[o+48:o+50])[0]
    p1 = struct.unpack('<f', dm[o+20:o+24])[0]
    items.append((n, cmd, lat, lon, alt, p1))
print('items', len(items))
for n, cmd, lat, lon, alt, p1 in items:
    if cmd == 187 and p1 == 1.0: print('payload release item', n)
print('land item', items[-1][0], f'{items[-1][2]:.5f},{items[-1][3]:.5f}')

# ---------- ULog ----------
G = Geod(ellps='WGS84'); u = ULog('flight.ulg')
T = lambda n: [d for d in u.data_list if d.name == n][0].data
near = lambda d, t: int(np.argmin(np.abs(d['timestamp'] / 1e6 - t)))
vc = T('vehicle_command')
t_rel = [vc['timestamp'][i] / 1e6 for i in range(len(vc['timestamp'])) if vc['command'][i] == 187 and vc['param1'][i] == 1.0][0]
t_inj = [vc['timestamp'][i] / 1e6 for i in range(len(vc['timestamp'])) if vc['command'][i] == 420][0]
gp, lp, vs = T('vehicle_global_position'), T('vehicle_local_position'), T('vehicle_land_detected')
ll = lambda t: (gp['lat'][near(gp, t)], gp['lon'][near(gp, t)])
fmt = lambda p: f'{p[0]:.7f},{p[1]:.7f}'
t_lift = [vs['timestamp'][i] / 1e6 for i in range(len(vs['timestamp'])) if vs['landed'][i] == 0][0]
sc = T('sensor_combined'); tt = sc['timestamp'] / 1e6
acc = np.linalg.norm(np.c_[sc['accelerometer_m_s2[0]'], sc['accelerometer_m_s2[1]'], sc['accelerometer_m_s2[2]']], axis=1)
t_imp = tt[np.argmax(np.where((tt > t_inj) & (tt < t_inj + 10), acc, 0))]
tl = lp['timestamp'] / 1e6; m = (tl >= t_rel) & (tl <= t_inj)
path = float(np.sum(np.hypot(np.diff(lp['x'][m]), np.diff(lp['y'][m]))))
print('t_rel', t_rel, 't_inj', t_inj, 't_lift', t_lift, 't_impact', t_imp)
print('Q11 takeoff', fmt(ll(t_lift)))
print('Q12 release', fmt(ll(t_rel)))
print('Q14 path', round(path), f'({path:.2f} m)')
print('Q15 crash  ', fmt(ll(t_imp)))
disarm = [l for l in u.logged_messages if 'Disarmed' in l.message][0]
print('Q16 disarm', disarm.timestamp / 1e6)
```
{% endraw %}
