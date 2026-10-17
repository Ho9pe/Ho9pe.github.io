---
title: "httpd: an ICMP-triggered backdoor behind an HTTP decoy"
date: 2026-07-02 13:00:00 +0600
series: "crackmes.one"
platform: "crackmes.one"
summary: "A Go binary for FreeBSD waits for a magic ping and builds its AES key from packet fields. Most of those fields turn out to be predictable."
description: "A Go binary for FreeBSD waits for a magic ping and builds its AES key from packet fields. Most of those fields turn out to be predictable."
tags: ["rev", "go", "network", "crypto"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
**Category:** Reverse Engineering  
**Platform:** crackmes.one (author: crudd)  
**Binary:** FreeBSD ELF 64-bit, Go 1.17.1

## Overview

`httpd` is a Go binary that masquerades as a simple HTTP server while secretly operating as an ICMP-triggered backdoor. It listens for a magic ICMP echo request, derives an AES-128 key and CBC IV from fields in the captured packet, and decrypts a hardcoded 32-byte ciphertext - printing the flag to stdout.

The challenge is entirely static: no network access, no PCAP file, no running environment. The flag can be recovered purely by understanding the packet field offsets, the IV construction logic, and recognizing that most of those fields are **predictable constants** in any standard ICMP packet.

## Initial Recon

```bash
file httpd
# ELF 64-bit LSB executable, x86-64, FreeBSD 14.3, Go BuildID: qFhGj9dLilyvUQG0jioV/...

strings httpd | grep go1
# go1.17.1
```

The binary has full Go debug symbols intact, making function names readable in the disassembly. The module path is `crackmes.one/httpd` and the source file is `/home/crudd/httpd3/httpd.go`.

## Surface Behavior: The HTTP Decoy

`main.main` starts two goroutines:

1. An HTTP server on `localhost:8080` via `net/http.ListenAndServe`
2. A goroutine (mislabeled `net/http.init` at VA `0x748080` by objdump due to symbol table layout) that does the real work

The HTTP handler at `main.handler` (VA `0x747fa0`) responds with:

- `"Nothing to see here :{"` for `GET` requests
- `"Method not allowed"` + HTTP 405 for everything else

This is pure decoy. The interesting logic is all in the goroutine.

## The ICMP Listener Goroutine

The goroutine (VA `0x748080`) does the following:

### Step 1: Open a pcap handle

```go
pcap.OpenLive("re0", 0x640, true, -1)
```

It opens interface `re0` (a FreeBSD Realtek NIC) with a snaplen of 1600, in promiscuous mode.

### Step 2: Set a BPF filter

```go
handle.SetBPFFilter("icmp")
```

Only ICMP packets are captured.

### Step 3: Loop over packets and check for the magic packet

For each captured packet, it reads the raw bytes and validates four conditions. The packet is treated as a raw Ethernet frame, so all offsets include the 14-byte Ethernet header:

|Frame Offset|Field|Required Value|
|---|---|---|
|`0x10-0x11`|IP Total Length (byteswapped)|`0x0020` (32 bytes)|
|`0x22`|ICMP Type|`0x08` (Echo Request)|
|`0x26-0x27`|ICMP Identifier|`0x1337`|
|`0x2a-0x2d`|ICMP Data (first 4 bytes)|`0xe55fdec6`|

If any check fails, the packet is discarded and the loop continues.

The IP total length of 32 means: IP header (20) + ICMP header (8) + ICMP data (4) = 32 bytes. This is a minimal ICMP echo request carrying exactly 4 bytes of payload.

### Step 4: Construct the AES IV

Once the magic packet is found, the goroutine builds a 16-byte IV by reading fields directly out of the raw frame bytes:

```
iv[ 0: 2] = byteswap( (0xe55f) XOR checksum_le )
iv[ 2: 6] = frame[0x14:0x18]      ← IP Flags + Frag Offset + TTL + Protocol
iv[ 6: 8] = frame[0x24:0x26]      ← ICMP Checksum (as raw LE bytes)
iv[ 8:12] = frame[0x2a:0x2e]      ← ICMP Data = 0xe55fdec6 → bytes [c6 de 5f e5]
iv[12:14] = frame[0x26:0x28]      ← ICMP ID = 0x1337 → bytes [37 13]
iv[14:16] = byteswap( (0xdec6) XOR checksum_le )
```

Where `checksum_le` is the raw 2-byte ICMP checksum read as a little-endian uint16 (i.e., the bytes are not byteswapped before being stored at `iv[6:8]`).

The assembly for this is in the function body, built incrementally via `runtime.makeslice` and `runtime.growslice` calls:

```asm
748291:  movzwl 0x24(%rax),%edx      ; read ICMP checksum into edx (zero-extend)
748295:  mov    %dx,0x42(%rsp)       ; save checksum_le

74828a:  mov    0x2a(%rax),%ecx      ; read ICMP data dword
7482ce:  shr    $0x10,%ecx           ; ecx = magic >> 16 = 0xe55f
7482d6:  xor    %ebx,%ecx           ; ecx = 0xe55f ^ checksum_le
7482d9:  rol    $0x8,%cx            ; byteswap the 16-bit result
7482dd:  mov    %cx,(%rax)           ; iv[0:2] = result

74832b:  mov    0x14(%rdx),%ebx      ; read frame[0x14..0x17] as dword
74832e:  mov    %ebx,0x2(%rax)       ; iv[2:6] = those 4 bytes

748374:  movzwl 0x24(%rdx),%ebx      ; read checksum again
748378:  mov    %bx,0x6(%rax)        ; iv[6:8] = checksum_le bytes

7483c1:  mov    0x2a(%rdx),%ebx      ; read magic dword
7483c4:  mov    %ebx,0x8(%rax)       ; iv[8:12] = [c6 de 5f e5]

748408:  movzwl 0x26(%rdx),%ebx      ; read ICMP ID = 0x1337 as LE = 0x3713
74840c:  mov    %bx,0xc(%rax)        ; iv[12:14] = [37 13]

748454:  movzwl 0x40(%rsp),%ebx      ; load precomputed byteswap(0xdec6 ^ checksum_le)
748459:  mov    %bx,0xe(%rax)        ; iv[14:16] = result
```

### Step 5: AES-128-CBC Decryption

The goroutine allocates a 32-byte buffer (`puVar5`) and fills it with hardcoded constants using four `movabs` instructions:

```asm
7484d2:  movabs $0xc07edfb429a5f151,%rcx
7484dc:  mov    %rcx,(%rax)         ; puVar5[0:8]

7484df:  movabs $0xb34e3d248f2f3b2a,%rcx
7484e9:  mov    %rcx,0x8(%rax)      ; puVar5[8:16]

7484ed:  movabs $0x8cdd9c0bcfb0ed5a,%rcx
7484f7:  mov    %rcx,0x10(%rax)     ; puVar5[16:24]

7484fb:  movabs $0x0c64c43e9b0ee6cd,%rcx
748505:  mov    %rcx,0x18(%rax)     ; puVar5[24:32]
```

Reading these as little-endian bytes gives the 32-byte ciphertext:

```
51 f1 a5 29 b4 df 7e c0  2a 3b 2f 8f 24 3d 4e b3
5a ed b0 cf 0b 9c dd 8c  cd e6 0e 9b 3e c4 64 0c
```

The decryption call sequence in the assembly is:

```asm
748509:  mov    0x60(%rsp),%rcx     ; rcx = IV slice pointer
74850e:  mov    %rcx,(%rsp)         ; arg[0] = IV ptr  ← KEY ptr
748512:  movq   $0x10,0x8(%rsp)     ; arg[8] = 16      ← KEY len
74851b:  mov    0x48(%rsp),%rdx     ; rdx = IV cap
748520:  mov    %rdx,0x10(%rsp)     ; arg[16] = IV cap ← KEY cap
748525:  call   628e00 <crypto/aes.NewCipher>
```

**Critically: `NewCipher` is called with the IV slice as the key.** Not a separate key - the same 16-byte IV is used as both the AES key and the CBC IV.

```asm
748572:  mov    0x88(%rsp),%rcx     ; Block.type
74857a:  mov    %rcx,(%rsp)
74857e:  mov    0x78(%rsp),%rcx     ; Block.data
748583:  mov    %rcx,0x8(%rsp)
748588:  mov    0x60(%rsp),%rcx     ; IV ptr ← same 0x60 slot as above
74858d:  mov    %rcx,0x10(%rsp)     ; IV slice for CBC
748592:  movq   $0x10,0x18(%rsp)    ; IV len = 16
7485a5:  call   625260 <crypto/cipher.NewCBCDecrypter>
```

And CryptBlocks decrypts `puVar5` (32 bytes of ciphertext) into the output buffer, which is then printed via `fmt.Fprintln`.

So the full decryption is:

```
plaintext = AES_CBC_Dec(key=IV, IV=IV, ciphertext=puVar5)
```

## The Key Insight: Most IV Bytes Are Constants

This is where the static solution becomes possible.

The IV depends on values read from the raw packet frame. Let's map every byte:

|IV bytes|Source|Varies?|
|---|---|---|
|`[0:2]`|`byteswap(0xe55f XOR cksum_le)`|Yes - depends on ICMP checksum|
|`[2:6]`|`frame[0x14:0x18]`|**Mostly fixed** - see below|
|`[6:8]`|`frame[0x24:0x26]` (ICMP checksum raw bytes)|Yes - depends on ICMP checksum|
|`[8:12]`|`frame[0x2a:0x2e]` (ICMP data magic)|**Fixed**: `c6 de 5f e5`|
|`[12:14]`|`frame[0x26:0x28]` (ICMP ID = 0x1337)|**Fixed**: `37 13`|
|`[14:16]`|`byteswap(0xdec6 XOR cksum_le)`|Yes - depends on ICMP checksum|

### Frame offset 0x14 is NOT the source IP

This is the critical realization. With a 14-byte Ethernet header, the IP header starts at byte 14 (`0x0e`). Mapping out the IP header fields:

|Frame Offset|IP Header Byte|Field|
|---|---|---|
|`0x0e`|0|Version + IHL|
|`0x0f`|1|DSCP + ECN|
|`0x10`|2-3|**Total Length** (checked: must be 0x0020)|
|`0x12`|4-5|Identification|
|`0x14`|6-7|**Flags + Fragment Offset**|
|`0x16`|8|**TTL**|
|`0x17`|9|**Protocol** (always 0x01 for ICMP)|
|`0x18`|10-11|Header Checksum|
|`0x1a`|12-15|Source IP|
|`0x1e`|16-19|Destination IP|

So `frame[0x14:0x18]` = `[Flags_byte, Frag_byte, TTL, Protocol]`, **not** the source IP. The source IP (at `0x1a`) is never read.

For a standard non-fragmented ICMP packet from a Unix-like system:

- **Flags byte** = `0x40` (Don't Fragment bit set)
- **Fragment offset** = `0x00`
- **TTL** = `0x40` (64, the default on Linux and FreeBSD)
- **Protocol** = `0x01` (ICMP)

So `iv[2:6]` = `[0x40, 0x00, 0x40, 0x01]` - predictable constants.

### The ICMP checksum depends only on the sequence number

The ICMP packet structure for the magic packet:

```
Type=0x08, Code=0x00, Checksum=?, ID=0x1337, Seq=?, Data=[c6 de 5f e5]
```

Type, ID, and Data are all fixed by the magic checks. The checksum is computed over the entire ICMP packet (with checksum field zeroed). The only free variable is the **ICMP sequence number** - a 16-bit field, giving 65,536 possible checksums.

This means the entire IV is determined by a single 16-bit value (the ICMP sequence number), assuming standard packet fields. That's fully enumerable.

## Solving It

With `iv[2:6]` = `[0x40, 0x00, 0x40, 0x01]` (fixed) and `iv[8:14]` = `[c6 de 5f e5 37 13]` (fixed), we iterate over all 65,536 possible ICMP sequence numbers, compute the resulting IV, and attempt decryption:

```python
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def icmp_checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return ~s & 0xFFFF

ct = bytes.fromhex(
    '51f1a529b4df7ec02a3b2f8f243d4eb3'
    '5aedb0cf0b9cdd8ccde60e9b3ec4640c'
)

for seq in range(65536):
    # Compute ICMP checksum for this seq value
    icmp_pkt = struct.pack('>BBHHH', 8, 0, 0, 0x1337, seq) + b'\xc6\xde\x5f\xe5'
    cksum = icmp_checksum(icmp_pkt)

    # Read checksum as LE uint16 (as x86 movzwl would see it in network-order bytes)
    cksum_le = ((cksum & 0xff) << 8) | (cksum >> 8)

    # Build the 16-byte IV
    magic = 0xe55fdec6
    v0  = ((magic >> 16) ^ cksum_le) & 0xFFFF
    bv0 = ((v0  << 8) | (v0  >> 8)) & 0xFFFF
    v14 = ((magic & 0xFFFF) ^ cksum_le) & 0xFFFF
    bv14= ((v14 << 8) | (v14 >> 8)) & 0xFFFF

    iv = (struct.pack('<H', bv0) +
          bytes([0x40, 0x00, 0x40, 0x01]) +   # flags, frag, TTL=64, proto=ICMP
          struct.pack('<H', cksum_le) +
          bytes([0xc6, 0xde, 0x5f, 0xe5]) +   # magic (fixed)
          bytes([0x37, 0x13]) +               # ICMP ID 0x1337 (fixed)
          struct.pack('<H', bv14))

    # key == IV (same slice passed to both NewCipher and NewCBCDecrypter)
    dec = Cipher(algorithms.AES(iv), modes.CBC(iv),
                 backend=default_backend()).decryptor()
    pt = dec.update(ct) + dec.finalize()

    score = sum(1 for b in pt if 32 <= b < 127)
    if score > 26:
        print(f"seq={seq}: {''.join(chr(b) if 32<=b<127 else '.' for b in pt)}")
        break
```

Output:

```
seq=9181: CMO{fUn_w1th_m4g1c_p4ck3t5}.....
```

The last 5 bytes are AES block padding and not part of the flag.

**Flag: `CMO{fUn_w1th_m4g1c_p4ck3t5}`**

## Summary of the Encryption Scheme

```
ICMP sequence = 9181  (seq used when author tested the binary)

ICMP checksum = icmp_checksum([08 00 00 00 37 13 23 D2 C6 DE 5F E5])
              = 0x7856  (network order)
              → cksum_le = 0x5678

iv[ 0: 2] = byteswap(0xe55f XOR 0x5678) = byteswap(0xb327) = [0x27, 0xb3]
iv[ 2: 6] = [0x40, 0x00, 0x40, 0x01]    ← flags=DF, frag=0, TTL=64, proto=ICMP
iv[ 6: 8] = [0x56, 0x78]                ← cksum_le as bytes
iv[ 8:12] = [0xc6, 0xde, 0x5f, 0xe5]   ← ICMP data magic
iv[12:14] = [0x37, 0x13]               ← ICMP ID 0x1337
iv[14:16] = byteswap(0xdec6 XOR 0x5678) = byteswap(0x88be) = [0xbe, 0x88]

key = iv  (same 16-byte value used for both AES key and CBC IV)

AES_CBC_Dec(key=iv, IV=iv, ct=puVar5) → "CMO{fUn_w1th_m4g1c_p4ck3t5}"
```
{% endraw %}
