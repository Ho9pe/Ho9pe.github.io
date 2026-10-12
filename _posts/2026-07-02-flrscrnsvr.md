---
title: "FLRSCRNSVR: peeling a screensaver's three-stage cipher"
date: 2026-07-02 11:00:00 +0600
series: "crackmes.one"
platform: "crackmes.one"
summary: "A 64-bit .scr hides a 25-character check behind junk code. Undoing a reversal, a position-dependent XOR and a substitution recovers the flag."
description: "A 64-bit .scr hides a 25-character check behind junk code. Undoing a reversal, a position-dependent XOR and a substitution recovers the flag."
tags: ["rev", "windows"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
## Challenge Overview

**File Type:** PE32+ executable (64-bit Windows screensaver)  
**Platform:** Windows  
**Category:** Reverse Engineering  

---

## Background Theory

### What is a Windows Screensaver (.SCR)?

A Windows screensaver file (.SCR) is essentially a regular Windows PE executable with a `.scr` extension instead of `.exe`. Screensavers support specific command-line arguments:

- `/s` or `-s`: Run the screensaver in full-screen mode
- `/c` or `-c`: Show the configuration dialog
- `/p <HWND>` or `-p <HWND>`: Preview mode in the given window handle

This standardized interface makes screensavers an interesting medium for CTF challenges, as they can hide functionality behind different execution modes.

### PE32+ Import Address Table (IAT)

The Import Address Table contains references to all external functions a program uses from DLLs. Analyzing the IAT gives us insight into what the program might do:

**Key imports from this binary:**

- **KERNEL32.dll**: Core Windows APIs (process, file, registry operations)
- **USER32.dll**: Window management and UI functions
- **GDI32.dll**: Graphics Device Interface (drawing functions)
- **ADVAPI32.dll**: Registry access functions
- **VCRUNTIME140.dll**: Visual C++ runtime

The presence of registry functions (`RegCreateKeyExW`, `RegSetValueExW`, `RegQueryValueExW`) immediately suggests the program stores or retrieves data from the Windows Registry.

### Anti-Analysis Techniques

This binary employs several **junk code** patterns to make reverse engineering more difficult:

1. **Dummy API calls**: Creating and immediately deleting GDI objects
2. **Meaningless loops**: Incrementing counters that are never used
3. **Repeated registry operations**: Opening and closing keys without reading data
4. **Performance counter queries**: Querying timers without using the results

These patterns clutter the decompiled code and make it harder to identify the actual logic.

---

## Initial Reconnaissance

### File Identification

```bash
$ file FLRSCRNSVR.SCR
FLRSCRNSVR.SCR: PE32+ executable for MS Windows 6.00 (GUI), x86-64, 6 sections
```

The file is a 64-bit Windows GUI application, which means we need a 64-bit disassembler like IDA Pro, Ghidra, or Binary Ninja.

### Loading into IDA Pro

After loading the binary into IDA Pro and allowing it to auto-analyze, we can examine:

- The entry point (`start`)
- String references (Shift+F12)
- Function names and cross-references
- The Import Address Table

### Key Strings Found

- `"Crackmes.one"` - Default text value
- `"Control Panel\\Desktop"` - Registry path (red herring)
- `"Software\\FLRSCRNSVR"` - Actual registry storage location
- Various window class names and resource identifiers

---

## Static Analysis

### Program Flow Analysis

#### Entry Point: `start()` and `WinMain()`

```c
__int64 start()
{
    sub_140004B58();  // Security cookie initialization
    return __scrt_common_main_seh();
}
```

The `start` function performs standard Windows initialization and calls `WinMain`, the main entry point for GUI applications.

#### WinMain - Command Line Parsing

The `WinMain` function implements the standard screensaver command-line interface:

```c
if (!wcsncmp(lpCmdLine, L"/c", 2) || !wcsncmp(lpCmdLine, L"-c", 2))
{
    // Configuration mode - shows dialog
    DialogBoxParamW(hInstance, (LPCWSTR)0x82, 0LL, DialogFunc, 0LL);
}
else if (!wcsncmp(lpCmdLine, L"/s", 2) || !wcsncmp(lpCmdLine, L"-s", 2))
{
    // Screensaver mode - full screen
    nShowCmd = 3;
    dword_140008980 = 1;
}
else if (!wcsncmp(lpCmdLine, L"/p", 2) || !wcsncmp(lpCmdLine, L"-p", 2))
{
    // Preview mode
    nShowCmd = 4;
}
```

**Key observation:** The `/c` configuration mode triggers a dialog box handled by `DialogFunc`. This is likely where we can interact with the challenge.

### Critical Functions Identified

Through cross-reference analysis, we identified several key functions:

1. **`sub_140002950`** - Window class registration (standard GUI setup)
2. **`sub_140002BF0`** - Main initialization function
3. **`DialogFunc`** - Dialog box handler (user interaction)
4. **`sub_140001AE0`** - Text processing and validation function
5. **`sub_140001300`** - Encryption/transformation function
6. **`sub_140001890`** - Retrieves encrypted data

---

## Understanding the Encryption Algorithm

### The Validation Function: `sub_140001AE0`

This function is the core of the challenge logic:

```c
LSTATUS __fastcall sub_140001AE0(wchar_t *Source)
{
    // ... initialization code ...
    
    v12 = -1LL;
    do
        ++v12;
    while ( Source[v12] );
    
    if ( v12 == 25 )  // Check if input is exactly 25 characters
    {
        wcscpy_s(Destination, 0x100uLL, Source);
        sub_140001300(Destination);      // Encrypt user input
        sub_140001890(v35);              // Get encrypted flag
        
        // Compare encrypted input with encrypted flag
        v15 = Destination;
        do
        {
            v16 = v15[520];  // v35 is at offset +520 from Destination
            v17 = *v15 - v16;
            if ( v17 )
                break;
            ++v15;
        }
        while ( v16 );
        
        if ( v17 )
        {
            // Mismatch - incorrect input
            return ...;
        }
        else
        {
            // Match! Set success flag
            byte_140008898 = 1;
        }
    }
    return result;
}
```

**Key insights:**
1. The function expects exactly **25 characters** of input
2. User input is encrypted via `sub_140001300`
3. The encrypted flag is retrieved via `sub_140001890`
4. If the encrypted input matches the encrypted flag, we win!

### The Encrypted Data: `aQj`

Using IDA's hex view, we can extract the encrypted flag from the `.rdata` section:

```
.rdata:00000001400064D0 aQj:
3C 00 51 00 6A 00 09 00 02 00 07 00 25 00 03 00
30 00 08 00 04 00 29 00 68 00 24 00 01 00 24 00
18 00 6B 00 77 00 0F 00 70 00 36 00 02 00 0E 00
0B 00 00 00
```

These are **wide-character (UTF-16LE) values**. Each character is 2 bytes:

- `0x3C 0x00` = Unicode character `<` (0x3C)
- `0x51 0x00` = Unicode character `Q` (0x51)
- `0x6A 0x00` = Unicode character `j` (0x6A)
- ... and so on

Converting to an array: `[0x3C, 0x51, 0x6A, 0x09, 0x02, 0x07, 0x25, 0x03, 0x30, 0x08, 0x04, 0x29, 0x68, 0x24, 0x01, 0x24, 0x18, 0x6B, 0x77, 0x0F, 0x70, 0x36, 0x02, 0x0E, 0x0B]`

That's **25 wide characters** (50 bytes of data + 2 null terminator bytes = 52 bytes = 0x34 bytes total).

### The Encryption Function: `sub_140001300`

This function implements a three-stage encryption algorithm:

#### Stage 1: Substitution Cipher

````c
wcscpy_s(Destination, 0x50uLL, L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789}_{=-");
wcscpy_s(v43, 0x50uLL, L"-={_}9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba");

for ( i = 0LL; i < v11; ++i )
{
    v17 = wcschr(Destination, *(_WORD *)(a1 + 2 * i));
    if ( v17 )
    {
        *(_WORD *)(a1 + 2 * i) = v43[v17 - Destination];
    }
}
```

This implements a **monoalphabetic substitution cipher**:
- Each character in the input is looked up in `Destination`
- Its position is used to index into `v43` to find the replacement character

**Mapping:**
```
Original: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789}_{=-
Cipher:   -={_}9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba
````

For example:

- `'a'` → `'-'`
- `'C'` → `'X'`
- `'}'` → `'}'` (maps to itself)

#### Stage 2: XOR with Key

````c
v32[0] = 4980806;  // 0x004BFF46
v32[1] = 5374017;  // 0x0051FF41
v32[2] = 5374021;  // 0x0051FF45
v32[3] = 4980801;  // 0x004BFF41
v32[4] = 70;       // 0x00000046

for ( j = 0LL; j < v11; ++j )
{
    LOWORD(v25) = *((_WORD *)v32 + j % v10) + j;
    *(_WORD *)(a1 + 2 * j) ^= v25;
}
```

The code treats the DWORD array `v32` as a WORD array by casting `(_WORD *)v32`. This means we read **16-bit values** sequentially from memory:

**Breaking down the DWORDs into WORDs:**
```
DWORD 4980806 (0x004BFF46):
  Low word:  0xFF46  (at index 0)
  High word: 0x004B  (at index 1)

DWORD 5374017 (0x0051FF41):
  Low word:  0xFF41  (at index 2)
  High word: 0x0051  (at index 3)

DWORD 5374021 (0x0051FF45):
  Low word:  0xFF45  (at index 4)
  High word: 0x0051  (at index 5)

DWORD 4980801 (0x004BFF41):
  Low word:  0xFF41  (at index 6)
  High word: 0x004B  (at index 7)

DWORD 70 (0x00000046):
  Low word:  0x0046  (at index 8)
  High word: 0x0000  (at index 9) ← NULL terminator!
````

The key length `v10` is calculated by counting until a null WORD is found, so **v10 = 9**.

The XOR key as WORDs: `[0xFF46, 0x004B, 0xFF41, 0x0051, 0xFF45, 0x0051, 0xFF41, 0x004B, 0x0046]`

Interestingly, looking at the low bytes: `0x46='F', 0x4B='K', 0x41='A', 0x51='Q', 0x45='E'...`

The key spells: **"FKAQEQAKF"** (with high bytes mostly being 0x00 or 0xFF as noise).

**The XOR operation:**

- For character at position `j`, the XOR key is: `key_words[j % 9] + j`
- The addition of `j` means the effective key changes for each position!

#### Stage 3: String Reversal

````c
if ( v11 >> 1 )
{
    v28 = (_WORD *)(a1 - 2 + 2 * v11);
    do
    {
        v29 = *(_WORD *)(a1 + 2 * v12);
        *(_WORD *)(a1 + 2 * v12) = *v28;
        *v28 = v29;
        ++v12;
        --v28;
    }
    while ( v12 < v11 >> 1 );
}
```

This is a simple **string reversal** - characters are swapped from both ends:
- Character 0 ↔ Character 24
- Character 1 ↔ Character 23
- ... and so on

### Summary of Encryption

**Encryption Process:**
```
Plaintext 
  ↓
[1. Substitution Cipher]
  ↓
[2. XOR with position-dependent key]
  ↓
[3. Reverse string]
  ↓
Ciphertext
```

---

## Decryption Process

To recover the flag, we need to **reverse each step** in **reverse order**:
```
Ciphertext (aQj)
  ↓
[3. Reverse string] ← Do first
  ↓
[2. XOR with position-dependent key] ← Do second
  ↓
[1. Reverse substitution] ← Do last
  ↓
Plaintext (flag)
````

### Step 1: Un-Reverse the String

Simply swap characters from both ends:

```python
n = len(encrypted)
unreversed = encrypted[:]
for i in range(n // 2):
    unreversed[i], unreversed[n-1-i] = unreversed[n-1-i], unreversed[i]
```

### Step 2: Un-XOR with Key

XOR is its own inverse (A ⊕ B ⊕ B = A), so we apply the same XOR operation:

```python
key_words = [0xFF46, 0x004B, 0xFF41, 0x0051, 0xFF45, 0x0051, 0xFF41, 0x004B, 0x0046]

unxored = []
for j in range(len(unreversed)):
    key_val = (key_words[j % 9] + j) & 0xFFFF
    unxored.append(unreversed[j] ^ key_val)
```

### Step 3: Reverse Substitution

Swap the lookup tables:

```python
sub_from = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789}_{=-"
sub_to   = "-={_}9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"

result = []
for val in unxored:
    char = chr(val)
    idx = sub_to.find(char)  # Find in cipher alphabet
    if idx != -1:
        result.append(sub_from[idx])  # Replace with original alphabet
    else:
        result.append(char)

flag = ''.join(result)
```

---

## Solution Script

Here's the complete Python decryption script:

```python
import struct

# The encrypted data from aQj (25 wide-chars)
encrypted = [0x3C, 0x51, 0x6A, 0x09, 0x02, 0x07, 0x25, 0x03, 
             0x30, 0x08, 0x04, 0x29, 0x68, 0x24, 0x01, 0x24, 
             0x18, 0x6B, 0x77, 0x0F, 0x70, 0x36, 0x02, 0x0E, 0x0B]

# Substitution alphabets
sub_from = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789}_{=-"
sub_to   = "-={_}9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"

# XOR key as DWORDs
key_dwords = [4980806, 5374017, 5374021, 4980801, 70]

# Convert DWORDs to array of WORDs (as the code does)
key_words = []
for dword in key_dwords:
    key_words.append(dword & 0xFFFF)          # Low word
    key_words.append((dword >> 16) & 0xFFFF)  # High word

# Find actual key length (until null terminator)
v10 = 0
while v10 < len(key_words) and key_words[v10] != 0:
    v10 += 1

print(f"Key words: {[hex(k) for k in key_words[:v10]]}")
print(f"Key length: {v10}")

# DECRYPTION - reverse the encryption steps

# Step 1: Un-reverse the string
n = len(encrypted)
unreversed = encrypted[:]
for i in range(n // 2):
    unreversed[i], unreversed[n-1-i] = unreversed[n-1-i], unreversed[i]

# Step 2: Un-XOR with key
unxored = []
for j in range(len(unreversed)):
    key_val = (key_words[j % v10] + j) & 0xFFFF
    unxored.append(unreversed[j] ^ key_val)

# Step 3: Reverse substitution
result = []
for val in unxored:
    char = chr(val)
    idx = sub_to.find(char)
    if idx != -1:
        result.append(sub_from[idx])
    else:
        result.append(char)

flag = ''.join(result)
print(f"Flag: {flag}")
```

### Running the Script

```bash
$ python3 solve.py
Key words: ['0x46', '0x4c', '0x41', '0x52', '0x45', '0x52', '0x41', '0x4c', '0x46']
Key length: 9
Flag: CMO{frogt4s7ic_r3vers1ng}
```

**Flag: `CMO{frogt4s7ic_r3vers1ng}`**
{% endraw %}
