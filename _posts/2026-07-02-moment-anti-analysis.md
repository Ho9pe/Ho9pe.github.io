---
title: "moment.exe: a static solve past 17 anti-analysis checks"
date: 2026-07-02 17:00:00 +0600
series: "crackmes.one"
platform: "crackmes.one"
summary: "Heavy anti-debugging, encoded strings and an event-gated flag path. Rebuilding the string table and reading call-site arguments recovers the flag without running the binary."
description: "Heavy anti-debugging, encoded strings and an event-gated flag path. Rebuilding the string table and reading call-site arguments recovers the flag without running the binary."
tags: ["rev", "windows", "anti-debug"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
**Flag:** `CMO{0xbadc00d5}`  
**Category:** Reverse Engineering  
**Difficulty:** Hard  
**Tools Used:** Python 3 (pefile, capstone), x64dbg, ScyllaHide

---

## 1. Initial Triage

The binary is a 64-bit Windows PE (`moment.exe`, ~1.2 MB). The README says:

> A Windows CTF for anyone interested in dealing with a binary that requires a mixed approach and circumventing various anti-tamper mechanisms.

Running `capa.exe` and static analysis reveals:
- 4072 `INT3`, 2002 `RDTSC`, 1007 `CPUID`, 13 `INT1`, 1 `INT2D`, 1147 `PUSHF` — heavy anti-debug/anti-tamper
- 9 PE sections, `.text` is ~1 MB
- Requires admin (manifest)
- Custom string encoding — no readable strings in the binary

Running the binary on FLARE-VM (which has analysis tools installed) produces two error messages and creates an empty `tmp.ggc` file. No flag is printed.

---

## 2. String Encoding (Type 1 Table)

All strings are encoded. A table at VA `0x140111680` holds entries of 16 bytes each:

```
struct type1_entry {
    uint8_t  xor_key;
    uint8_t  pad[7];
    uint64_t func_ptr;   // pointer to a tiny function that returns a constant
};
```

To decode a character at index `i`:
```
char = (call table[i].func_ptr()) ^ table[i].xor_key
```

This builds a complete character mapping:
- Indices 0–25 → `a`–`z`
- Indices 26–51 → `A`–`Z`
- Indices 52–61 → `0`–`9`
- Special chars: `62='.'  63=':'  64='\\'  65='%'  67=' '  68='"'  69='_'  74='{'  75='}'` etc.

Strings are built by "string builder" functions that take character indices as arguments (r8, r9, then stack at [rsp+0x20], [rsp+0x28], ...) and loop over them, decoding each via the table.

---

## 3. Anti-Debug Dual-Path Mechanism

Each string builder has **two decode paths** selected by a `jmp qword ptr [rip+9]` trick:

1. **Anti-debug path** (Path 1): Reads `SharedUserData+0x2F8` (`[0x7FFE02F8]`), XORs with `0x77190988`, adds a constant, interprets the result as a function address, calls it twice with magic constants, then XORs the return value with `0x9A`. Under a debugger or in a VM, this produces **garbage characters**.

2. **Normal path** (Path 2): Simply calls `type1_table[index].func_ptr` and XORs with `type1_table[index].xor_key` — producing the **correct characters**.

The path selection is runtime-controlled. On a clean system with all anti-analysis checks passing, Path 2 is taken. On FLARE-VM (with debuggers/tools installed), Path 1 is taken, poisoning all decoded strings.

---

## 4. Program Architecture

### Main Function (`0x140104520`)

1. Creates `tmp.ggc` via `NtCreateFile` (direct syscall) — the file is never written to
2. Opens registry key `HKLM\SOFTWARE\Microsoft\RemovalTools\MRT` and reads a GUID
3. Builds an `std::unordered_map` hash table from the GUID
4. Spawns **Thread 1** and **Thread 2** via `_beginthreadex`, both using the same start wrapper (`0x140109430`) which simply does `call [rcx]`
5. Sets a self-poison anti-debug flag
6. Calls `WaitForSingleObject(event_handle, 100ms)`:
   - **Timeout (0x102)**: Prints error messages (the path taken on FLARE-VM)
   - **Success (0)**: Takes the flag output path

### TLS Callback (`0x140101620`)

Creates a manual-reset, initially non-signaled event. The handle is stored at `0x14012B2C0`. This event is the gatekeeper — it must be signaled for the main thread to proceed to the flag path.

### Thread 1 (`0x140108DE0`)

Iterates an **entry table** at `0x14012A4A0` containing 17 entries (16 bytes each, populated at runtime). For each entry, it:
1. Allocates a 24-byte struct: `{extra_value, func_ptr, callback=0x1401044F0}`
2. Spawns a sub-thread via `_beginthreadex`

After all 17 sub-threads complete, Thread 1 resolves `SetEvent` via PEB walking + FNV-1a hashing and **signals the event**, allowing the main thread to proceed.

### The 17 Anti-Analysis Check Functions

Each sub-thread runs a check function. These check for:
- Debuggers (x64dbg, ScyllaHide, CheatEngine)
- Virtual machines (VMware, VirtualBox, QEMU/KVM, Hyper-V, Parallels)
- Analysis tools (Wireshark, Process Monitor, Sysinternals, etc.)
- Vulnerable/suspicious drivers
- CPUID hypervisor detection
- Debug boot configuration (TESTSIGN, DEBUGPORT, etc.)
- FNV-1a hash-based process/module enumeration

On FLARE-VM, most of these checks **fail** (they detect analysis tools), so the event is never signaled (or is signaled too late), and `WaitForSingleObject` times out.

### Thread 2 (`0x1401031A0`)

Spin-waits, then builds the string "yikes" and a taunt message — this is the error/failure output path.

---

## 5. Finding the Flag

### Key Insight

Since we have the complete Type 1 character table, we don't need to run the binary successfully. We just need to find the **character indices** passed to the string builder that constructs the flag.

### Locating the Flag Builder

Using a script that:
1. Finds all 29 type2 decode (string builder) functions via their `xor al, 0x9A` signature
2. Scans `.text` for all `E8 xx xx xx xx` (CALL) instructions targeting these functions
3. For each call site, disassembles backwards to extract the `mov` instructions that set up arguments

We find 245 total calls to string builders across the binary. Most decode anti-analysis strings ("x64dbg", "Wireshark", "BOCHS", "VBoxGuest.sys", etc.).

### The Flag Call

In **Entry16** (`0x1400FE8A0`, 5940 bytes), we find two critical calls:

**Call at `0x1400FF73E`** → string builder `0x1400BDAC0`:
```asm
mov dword ptr [rsp+0x80], 0x4B   ; 75 → '}'
mov dword ptr [rsp+0x78], 0x39   ; 57 → '5'
mov dword ptr [rsp+0x70], 0x03   ;  3 → 'd'
mov dword ptr [rsp+0x68], 0x34   ; 52 → '0'
mov dword ptr [rsp+0x60], 0x34   ; 52 → '0'
mov dword ptr [rsp+0x58], 0x02   ;  2 → 'c'
mov dword ptr [rsp+0x50], 0x03   ;  3 → 'd'
mov dword ptr [rsp+0x48], 0x00   ;  0 → 'a'
mov dword ptr [rsp+0x40], 0x01   ;  1 → 'b'
mov dword ptr [rsp+0x38], 0x17   ; 23 → 'x'
mov dword ptr [rsp+0x30], 0x34   ; 52 → '0'
mov dword ptr [rsp+0x28], 0x4A   ; 74 → '{'
mov dword ptr [rsp+0x20], 0x28   ; 40 → 'O'
mov r8d, 0x1C                    ; 28 → 'C'
mov r9d, 0x26                    ; 38 → 'M'
call 0x1400BDAC0
```

Reading in Windows x64 calling convention order (r8, r9, [rsp+0x20], [rsp+0x28], ...):

| Arg | Index | Char |
|-----|-------|------|
| r8  | 0x1C (28) | C |
| r9  | 0x26 (38) | M |
| [rsp+0x20] | 0x28 (40) | O |
| [rsp+0x28] | 0x4A (74) | { |
| [rsp+0x30] | 0x34 (52) | 0 |
| [rsp+0x38] | 0x17 (23) | x |
| [rsp+0x40] | 0x01 (1) | b |
| [rsp+0x48] | 0x00 (0) | a |
| [rsp+0x50] | 0x03 (3) | d |
| [rsp+0x58] | 0x02 (2) | c |
| [rsp+0x60] | 0x34 (52) | 0 |
| [rsp+0x68] | 0x34 (52) | 0 |
| [rsp+0x70] | 0x03 (3) | d |
| [rsp+0x78] | 0x39 (57) | 5 |
| [rsp+0x80] | 0x4B (75) | } |

**Flag: `CMO{0xbadc00d5}`**

The second call at `0x1400FFA35` builds `"FLAG DISPLAY"` — the label for outputting the flag.

---

## 6. Reproduction Steps

### Requirements
- Python 3 with `pefile` and `capstone` (`pip install pefile capstone`)
- The `moment.exe` binary

### Script

```python
import struct, pefile
from capstone import *

pe = pefile.PE("moment.exe")
data = open("moment.exe", "rb").read()
image_base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def rva_to_offset(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return s.PointerToRawData + (rva - s.VirtualAddress)
    return None

def disasm_at(va, size):
    off = rva_to_offset(va - image_base)
    if off is None:
        return []
    return list(md.disasm(data[off:off+size], va))

# Step 1: Build the Type 1 character table
# Table at VA 0x140111680, 16 bytes per entry: [xor_key(1B), pad(7B), func_ptr(8B)]
# Each func does: mov eax, <constant>; ret
# Decoded char = (func_return & 0xFF) ^ xor_key
type1_table_va = 0x140111680
type1_chars = {}
for i in range(89):
    entry_off = rva_to_offset(type1_table_va - image_base + i * 16)
    if entry_off is None:
        continue
    xor_key = data[entry_off]
    func_ptr = struct.unpack_from("<Q", data, entry_off + 8)[0]
    func_off = rva_to_offset(func_ptr - image_base)
    if func_off:
        for insn in md.disasm(data[func_off:func_off+16], func_ptr):
            if insn.mnemonic == 'mov' and len(insn.operands) == 2:
                dst_name = insn.reg_name(insn.operands[0].reg)
                if dst_name == 'eax' and insn.operands[1].type == 2:  # IMM
                    ret_val = insn.operands[1].imm & 0xFF
                    type1_chars[i] = chr(ret_val ^ xor_key)
                    break

# Step 2: Read the flag character indices from the code before call at 0x1400FF73E
# This is inside Entry16 check function (0x1400FE8A0).
# The code sets up args: r8=first_char_index, r9=second, [rsp+0x20]=third, etc.
# The mov sequence starts at 0x1400FF6C3 (= flag_call - 0x7B)
flag_call = 0x1400FF73E
flag_setup = 0x1400FF6C3  # known instruction boundary
instrs = disasm_at(flag_setup, flag_call - flag_setup + 5)

args = {}
for insn in instrs:
    if insn.address >= flag_call:
        break
    if insn.mnemonic == 'mov' and len(insn.operands) == 2:
        dst, src = insn.operands[0], insn.operands[1]
        if src.type == 2:  # IMM source
            val = src.imm & 0xFFFFFFFF
            if val > 0xFFFF:
                continue  # skip address-like values
            if dst.type == 1:  # REG destination
                reg = insn.reg_name(dst.reg)
                if reg in ('r8d', 'r8'):   args[0] = val
                elif reg in ('r9d', 'r9'): args[1] = val
            elif dst.type == 3:  # MEM destination
                base = insn.reg_name(dst.mem.base) if dst.mem.base != 0 else ""
                if base == 'rsp':
                    slot = (dst.mem.disp - 0x20) // 8 + 2
                    args[slot] = val

# Step 3: Decode the flag
flag = ''.join(type1_chars.get(args[i], '?') for i in sorted(args))
print(f"Flag: {flag}")
```

**Output:**
```
Flag: CMO{0xbadc00d5}
```

---

## 7. Summary

The binary uses a layered defense:
1. **No readable strings** — all encoded via a custom table
2. **Dual decode paths** — anti-debug path produces wrong output under analysis
3. **17 parallel anti-analysis checks** — detect VMs, debuggers, and tools
4. **Event-gated flag output** — flag only displayed if ALL checks pass
5. **Direct syscalls** — bypass API hooking
6. **Heavy obfuscation** — thousands of `INT3`, `RDTSC`, `CPUID` instructions

The solve was **purely static**: by reverse engineering the string encoding table and tracing the character indices passed to the flag's string builder function, no dynamic execution on a clean system was needed.
{% endraw %}
