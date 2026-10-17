---
title: "Position-independent code on x86-64: GOT, PLT and lazy binding"
date: 2026-07-02 09:00:00 +0600
series: "Notes"
summary: "Following one global and one function call from the compiler's placeholder zeros, through the linker's offsets and ld.so's relocations, to the first lazy-binding resolve in GDB."
description: "Following one global and one function call from the compiler's placeholder zeros, through the linker's offsets and ld.so's relocations, to the first lazy-binding resolve in GDB."
tags: ["linux", "elf", "notes"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
## The Problem: Why PIC?

Shared libraries (.so files) are loaded at different base addresses every time a program runs, especially with ASLR enabled. Code with hardcoded absolute addresses would be wrong at every load.

**WITHOUT PIC (load-time relocation, x86 approach):**

- Every process gets its OWN private copy of .text
- .text is patched with absolute addresses at load time
- Wastes RAM - can't share .text between processes

```
mov eax, [0x7f3a2000]       ; hardcoded absolute - only works at this base
```

**WITH PIC (x86-64 approach):**

- .text is READ-ONLY and shared between all processes
- A writable table (GOT) holds the real addresses
- Code uses RIP-relative offsets to reach the GOT

```
mov rax, [rip+0x2e89]       ; always correct regardless of base address
```

*KEY INSIGHT:* The distance between .text and .got is fixed at link time. Regardless of where the library loads in memory, that gap never changes. So RIP + fixed_offset always reaches the correct GOT slot.

```
GOT address = RIP + encoded_offset   (always true, any base)
```

---

## Key Structures: GOT and PLT

### Global Offset Table (GOT)

A writable table in the data segment. Each slot is 8 bytes holding one absolute address. Code never stores absolute addresses directly - it always goes through the GOT as a middleman.

| Section  |             Purpose             | Filled by | When              |
|:--------:|:-------------------------------:|:---------:|:----------------- |
|   .got   |  Addresses of global variables  |   ld.so   | Load time (eager) |
| .got.plt | Addresses of external functions |   ld.so   | First call (lazy) |

### .got.plt Layout (demo)

```
GOT[0]  @ base+0x3fe8  = address of .dynamic section      (linker fills)
GOT[1]  @ base+0x3ff0  = link_map pointer                 (ld.so fills)
GOT[2]  @ base+0x3ff8  = ld.so resolver function address  (ld.so fills)
GOT[n]  @ base+0x4000  = ml_util_func slot             (lazy - first call)
```
  
*GOT[1]* answers "which library is this?"

*GOT[2]* answers "where is the resolver in ld.so?"

*GOT[n]* starts pointing back into the PLT, gets patched to the real function after the first call.

### Procedure Linkage Table (PLT)

A read-only trampoline section in .text. Every external function gets its own PLT stub. The stub reads the GOT slot and jumps there. Before resolution it bounces back into the PLT itself, triggering the resolver.

**THE BOUNCE TRICK:** Before the first call, GOT[n] points to PLT[n]+6 (the push instruction). So the JMP reads the GOT, and lands right back in the PLT just past the JMP, falling through to `push → PLT[0] → resolver.`

After the first call, GOT[n] holds the real function address. JMP goes directly without resolver.
### .plt Layout (demo)

```
; PLT[0] - shared resolver trampoline  (at base+0x1020)
	push [GOT[1]]     ; push link_map  (which library is this?)
	jmp  [GOT[2]]     ; jump into ld.so resolver

; PLT[n] - per-function stub for ml_util_func (at base+0x1030)
	jmp  [GOT[n]]     ; jump to whatever GOT[n] currently holds
	push 0x0          ; slot index: "I am function #0 in .rela.plt"
	jmp  PLT[0]       ; fall through to resolver trampoline
```

---

## Compilation Flags

```c
//ml_main.c    

int myglob = 42;

int ml_util_func(int a)
{
    return a + 1;
}

int ml_func(int a, int b)
{
    int c = b + ml_util_func(a);
    myglob += c;
    return b + myglob;
}

```

### ml_main.c → ml_main.o

```sh
$ gcc ml_main.c -o ml_main.o -c -fPIC -g
```

| Flag  | Meaning                                                                                                                |
|:-----:| ---------------------------------------------------------------------------------------------------------------------- |
|  -c   | Compile only, do NOT link. Output is a relocatable .o file                                                             |
| -fPIC | Generate Position Independent Code, use RIP-relative addressing and GOT indirection for all globals and external calls |
|  -g   | Embed debug info (produces .rela.debug_* sections in the .o)                                                           |


### ml_main.o → libmlpic.so


```sh
$ gcc ml_main.o -o libmlpic.so -shared -fPIC -g
```

|  Flag   |                      Meaning                       |
|:-------:|:--------------------------------------------------:|
|  -fPIC  | Ensure GCC-added glue code (init/fini) is also PIC |
| -shared |    Produce a shared library, not an executable     |
|   -g    |             Keep debug info in the .so             |
  
### driver.c → driver

```c
//driver.c

#include <stdio.h>
extern int ml_func(int, int);

int main()
{
    printf("=== First call ===\n");
    int r1 = ml_func(1, 1);
    printf("ml_func(1,1) = %d\n", r1);
    
    printf("=== Second call ===\n");
    int r2 = ml_func(2, 2);
    printf("ml_func(2,2) = %d\n", r2);
    return 0;
}

```

```sh
$ gcc driver.c -o driver -L. -lmlpic -Wl,-rpath,. -g
```

|     Flag     |                                               Meaning                                               |
|:------------:|:---------------------------------------------------------------------------------------------------:|
|     -L.      |                         Search current directory for libraries at link time                         |
|   -lmlpic    |                                      Link against libmlpic.so                                       |
| -Wl,-rpath,. | Embed "." as runtime library search path so ld.so finds the .so without needing LD_LIBRARY_PATH set |

---

## Stage 1: Compiler Output (.o file)

After Executing `$ gcc ml_main.c -o ml_main.o -c -fPIC -g`

The compiler sees only one .c file in isolation. It has no idea where anything will land in memory. It does two things:

1. Emits PLACEHOLDER ZEROS in the instructions
2. Writes a TO-DO LIST of relocation records for the linker (.rela.text)
### .rela.text: Linker's To-Do List

```sh
$ readelf -r ml_main.o 
```

Relocation section '.rela.text' at offset 0x538 contains 4 entries:

| Offset       | Info         | Type              | Sym. Value       | Sym. Name + Addend |
| ------------ | ------------ | ----------------- | ---------------- | ------------------ |
| 000000000023 | 000900000004 | R_X86_64_PLT32    | 0000000000000000 | ml_util_func - 4   |
| 000000000032 | 00080000002a | R_X86_64_REX_GOTP | 0000000000000000 | myglob - 4         |
| 000000000040 | 00080000002a | R_X86_64_REX_GOTP | 0000000000000000 | myglob - 4         |
| 000000000049 | 00080000002a | R_X86_64_REX_GOTP | 0000000000000000 | myglob - 4         |

Field meanings:

```
	Offset                  Byte position inside .text where the placeholder sits and needs to be patched by the linker
	R_X86_64_PLT32          Patch a CALL instruction to go through the PLT (enables lazy binding for functions)
	R_X86_64_REX_GOTP       Patch a MOV instruction's RIP-relative offset to point to a GOT slot (for global variable access)
```
  
At the time the CPU executes the instruction, RIP already points to the NEXT instruction (4 bytes ahead). The -4 corrects for this when computing the offset.

### Disassembly: Placeholder Zeros in .text

```sh
$ objdump -d -M intel ml_main.o
```  

```asm
; ml_util_func - self-contained, no globals, NO relocations needed
    0x00: ml_util_func:
        ...

; ml_func - calls external function + accesses global → needs relocations
    0x0f: ml_func:
        ...
        
        22: e8 00 00 00 00   call 27     ; PLACEHOLDER
                                         ; e8 = CALL opcode
                                         ; 00 00 00 00 = offset placeholder
                                         ; objdump says "call 27" because:
                                         ; RIP(0x27) + 0x0 = 0x27 (meaningless)
        ...                                 
        
        2f: 48 8b 05 00 00 00 00   mov rax,[rip+0x0]     ; PLACEHOLDER (read myglob)
                                         ; 48     = REX.W prefix (64-bit)
                                         ; 8b 05  = MOV rax, [rip+disp32]
                                         ; 00 00 00 00 = offset placeholder
                                         ; objdump says "# 36" because:
                                         ; RIP(0x36) + 0x0 = 0x36 (meaningless)
        ...

        3d: 48 8b 05 00 00 00 00   mov rax,[rip+0x0]   ; PLACEHOLDER (write myglob)
        ...
        
        46: 48 8b 05 00 00 00 00   mov rax,[rip+0x0]   ; PLACEHOLDER (read myglob)
```

### Why "call 27" and "# 36" in objdump?

objdump computes `RIP + encoded_offset` and prints it as the target address.
 
Since the offset is a placeholder zero, the annotation just equals RIP (i.e. the next instruction address). 

It is meaningless at this stage. After the linker patches the real offsets, these annotations will point to actual GOT slots and PLT entries.

### Two Levels of Indirection for myglob

```asm
    mov rax, [rip+offset]   ; step 1: rax = contents of GOT slot = &myglob
	mov edx, [rax]          ; step 2: edx = *rax = actual value of myglob
```

The GOT slot holds &myglob (the address), not the value itself. 

ld.so fills &myglob into the GOT slot at load time.

The instruction then dereferences it to get the value.

---

## Stage 2: Linker Output (.so file)

After Executing `$ gcc ml_main.o -o libmlpic.so -shared -fPIC -g`

The linker sees the full picture - all sections, all symbols, final layout.

It does three things:
1. Patches all placeholder zeros in .text with real RIP-relative offsets
2. Creates the PLT and GOT sections
3. Discards link-time relocation records, keeps only runtime ones

### What Got DISCARDED (consumed by linker, gone from .so)

- R_X86_64_PLT32          (for the CALL to ml_util_func)
- R_X86_64_REX_GOTPCREL   (for all three MOVs accessing myglob)

These are gone. The linker computed and baked in the real offsets.

### What SURVIVED in .rela.dyn (ld.so fills at load time)

```sh 
$ readelf -r libmlpic.so 
```

Relocation section '.rela.dyn' at offset 0x3c8 contains 8 entries:

| Offset       | Info         | Type              | Sym. Value       | Sym. Name + Addend              | (Comment)               |
| ------------ | ------------ | ----------------- | ---------------- | ------------------------------- | ----------------------- |
| 000000003e30 | 000000000008 | R_X86_64_RELATIVE |                  | 1100                            | ← internal ptr          |
| 000000003e38 | 000000000008 | R_X86_64_RELATIVE |                  | 10c0                            | ← internal ptr          |
| 000000004008 | 000000000008 | R_X86_64_RELATIVE |                  | 4008                            | ← internal ptr          |
| 000000003fc0 | 000100000006 | R_X86_64_GLOB_DAT | 0000000000000000 | \_\_cxa\_finalize + 0           |                         |
| 000000003fc8 | 000500000006 | R_X86_64_GLOB_DAT | 0000000000004010 | myglob + 0                      | ← fill GOT slot eagerly |
| 000000003fd0 | 000200000006 | R_X86_64_GLOB_DAT | 0000000000000000 | \_ITM\_registerTMCl[\.\.\.] + 0 |                         |
| 000000003fd8 | 000300000006 | R_X86_64_GLOB_DAT | 0000000000000000 | \_ITM\_deregisterTM[\.\.\.] + 0 |                         |
| 000000003fe0 | 000400000006 | R_X86_64_GLOB_DAT | 0000000000000000 | \_\_gmon\_start\_\_ + 0         |                         |

### What SURVIVED in .rela.plt (ld.so fills lazily)

```sh 
$ readelf -r libmlpic.so 
```

Relocation section '.rela.plt' at offset 0x488 contains 1 entry:

| Offset       | Info         | Type              | Sym. Value       | Sym. Name + Addend | (Comment)                   |
| ------------ | ------------ | ----------------- | ---------------- | ------------------ | --------------------------- |
| 000000004000 | 000600000007 | R_X86_64_JUMP_SLO | 0000000000001109 | ml_util_func + 0   | ← fill lazily on first call |

### Section Headers

```
$ readelf -S libmlpic.so
```

There are 31 section headers, starting at offset 0x37e0:

| [Nr]<br> |         Name<br>Size          |       Type<br>EntSize        | Address<br>Flags - Link - Info | Offset<br>Align |
| :------: | :---------------------------: | :--------------------------: | :----------------------------: | :-------------: |
| [ 5]<br> | .rela.dyn<br>00000000000000c0 |   RELA<br>0000000000000018   |   00000000000003c8<br>A 3 0    |  000003c8<br>8  |
|   [ 6]   | .rela.plt<br>0000000000000018 |   RELA<br>0000000000000018   |  0000000000000488<br>AI 3 18   |  00000488<br>8  |
|   [ 8]   |   .plt<br>0000000000000020    | PROGBITS<br>0000000000000010 |   0000000000001020<br>AX 0 0   | 00001020<br>16  |
|   [ 9]   | .plt.got<br>0000000000000008  | PROGBITS<br>0000000000000008 |   0000000000001040<br>AX 0 0   |  00001040<br>8  |
|   [10]   |   .text<br>000000000000010f   | PROGBITS<br>0000000000000000 |   0000000000001050<br>AX 0 0   | 00001050<br>16  |
|   [17]   |   .got<br>0000000000000028    | PROGBITS<br>0000000000000008 |   0000000000003fc0<br>WA 0 0   |  00002fc0<br>8  |
|   [18]   | .got.plt<br>0000000000000020  | PROGBITS<br>0000000000000008 |   0000000000003fe8<br>WA 0 0   |  00002fe8<br>8  |
|   [19]   |   .data<br>000000000000000c   | PROGBITS<br>0000000000000000 |   0000000000004008<br>WA 0 0   |  00003008<br>8  |

Key to Flags:
  W (write), A (alloc), X (execute), I (info)

| Section   | Meaning                                              |
| --------- | ---------------------------------------------------- |
| .plt      | PLT stubs - the trampoline code for lazy binding     |
| .plt.got  | Eagerly bound functions (no lazy fallback)           |
| .text     | Actual code with patched RIP-relative offsets        |
| .got      | GOT slots for global variables (filled at load time) |
| .got.plt  | GOT slots for functions (filled lazily)              |
| .rela.dyn | ld.so's to-do list for load-time relocations         |
| .rela.plt | ld.so's to-do list for lazy function relocations     |
| .data     | Where globals like `myglob` actually live            |

### Entry Types

| Type               | Meaning                          | When                                         |
| ------------------ | -------------------------------- | -------------------------------------------- |
| R_X86_64_GLOB_DAT  | Write symbol's runtime address   | Load time (eager) into GOT slot at Offset    |
| R_X86_64_JUMP_SLOT | Write function's runtime address | First call (lazy) into GOT slot at Offset    |
| R_X86_64_RELATIVE  | \*slot = base + addend           | Load time (internal pointers within library) |

### Linker Math: Patching the Placeholders

```sh
$ objdump -d -M intel libmlpic.so  
```

**Disassembly of section .plt:**

```asm
0000000000001020 <ml_util_func@plt-0x10>:
    1020:       ff 35 ca 2f 00 00       push   QWORD PTR [rip+0x2fca]        # 3ff0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:       ff 25 cc 2f 00 00       jmp    QWORD PTR [rip+0x2fcc]        # 3ff8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:       0f 1f 40 00             nop    DWORD PTR [rax+0x0]

0000000000001030 <ml_util_func@plt>:
    1030:       ff 25 ca 2f 00 00       jmp    QWORD PTR [rip+0x2fca]        # 4000 <ml_util_func+0x2ef7>
    1036:       68 00 00 00 00          push   0x0
    103b:       e9 e0 ff ff ff          jmp    1020 <_init+0x20>
```

**Disassembly of section .plt.got:**

```asm
0000000000001040 <__cxa_finalize@plt>:
    1040:       ff 25 7a 2f 00 00       jmp    QWORD PTR [rip+0x2f7a]        # 3fc0 <__cxa_finalize>
    1046:       66 90                   xchg   ax,ax
```

**Disassembly of section .text:**

```asm
...

; ml_util_func - self-contained, no globals, NO relocations needed
0000000000001109 <ml_util_func>:
...

; ml_func - calls external function + accesses global
0000000000001118 <ml_func>:
    ...
    
    112b:       e8 00 ff ff ff          call   1030 <ml_util_func@plt>
    ...
    
    1138:       48 8b 05 89 2e 00 00    mov    rax,QWORD PTR [rip+0x2e89]        # 3fc8 <myglob-0x48>
    ...
    
    1146:       48 8b 05 7b 2e 00 00    mov    rax,QWORD PTR [rip+0x2e7b]        # 3fc8 <myglob-0x48>
    ...
    
    114f:       48 8b 05 72 2e 00 00    mov    rax,QWORD PTR [rip+0x2e72]        # 3fc8 <myglob-0x48>
    ...
    
```

The linker computes: offset = `GOT_slot_address - RIP`

Then patches the 4-byte placeholder in the instruction with this offset.

myglob GOT slot is at file offset `0x3fc8` (.rela.dyn)

All three MOV instructions reach the SAME slot, but from different RIPs, so they each get a different encoded offset.

**MOV #1 at 0x1138**
- instruction length = 7 bytes
- RIP = 0x1138 + 7 = 0x113f
- offset = 0x3fc8 - 0x113f = 0x2e89 ✓    ← patched into instruction

**MOV #2 at 0x1146**
- instruction length = 7 bytes
- RIP = 0x1146 + 7 = 0x114d
- offset = 0x3fc8 - 0x114d = 0x2e7b ✓    ← patched into instruction
  
**MOV #3 at 0x114f**
- instruction length = 7 bytes
- RIP = 0x114f + 7 = 0x1156
- offset = 0x3fc8 - 0x1156 = 0x2e72 ✓    ← patched into instruction

Three different offsets, all pointing to the same GOT slot 0x3fc8.

**PLT[n] JMP instruction for ml_util_func:**

**JMP at 0x1030**
- instruction length = 6 bytes
- RIP = 0x1030 + 6 = 0x1036
- GOT[ml_util_func] at 0x4000
- offset = 0x4000 - 0x1036 = 0x2fca ✓    ← patched into JMP

**PLT[0] entries (resolver trampoline):**

From Section Header, .got.plt address = 0x3fe8
- GOT[0] = 0x3fe8 + (0 * 8) = 0x3fe8 
- GOT[1] = 0x3fe8 + (1 * 8) = 0x3ff0 ← each slot is 8 bytes (64-bit pointer) 
- GOT[2] = 0x3fe8 + (2 * 8) = 0x3ff8 
- GOT[n] = 0x3fe8 + (3 * 8) = 0x4000

**PUSH at 0x1020**
- length = 6
- RIP = 0x1020 + 6 = 0x1026
- reads GOT[1] at 0x3ff0
- offset = 0x3ff0 - 0x1026 = 0x2fca ✓
    
**JMP  at 0x1026** 
- length = 6
- RIP = 0x1026 + 6 = 0x102c
- reads GOT[2] at 0x3ff8
- offset = 0x3ff8 - 0x102c = 0x2fcc ✓
### After Patching: ml_func Disassembly

; **CALL** - was 00 00 00 00, now patched to reach PLT[n]

```
    112b:       e8 00 ff ff ff          call   1030 <ml_util_func@plt>
```

; **MOV myglob** x3 - were rip+0x0, now patched to reach GOT[myglob]

```
    1138:       48 8b 05 89 2e 00 00    mov    rax,QWORD PTR [rip+0x2e89]        # 3fc8 <myglob-0x48>
    1146:       48 8b 05 7b 2e 00 00    mov    rax,QWORD PTR [rip+0x2e7b]        # 3fc8 <myglob-0x48>
    114f:       48 8b 05 72 2e 00 00    mov    rax,QWORD PTR [rip+0x2e72]        # 3fc8 <myglob-0x48>
```

### PLT Disassembly

; PLT[0] - resolver trampoline @ 0x1020
```
    1020:       push [rip+0x2fca]     → RIP=0x1026, reads 0x1026+0x2fca = 0x3ff0 = GOT[1]
	1026:       jmp  [rip+0x2fcc]     → RIP=0x102c, reads 0x102c+0x2fcc = 0x3ff8 = GOT[2]
```

; PLT[n] - ml_util_func stub @ 0x1030

```
	1030:        jmp  [rip+0x2fca]    → RIP=0x1036, reads 0x1036+0x2fca = 0x4000 = GOT[n]
	1036:        push 0x0             → slot index 0 (first entry in .rela.plt)
	103b:        jmp  0x1020          → jump to PLT[0] resolver trampoline
```
  
; .plt.got - \_\_cxa_finalize (eagerly bound, no lazy fallback)

```
	1040:       jmp  [rip+0x2f7a]    → reads GOT slot @ 0x3fc0 (filled at load time)
	1046:       xchg ax,ax           → 2-byte NOP padding (no push/jmp fallback needed)
```

---

## Stage 3: Load Time (ld.so)

ld.so runs before main(). It maps libmlpic.so into memory at a random base address (ASLR), then processes all .rela.dyn entries eagerly.

### Runtime Address Calculation (from GDB session)

```gdb
(gdb) file driver
Reading symbols from driver...
(gdb) set environment LD_LIBRARY_PATH=.
(gdb) break main
Breakpoint 1 at 0x1161: file driver.c, line 7.
(gdb) run
...
Breakpoint 1, main () at driver.c:7
7           printf("=== First call \=\=\=\n");
```

```gdb
(gdb) info sharedlibrary
From                To                  Syms Read   Shared Object Library
0x00007ffff7fc7000  0x00007ffff7fff000  Yes (*)     /lib64/ld-linux-x86-64.so.2
0x00007ffff7fb8000  0x00007ffff7fbd000  Yes         ./libmlpic.so
0x00007ffff7da4000  0x00007ffff7f9a000  Yes (*)     /usr/lib/x86_64-linux-gnu/libc.so.6
(*): Shared library is missing debugging information.
```
    
So, `libmlpic.so` loaded at base `0x00007ffff7fb8000`

Now let's compute our key runtime addresses:

base = 0x7ffff7fb8000

|    Symbol/Location    | Calculation   | Runtime Address |
| :-------------------: | ------------- | --------------- |
|     ml_util_func      | base + 0x1109 | 0x7ffff7fb9109  |
|        ml_func        | base + 0x1118 | 0x7ffff7fb9118  |
|       PLT\[0\]        | base + 0x1020 | 0x7ffff7fb9020  |
| PLT[n] (ml_util_func) | base + 0x1030 | 0x7ffff7fb9030  |
|     GOT\[myglob\]     | base + 0x3fc8 | 0x7ffff7fbbfc8  |
|  GOT\[ml_util_func\]  | base + 0x4000 | 0x7ffff7fbc000  |
|   myglob (in .data)   | base + 0x4010 | 0x7ffff7fbc010  |

All offsets (0x1109, 0x3fc8, etc.) came from static analysis of the .so file (objdump, readelf). The base address is only known at runtime.

| Address                                       | Source                                                                        |
| --------------------------------------------- | ----------------------------------------------------------------------------- |
| `base`                                        | `info sharedlibrary` output                                                   |
| `ml_util_func`, `ml_func`, `PLT[0]`, `PLT[n]` | `base + offset` where offsets came from `objdump` of `.so`                    |
| `GOT[myglob]` = `base + 0x3fc8`               | `base + offset` where `0x3fc8` came from `.rela.dyn` entry for `myglob`       |
| `GOT[ml_util]` = `base + 0x4000`              | `base + offset` where `0x4000` came from `.rela.plt` entry for `ml_util_func` |

### What ld.so Does Before main()

**Processing R_X86_64_GLOB_DAT for myglob:**
- myglob lives at base + 0x4010 = 0x7ffff7fbc010
- ld.so writes 0x7ffff7fbc010 into GOT\[myglob\] slot @ 0x7ffff7fbbfc8

```gdb
(gdb) x/gx 0x7ffff7fbbfc8
0x7ffff7fbbfc8: 0x00007ffff7fbc010                  ← ld.so filled this at load time

(gdb) x/gx 0x7ffff7fbc010
0x7ffff7fbc010 <myglob>:        0x000000000000002a  ← that's &myglob, value is 42
```

**Processing R_X86_64_RELATIVE entries (internal pointers):**
- \*( base + 0x3e30 ) = base + 0x1100   (frame\_dummy pointer)
- \*( base + 0x3e38 ) = base + 0x10c0   (\_\_do\_global\_dtors\_aux pointer)

**Bootstrapping .got.plt:**

```gdb
(gdb) x/gx 0x7ffff7fbbff0
0x7ffff7fbbff0: 0x00007ffff7fbd1d0

(gdb) x/gx 0x7ffff7fbbff8
0x7ffff7fbbff8: 0x00007ffff7fda9e0

(gdb) x/gx 0x7ffff7fbc000
0x7ffff7fbc000 <ml_util_func@got.plt>:  0x00007ffff7fb9036
```
    
- GOT[1] @ 0x7ffff7fbbff0  =  0x7ffff7fbd1d0   (link_map struct)
- GOT[2] @ 0x7ffff7fbbff8  =  0x7ffff7fda9e0   (ld.so resolver)
- GOT[n] @ 0x7ffff7fbc000  =  0x7ffff7fb9036   (PLT bounce - NOT resolved yet)

### GDB Verification Before Any Call

We saw that myglob variable is filled but the ml_util_func is not resolved

```
	(gdb) x/gx 0x7ffff7fbbfc8
	0x7ffff7fbbfc8:  0x00007ffff7fbc010              ← GOT\[myglob\] filled ✓
	(gdb) x/gx 0x7ffff7fbc010
	0x7ffff7fbc010 <myglob>:  0x000000000000002a     ← value = 42 ✓
```

```
	(gdb) x/gx 0x7ffff7fbc000
	0x7ffff7fbc000:  0x00007ffff7fb9036              ← GOT[ml_util] = PLT bounce, NOT resolved
```

---

## Stage 4: First Call (Lazy Binding)

```
GOT[ml_util_func] @ 0x7ffff7fbc000 = 0x7ffff7fb9036
```

`0x7ffff7fb9036` = `base + 0x1036` - that's the `push 0x0` instruction inside `PLT[n]`, right after the `jmp`. The GOT is bouncing back into the PLT. `ml_util_func` is **not resolved yet**.

**Current state**

```
GOT[myglob]      = 0x7ffff7fbc010  ✓ resolved (points to myglob)
GOT[ml_util]     = 0x7ffff7fb9036  ✗ not resolved (bounces back into PLT)
                              ↑
                        base + 0x1036 = PLT[n]+6 (the push instruction)
```

Now let's set a breakpoint at `PLT[n]` and step through the first call instruction by instruction. 

```gdb
break *0x7ffff7fb9030
continue
```

This will stop us at the very first instruction of the PLT stub for `ml_util_func` - right when `ml_func` calls it.

I am using gef with gdb so i can see the instructions easily right now I am at: 

```
●→  0x7ffff7fb9030 <ml_util_func@plt+0000> jmp    QWORD PTR [rip+0x2fca]        # 0x7ffff7fbc000 <ml_util_func@got.plt>
	0x7ffff7fb9036 <ml_util_func@plt+0006> push   0x0
	0x7ffff7fb903b <ml_util_func@plt+000b> jmp    0x7ffff7fb9020
```

```gdb
si
```

This JMP will read `GOT[ml_util_func]` and jump to whatever is there. We already know it contains `0x7ffff7fb9036` - so it will bounce to `push 0x0` right below.

**What `push 0x0` means**

This pushes the **function index** onto the stack. `0x0` means _"I am slot 0 in `.rela.plt`"_. The resolver will read this to know which function to look up - in our case `ml_util_func`.

```gdb
si
```

```
 → 0x7ffff7fb9020                  push   QWORD PTR [rip+0x2fca]        # 0x7ffff7fbbff0
   0x7ffff7fb9026                  jmp    QWORD PTR [rip+0x2fcc]        # 0x7ffff7fbbff8
   0x7ffff7fb902c                  nop    DWORD PTR [rax+0x0]
```

We're now at `PLT[0]` - the resolver trampoline. Two instructions here 

```
push [rip+0x2fca] → reads 0x7ffff7fbbff0 ← GOT[1] = link_map ptr 
jmp [rip+0x2fcc] → reads 0x7ffff7fbbff8 ← GOT[2] = ld.so resolver
```

**`push GOT[1]`** - pushes the `link_map` pointer. This tells the resolver _which library_ this call is coming from.

**`jmp GOT[2]`** - jumps into `ld.so`'s resolver function. At this point the stack has:

```
[rsp]   = link_map   (pushed just now - which library)
[rsp+8] = 0x0        (pushed earlier - which function slot)
```

The resolver has everything it needs to look up `ml_util_func`.

jump and finish resolver

```
si
```

```
finish
```

After resolver completes and returns check GOT\[ml_util_func\] again, This time:

```
gef➤  x/gx 0x7ffff7fbc000
0x7ffff7fbc000 <ml_util_func@got.plt>:  0x00007ffff7fb9109
```

```
GOT[ml_util] BEFORE resolver = 0x7ffff7fb9036  (bounce back into PLT)
GOT[ml_util] AFTER  resolver = 0x7ffff7fb9109  (real ml_util_func)
```

Verify:
`base + 0x1109 = 0x7ffff7fb8000 + 0x1109 = 0x7ffff7fb9109  ✓

**Step-by-step execution trace:**

```
    STEP 1  ml_func executes: call 0x7ffff7fb9030
            Enters PLT[n] for ml_util_func.

    STEP 2  PLT[n]: jmp [GOT[ml_util]]
            Reads GOT[ml_util] @ 0x7ffff7fbc000 = 0x7ffff7fb9036
            JMP goes to 0x7ffff7fb9036 = PLT[n]+6 (the push instruction)
            THE BOUNCE - lands right back in PLT past the JMP.

    STEP 3  push 0x0
            Pushes slot index 0 onto the stack.\
            This tells the resolver: "look up slot 0 in .rela.plt" = ml_util_func.

    STEP 4  jmp 0x7ffff7fb9020
            Jumps to PLT[0], the shared resolver trampoline.
  
    STEP 5  PLT[0]: push [GOT[1]]
            Reads GOT[1] @ 0x7ffff7fbbff0 = 0x7ffff7fbd1d0 (link_map)
            Pushes link_map onto the stack.
            Stack now holds: [ link_map | slot_index=0 | return_addr ]

    STEP 6  PLT[0]: jmp [GOT[2]]
            Reads GOT[2] @ 0x7ffff7fbbff8 = 0x7ffff7fda9e0
            Jumps into ld.so resolver (lives inside ld-linux-x86-64.so.2).

    STEP 7  ld.so resolver runs:
            1. Reads slot index (0) from stack
            2. Looks up .rela.plt[0] → symbol name "ml_util_func"
            3. Reads link_map → identifies libmlpic.so
            4. Searches libmlpic.so symbol table for ml_util_func
            5. Computes runtime address:
                   base + Sym.Value = 0x7ffff7fb8000 + 0x1109 = 0x7ffff7fb9109
            6. WRITES 0x7ffff7fb9109 into GOT[ml_util] @ 0x7ffff7fbc000
            7. Jumps directly to ml_util_func
```

### GOT Before vs After Resolver (GDB)

```
    BEFORE first call:
        x/gx 0x7ffff7fbc000  →  0x00007ffff7fb9036   (PLT bounce address)

    AFTER resolver ran:
        x/gx 0x7ffff7fbc000  →  0x00007ffff7fb9109   (real ml_util_func)

    Verify: base + Sym.Value = 0x7ffff7fb8000 + 0x1109 = 0x7ffff7fb9109  ✓
```

---

## Stage 5: Second Call (Direct Jump)

Step through the functions and go back to main and catch the second call

```
●→ 0x7ffff7fb9030 <ml_util_func@plt+0000> jmp    QWORD PTR [rip+0x2fca]        # 0x7ffff7fbc000 <ml_util_func@got.plt>
```

`si`

Jumps to: ` → 0x7ffff7fb9109 <ml_util_func+0000> push   rbp` directly

**Step-by-step execution trace:**

```
    STEP 1  ml_func executes: call 0x7ffff7fb9030
            Enters PLT[n] again. Identical code path starts.

    STEP 2  PLT[n]: jmp [GOT[ml_util]]
            Reads GOT[ml_util] @ 0x7ffff7fbc000 = 0x7ffff7fb9109
            GOT now holds the real address. JMP goes directly to ml_util_func.

    STEP 3  Inside ml_util_func immediately.
            No push. No PLT[0]. No resolver. Never again.
```

### Why Not Skip the PLT Entirely on Second Call?

The call instruction in ml_func always goes to PLT[n] - the code in .text is never modified. Only the GOT (writable data) changes. This is by design:

.text must stay read-only so it can be shared between all processes loading the same library.  

---

## Full Timeline Summary

1. **.got (Global Offset Table):**

```
Purpose:    Holds runtime addresses of global variables

Written by: ld.so at load time (eager, before main)

Writable:   Yes - always writable (variables need updating)

Protection: With Full RELRO    → read-only after load
            With Partial RELRO → writable forever

Contains:   One 8-byte slot per global variable
            Each slot = absolute runtime address of that variable
```

2. **.got.plt (GOT for PLT functions):**

```
Purpose:    Holds runtime addresses of external functions

Written by: ld.so (GOT[0,1,2] at load time)
            ld.so resolver (GOT[n] slots lazily on first call)

Writable:   Yes - must be writable for lazy binding to work

Protection: With Full RELRO    → all resolved eagerly then read-only
            With Partial RELRO → stays writable forever

Contains:   Fixed header slots + one slot per external function

Layout:
    GOT[0]  address of .dynamic section      (linker fills)
    GOT[1]  link_map pointer                 (ld.so fills at load time)
    GOT[2]  ld.so resolver function address  (ld.so fills at load time)
    GOT[n]  one slot per external function   (lazy - starts as PLT bounce)

Before first call:  GOT[n] = PLT[n]+6  (bounce back into PLT)
After first call:   GOT[n] = real function address
```

3. **.plt (Procedure Linkage Table):**

```
Purpose:    Trampoline stubs that enable lazy binding

Written by: Linker (created at link time, never modified after)

Writable:   No - read-only, lives in .text region

Contains:   PLT[0] shared resolver trampoline
            PLT[n] one stub per external function

PLT[0] layout (shared by all functions):
    push [GOT[1]]     ← push link_map onto stack
    jmp  [GOT[2]]     ← jump into ld.so resolver

PLT[n] layout (one per external function):
    jmp  [GOT[n]]     ← jump to GOT slot (bounce or real address)
    push index         ← slot index for resolver to identify function
    jmp  PLT[0]        ← fall through to resolver trampoline

The code here NEVER changes. Only the GOT slot it reads changes.
This is what keeps .text read-only and shareable between processes.
```

*Note: Here GOT\[\] refers to it's address not its value, notice we are dereferencing to get the value pointed by GOT\[\] addresses. (And those values are also addresses lol). GOT slots are data (they hold addresses). On the other hand PLT\[\] slots are code/instruction, we directly jump to the address of those instruction and execute them, no need to dereference it*


4. **.plt.got (PLT for eagerly bound functions):**

```
Purpose:    Stubs for functions that are resolved at load time
            not lazily. Used for internal/special functions like
            __cxa_finalize.

Written by: Linker (created at link time)

Writable:   No - read-only

Contains:   Compact 2-instruction stubs (no lazy fallback needed)

Layout (per function):
    jmp  [GOT slot]   ← jump directly, slot already filled at load time
    nop               ← padding (no push/jmp PLT[0] needed)

Difference from .plt:
    .plt      has 3 instructions - jmp + push index + jmp PLT[0]
    .plt.got  has 2 instructions - jmp + nop
    Because .plt.got functions are already resolved, the bounce
    fallback is unnecessary.
```

**Steps:**

```
COMPILE TIME    (gcc -c -fPIC)
    .text:       call [00000000]   mov rax,[rip+0x0]   ← placeholder zeros
	.rela.text:  R_X86_64_PLT32, R_X86_64_REX_GOTPCREL → linker to-do list
```

```
LINK TIME    (gcc -shared)
	.text:       call 0x1030   mov rax,[rip+0x2e89] ← real offsets patched
	.rela.text:  consumed and GONE
	.rela.dyn:   R_X86_64_GLOB_DAT (myglob)         → ld.so to-do (eager)
	.rela.plt:   R_X86_64_JUMP_SLOT (ml_util_func)  → ld.so to-do (lazy)
	GOT[ml_util]: initialized to 0x1036 (PLT bounce address)
```

```
LOAD TIME    (ld.so, before main)
	GOT[myglob]  @ 0x7ffff7fbbfc8   ←  0x7ffff7fbc010   ✓ eager (value=42)
	GOT[1],[2]                      ←  link_map, resolver ✓ eager
	GOT[ml_util] @ 0x7ffff7fbc000  =   0x7ffff7fb9036   ✗ still PLT bounce
```

```
FIRST CALL    (resolver fires once)
	call PLT[n]→PLT[n] → JMP → GOT(bounce) → push 0x0 → PLT[0] → resolver
	resolver: base(0x7ffff7fb8000) + 0x1109 = 0x7ffff7fb9109
	GOT[ml_util] @ 0x7ffff7fbc000  ←  0x7ffff7fb9109   ✓ patched

SECOND CALL+  (direct forever)
	PLT[n] → JMP → GOT (0x7ffff7fb9109) → ml_util_func ✓ direct
	Resolver never involved again.
```

**Diagram:**

```
.text (read-only)                 .got.plt (writable)
─────────────────                 ───────────────────
your code                         GOT[0] = address of .dynamic section
  call ml_util_func@plt           GOT[1] = link_map
         │                        GOT[2] = resolver
         ▼                        GOT[n] = 0x7f...9036 (before first call)
.plt                                     = 0x7f...9109 (after first call)
  PLT[n]: jmp [GOT[n]] ─────────────────────────┘
          push index    <- (only on first call, GOT bounces back)
          jmp PLT[0]  
                 │            
                 ▼            
        PLT[0]: push GOT[1] 
                jmp  GOT[2] ──────► ld.so resolver
                                          │
                                          └──► patches GOT[n]
                                               jumps to function

.text (read-only)                        .got (writable)
─────────────────                        ────────────────
your code                                 GOT[myglob] = &myglob
	mov rax, [rip+0x2e89] ────────────────────┘
	mov edx, [rax]                 (filled eagerly at load time by ld.so)
		(dereference to get value)

.plt.got (read-only)                     .got (writable)
────────────────────                     ────────────────
  jmp [GOT slot] ─────────────────► GOT[__cxa_finalize] = &__cxa_finalize
  nop                               (filled eagerly at load time by ld.so)
```


## References

- https://eli.thegreenplace.net/tag/linkers-and-loaders
- https://reverseengineering.stackexchange.com/questions/1992/what-is-plt-got/1993#1993

## Appendix: automating the walkthrough with GDB's Python API

Once I understood the flow, I scripted it so the whole first-call/second-call trace replays in one command (`gdb -q -x gdb_script.py`). This version comes from a later build compiled with Intel CET enabled (GCC's default `-fcf-protection` on recent Ubuntu), so every PLT stub starts with `endbr64` and the jump stubs live in a separate `.plt.sec` section. That is why its offsets (`0x1119`, `0x1050`) differ from the ones above.

```python
import gdb

gdb.execute('file driver')
gdb.execute('set environment LD_LIBRARY_PATH=.')
gdb.execute('break ml_func')
gdb.execute('run')

# Get addresses
ml_util_addr  = int(gdb.parse_and_eval('&ml_util_func'))
base          = ml_util_addr - 0x1119
got_ml_util   = base + 0x4000
plt_sec       = base + 0x1050
plt0          = base + 0x1020

print(f'\nbase            = 0x{base:x}')
print(f'ml_util_func    = 0x{ml_util_addr:x}')
print(f'GOT[ml_util]    = 0x{got_ml_util:x}')
print(f'PLT.sec         = 0x{plt_sec:x}')
print(f'PLT[0]          = 0x{plt0:x}')

def got_val():
    raw = gdb.execute(f'x/gx 0x{got_ml_util:x}', to_string=True)
    return int(raw.split(':')[1].strip(), 16)

print(f'\nGOT[ml_util] before first call = 0x{got_val():x}')
print(f'Points back into PLT?           {hex(got_val()).startswith(hex(plt_sec)[:8])}')

# Step through PLT for first call
gdb.execute(f'break *0x{plt_sec:x}')
gdb.execute('continue')

print('\n--- FIRST CALL: entering PLT.sec ---')
print(gdb.execute('x/3i $rip', to_string=True).strip())

gdb.execute('ni')  # skip endbr64
print('\nSkipped endbr64, now at JMP:')
print(gdb.execute('x/2i $rip', to_string=True).strip())

gdb.execute('stepi')  # execute jmp [got] -> bounces to PLT[n]+6
print('\nAfter JMP [GOT] (bounced back into PLT):')
print(gdb.execute('x/3i $rip', to_string=True).strip())

gdb.execute('stepi')  # skip endbr64 in PLT[n]
gdb.execute('stepi')  # push function_index
print('\nAfter PUSH function_index (0x0):')
print(gdb.execute('x/2i $rip', to_string=True).strip())

gdb.execute('stepi')  # jmp PLT[0]
print('\nJumped to PLT[0] resolver trampoline:')
print(gdb.execute('x/3i $rip', to_string=True).strip())

# Now let ld.so resolver run fully
gdb.execute('delete breakpoints')
gdb.execute(f'break *0x{ml_util_addr:x}')
gdb.execute('continue')
print('\nResolver DONE. Now at ml_util_func entry:')
print(gdb.execute('x/2i $rip', to_string=True).strip())
print(f'\nGOT[ml_util] AFTER resolver = 0x{got_val():x}')
print(f'Equals &ml_util_func?        {got_val() == ml_util_addr}')

# Second call
gdb.execute('delete breakpoints')
gdb.execute('break ml_func')
gdb.execute('continue')  # finish first ml_func, hit second
gdb.execute(f'break *0x{plt_sec:x}')
gdb.execute('continue')  # inside second ml_func, hits PLT.sec

print('\n--- SECOND CALL: entering PLT.sec ---')
print(f'GOT[ml_util] = 0x{got_val():x}  (already resolved)')
gdb.execute('ni')   # skip endbr64
gdb.execute('stepi')  # execute jmp [got]
rip_after = int(gdb.parse_and_eval('$rip'))
print(f'\nAfter JMP [GOT]: RIP = 0x{rip_after:x}')
print(f'ml_util_func address = 0x{ml_util_addr:x}')
print(f'Went directly to ml_util_func? {rip_after == ml_util_addr}')
print('\nNO push, NO resolver, NO PLT[0]. Just one jump.')

gdb.execute('quit')
```
{% endraw %}
