---
title: "RecordPlayer: fixing two hidden switches with a two-byte patch"
date: 2026-07-02 12:00:00 +0600
series: "crackmes.one"
platform: "crackmes.one"
summary: "The audio plays as noise because direction and pitch are hard-coded to the wrong values. Two bytes in x64dbg make it play the flag."
description: "The audio plays as noise because direction and pitch are hard-coded to the wrong values. Two bytes in x64dbg make it play the flag."
tags: ["rev", "windows", "patching"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
**Challenge:** RecordPlayer  
**Author:** Fatmike  
**Category:** Reverse Engineering  
**Platform:** Windows x86-64

## Description

A Windows GUI app that plays audio when you click PLAY — but it sounds like noise. The README hints at two broken "switches" controlling direction and pitch, but no switches are visible in the UI. They need to be fixed in the binary.

## Reconnaissance

```
$ file RecordPlayer.exe
RecordPlayer.exe: PE32+ executable for MS Windows 6.00 (GUI), x86-64, 6 sections
```

The `.rsrc` section is unusually large (~1.2 MB), indicating embedded audio data. Key imports include `waveOutOpen`, `waveOutWrite`, and `waveOutPrepareHeader`, confirming PCM audio playback via WinMM.

## Static Analysis (IDA / Hex-Rays)

### Application Flow

`WinMain` constructs a `MainDialog` object, shows it via `DialogBoxParamW`, then cleans up. The app is entirely dialog-based.

### The PLAY Button Handler (`sub_140003860`)

Button handler dispatches on control ID. Case `1001` is PLAY:

```c
case 1001:
    sub_140001F50(audio_obj, 0x8D);   // load audio resource (type "SOUND", ID 141)

    sub_140003A00(audio_obj, 1);      // ← SWITCH 1: direction (broken)
    sub_140003A20(audio_obj, 1);      // ← SWITCH 2: pitch    (broken)

    sub_1400020F0(audio_obj);         // start playback thread
    break;
```

Both switches are **hardcoded to `1`** — the broken state. There is no UI to toggle them.

### Switch 1 — Direction (`sub_140003A00`)

```c
__int64 __fastcall sub_140003A00(__int64 audio_obj, unsigned __int8 a2)
{
    // a2=1  →  2*(1^1)-1 = -1  (REVERSED)
    // a2=0  →  2*(0^1)-1 = +1  (FORWARD)
    __int64 step = 2 * (a2 ^ 1u) - 1;
    *(DWORD*)(audio_obj + 0x18) = step;
    return step;
}
```

Called with `a2=1`, the playback step is set to `-1`, traversing the PCM buffer backwards.

### Switch 2 — Pitch (`sub_140003A20`)

```c
void __fastcall sub_140003A20(__int64 audio_obj, char a2)
{
    *(BYTE*)(audio_obj + 0x1D) = a2;   // pitch_mode flag
}
```

When `pitch_mode = 1`, the sample fill function activates a sinusoidal speed oscillator that bounces the playback rate between ~0.3x and ~1.2x, producing the warbled noise. Setting it to `0` plays samples directly.

## The Patch

Navigate in x64dbg with **Ctrl+G** → `recordplayer.exe+3860`, then scroll to the case 1001 branch:

```
00007FF702FF392D    B2 01    mov dl,1    ← SWITCH 1 (direction)
00007FF702FF392F    48:8B4B 50    mov rcx,[rbx+50]
00007FF702FF3933    E8 ...        call sub_3A00

00007FF702FF3938    B2 01    mov dl,1    ← SWITCH 2 (pitch)
00007FF702FF393A    48:8B4B 50    mov rcx,[rbx+50]
00007FF702FF393E    E8 ...        call sub_3A20
```

**Double-click each `mov dl,1` and change to `mov dl,0`:**

|Address|Before|After|Effect|
|---|---|---|---|
|`0x...392D`|`B2 01`|`B2 00`|step = +1 (forward)|
|`0x...3938`|`B2 01`|`B2 00`|pitch_mode = 0 (normal)|

Then: right-click → **Patches** → **Patch File** to save.

## Result

Clicking PLAY on the patched binary plays the embedded audio correctly — forward, at steady pitch — revealing the flag.

The entire fix is **2 bytes changed across 2 addresses**.

## Key Takeaways

- The "switches" were not UI elements — they were hardcoded arguments in the button handler. The README was the hint to look at audio behaviour, not the interface.
- The pitch wobble is a sinusoidal speed oscillator; recognising it as intentional distortion (not corruption) was important.
- Use `modulename+offset` addressing in x64dbg to avoid recalculating addresses after ASLR rebases between sessions.
{% endraw %}
