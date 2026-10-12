---
title: "Holmes CTF 2025: a solo, all-blue-team run"
date: 2025-09-28 21:00:00 +0600
series: "CTF recaps"
platform: "Hack The Box"
summary: "Hack The Box's first all-blue-team CTF. I played it solo, cleared all 65 challenges in three days, and finished 251st of 7,085 teams."
description: "Hack The Box's first all-blue-team CTF. I played it solo, cleared all 65 challenges in three days, and finished 251st of 7,085 teams."
tags: ["dfir", "forensics", "malware", "recap"]
---

I just wrapped up Hack The Box's first-ever all-blue-team CTF, **Holmes CTF 2025**. I played this Sherlock-themed investigation solo and finished **251st out of 7,085 teams**. It took me three days, and although it took a while, I'm very happy to have finished **all 65 of 65 challenges** across the different incident-response categories.

## The challenge I enjoyed most: *The Payload*

The malware analysis challenge had me reversing a live sample in Ghidra, staring at the disassembly for hours until the execution flow finally made sense step by step. The sample used a **COM wrapper** to bridge native C++ code with a .NET assembly, and working out how it used COM interop to reach managed code from unmanaged code was fascinating. Decoding the killswitch domain at the end was the most satisfying moment of the event.

## The one I struggled with: *The Watchman's Residue*

This SOC challenge spread the evidence across network logs, RMM logs, Windows event logs, registry hives and a KeePass artifact. Even after working through all of them I was still missing key information, and I was stuck on some tasks for a long time.

The breakthrough was the **USN Journal**. I had never worked with the `$J` file before. I parsed it to CSV with MFTECmd and spent hours building the timeline by hand with `grep`. The trap: the RMM logs were in local time while the USN Journal was in UTC, and it took me several wrong submissions to notice.

## Tools I used

Ghidra, Wireshark, Volatility 3, MFTECmd, John the Ripper, RegRipper, `Get-WinEvent`, Autopsy, bulk_extractor, pwntools, and good old `grep` and `find`.

What I liked most is that every challenge simulated a realistic incident, and they were all connected into one investigation. The Hack The Box team did an excellent job, and I'd love to see more CTFs like this.
