#!/usr/bin/env python3
"""Turn Obsidian notes into Jekyll posts for this site.

Usage:
    python tools/obsidian2post.py tools/posts.json

posts.json lists each source note and the front matter for the post(s) it
becomes. A note that holds several writeups (one per top-level "# " heading)
is split by giving a "sections" list instead of a single post.

What the converter does to each note:
  * drops the note's first H1 (the post layout prints the title)
  * removes Obsidian-only blocks (```table-of-contents)
  * turns ==highlight== into <mark>, [[link|alias]] into plain text,
    and ![[image.png]] into a normal image copied to assets/img/posts/
  * applies the "replace" pairs (e.g. live challenge hosts -> <host>)
  * wraps the body in {% raw %} so Jinja/f-string braces survive Liquid
Standard library only.
"""
import json, re, shutil, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POSTS = ROOT / "_posts"
IMG = ROOT / "assets" / "img" / "posts"
FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")


def split_fences(lines):
    """Yield (line, in_code) so transforms can skip fenced code."""
    fence = None
    for line in lines:
        m = FENCE.match(line)
        if fence is None and m:
            fence = m.group(1)
            yield line, True
            continue
        if fence is not None:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) and line.strip() == m.group(1):
                fence = None
            yield line, True
            continue
        yield line, False


def sections(text):
    """Split a multi-writeup note on top-level '# ' headings outside code."""
    out, cur, title = [], [], None
    for line, code in split_fences(text.splitlines()):
        if not code and line.startswith("# "):
            if title is not None or any(l.strip() for l in cur):
                out.append((title, "\n".join(cur)))
            title, cur = line[2:].strip(), []
        else:
            cur.append(line)
    out.append((title, "\n".join(cur)))
    return [s for s in out if s[0]]


def clean(body, src_dir, replace):
    lines = body.splitlines()
    # drop Obsidian table-of-contents plugin blocks
    txt = re.sub(r"```table-of-contents.*?```\n?", "", "\n".join(lines), flags=re.S)
    out = []
    for line, code in split_fences(txt.splitlines()):
        if not code:
            line = re.sub(r"==([^=\n]+)==", r"<mark>\1</mark>", line)
            def embed(m):
                name = m.group(1).split("|")[0].strip()
                hit = next(iter(src_dir.rglob(name)), None) or next(iter(src_dir.parent.rglob(name)), None)
                if hit:
                    IMG.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(hit, IMG / hit.name)
                    return f"![{hit.stem}](/assets/img/posts/{hit.name})"
                return ""
            line = re.sub(r"!\[\[([^\]]+)\]\]", embed, line)
            line = re.sub(r"\[\[([^\]|]+)\|([^\]]+)\]\]", r"\2", line)
            line = re.sub(r"\[\[([^\]]+)\]\]", r"\1", line)
        out.append(line)
    txt = "\n".join(out)
    for a, b in replace:
        txt = txt.replace(a, b)
    return txt.strip("\n")


def strip_first_h1(text):
    lines = text.splitlines()
    for i, (line, code) in enumerate(split_fences(lines)):
        if line.strip():
            if not code and line.startswith("# "):
                return "\n".join(lines[i + 1:])
            return text
    return text


def yaml_str(s):
    return json.dumps(s, ensure_ascii=False)


def write_post(meta, body):
    fm = ["---", f"title: {yaml_str(meta['title'])}", f"date: {meta['date']}"]
    for key in ("series", "platform", "summary"):
        if meta.get(key):
            fm.append(f"{key}: {yaml_str(meta[key])}")
    if meta.get("summary"):
        fm.append(f"description: {yaml_str(meta['summary'])}")
    fm.append("tags: [" + ", ".join(yaml_str(t) for t in meta.get("tags", [])) + "]")
    fm.append("---")
    toc = ""
    if meta.get("toc", True):
        toc = '<details class="toc" markdown="1">\n<summary>Contents</summary>\n\n* TOC\n{:toc}\n\n</details>\n\n'
    text = "\n".join(fm) + "\n\n" + toc + "{% raw %}\n" + body + "\n{% endraw %}\n"
    name = f"{meta['date'][:10]}-{meta['slug']}.md"
    (POSTS / name).write_text(text, encoding="utf-8")
    return name


def main(manifest):
    cfg = json.loads(Path(manifest).read_text(encoding="utf-8"))
    replace = [tuple(p) for p in cfg.get("replace", [])]
    POSTS.mkdir(exist_ok=True)
    written = []
    for item in cfg["notes"]:
        src = Path(item["source"])
        raw = src.read_text(encoding="utf-8")
        raw = re.sub(r"\A---\n.*?\n---\n", "", raw, flags=re.S)  # note front matter
        if "sections" in item:
            found = dict(sections(raw))
            for sec in item["sections"]:
                key = next((t for t in found if t.startswith(sec["heading"])), None)
                if key is None:
                    sys.exit(f"section {sec['heading']!r} not found in {src}")
                meta = {**item.get("defaults", {}), **sec}
                written.append(write_post(meta, clean(found[key], src.parent, replace)))
        else:
            body = clean(strip_first_h1(raw), src.parent, replace)
            written.append(write_post(item, body))
    print(f"wrote {len(written)} posts:")
    for w in written:
        print("  ", w)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "tools/posts.json")
