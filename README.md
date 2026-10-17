# ho9pe.github.io

Personal site of Md Asif Sajeed: research, projects, CTF results and writeups.
Live at **https://ho9pe.github.io**.

## Stack at a glance

| Part | What it is | Where it lives |
|---|---|---|
| Site generator | [Jekyll](https://jekyllrb.com), pinned through the `github-pages` gem so local builds match GitHub's | `_config.yml`, `Gemfile` |
| Hosting and deploy | GitHub Pages, *Deploy from a branch* → `main` / `(root)`. GitHub builds the site itself on every push. There's no workflow file. | repo Settings → Pages |
| Templates | Liquid, in layouts and includes | `_layouts/`, `_includes/` |
| Markdown | kramdown with GFM input, and Rouge for code highlighting | `_config.yml` |
| Plugins | `jekyll-feed` (`/feed.xml`), `jekyll-seo-tag` (`{% seo %}` meta and Open Graph tags), `jekyll-sitemap` (`/sitemap.xml`) | `_config.yml` |
| Styling | One hand-written CSS file with no framework or preprocessor. Design tokens, with light and dark mode. | `assets/css/site.css` |
| JavaScript | One vanilla file with no dependencies and no build step | `assets/js/site.js` |
| Fonts | Schibsted Grotesk (text) and JetBrains Mono (code, dates and labels), from Google Fonts | `_includes/head.html` |
| Content data | Blog groups and featured posts, project cards, CTF results, as YAML | `_data/` |
| Content tooling | Obsidian note → post converter, plain Python standard library | `tools/obsidian2post.py`, `tools/posts.json` |
| Local preview | Docker (`ruby:3.3-slim`), so nothing gets installed on the host | `tools/docker-serve.sh`, `tools/docker-build.sh` |

## Repo layout

```
_config.yml          site settings: title, social links, CV path, permalinks, plugins
_layouts/
  default.html       HTML shell: <head>, nav, footer, site.js
  page.html          section page: header (eyebrow, title, lede, buttons), then the content
  post.html          blog post: breadcrumb, meta, tags, side rail (at a glance + contents),
                     older/newer links and more posts from the same group
_includes/
  head.html          meta tags, fonts, CSS, applies the saved theme before first paint
  nav.html           header, menu, dark-mode button, reading-progress bar on posts
  footer.html        footer links (read from `social:` in _config.yml)
  post-card.html     the post card used on the home page, blog and posts
  post-group.html    finds a post's group in _data/blog.yml
  rank-reversal.html the thesis AUC dot plot (home + research)
  icon.html          inline SVG icons; read-time, teaser, ordinal, thousands: small helpers
_data/
  blog.yml           blog groups, topic buttons, featured posts, card covers, card teasers
  glance.yml         the "At a glance" box on every post, keyed by slug
  projects.yml       project cards (and which three the home page shows)
  ctf.yml            the results table on /ctf/
index.html           home page
research.html        /research/   thesis, papers, experience, skills
projects.html        /projects/   project cards (from _data/projects.yml)
ctf.html             /ctf/        highlights, results (from _data/ctf.yml), practice, toolbox
blog/index.html      /blog/       start-here cards, filters, posts grouped by year
404.html             not-found page
_posts/              blog posts, YYYY-MM-DD-slug.md → /blog/slug/
assets/
  css/site.css       all styling (not style.css: see Gotchas)
  js/site.js         theme toggle, code-block header + copy button, post contents rail
                     and reading progress, blog filters
  cv/Md_Asif_Sajeed_CV.pdf   the CV behind the "CV" / "Download CV" links
  img/               profile photo, favicon (post images go in img/posts/)
tools/               converter + Docker scripts (excluded from the built site)
```

## How the pieces fit

- **Layouts nest.** Every page ends up in `default.html`. The research, projects and CTF pages use `layout: page`, which draws the page header from front matter (`eyebrow`, `title`, `lede`, and `actions`: buttons with a `label` plus `social: <key>`, `cv: true` or `href:`). The rest of each page is full-width `<section class="band">` blocks. Posts get `layout: post` automatically, via `defaults:` in `_config.yml`.
- **URLs.** Pages set their own `permalink:`. Posts get `/blog/<slug>/`, where the slug comes from the file name (`permalink: /blog/:title/`).
- **Post front matter:**
  ```yaml
  ---
  title: "Name: one-line hook"
  date: 2026-10-08 20:00:00 +0600
  series: "AlpacaHack Daily"     # optional. Puts the post in a blog group (see below)
  platform: "AlpacaHack"         # optional. Shown in the date line
  summary: "One or two sentences." # shown under the title and in the blog list
  description: "Same as summary."  # used by jekyll-seo-tag for search/social previews
  tags: ["pwn"]
  teaser: "One sentence."          # optional. Card text; defaults to the summary's first sentence
                                   # (for converted posts, use `teasers` in _data/blog.yml instead)
  ---
  ```
  The reading time is worked out at about 220 words a minute (`_includes/read-time.html`).
- **Blog groups come from `_data/blog.yml`.** A post joins the first group that lists its slug under `posts`, otherwise the group that lists its `series` (Deep dives = Malware analysis and HTB Sherlocks, plus the PIC and whisper_evidence posts by slug; CTF writeups = Hardware and Black Hat). A post with a new series shows up under "All posts" only until that series is added to a group. The same file sets the topic buttons, the "Start here" and home-page featured posts (by slug), the monospace cover lines on cards and short card `teasers`. A tag not listed under `topics` still works on posts and in the URL; it just has no button.
- **"At a glance" boxes come from `_data/glance.yml`**, one entry per post slug (writeups use Source, Category, Target, Tools; recaps and notes their own fields). Add one with every new post; a post without an entry simply has no box. It lives in a data file rather than front matter because the converter rewrites converted posts. Filtering happens in the browser (`site.js`) and keeps the state in the URL hash (`/blog/#deep-dives`, `/blog/#pwn`, `/blog/#alpacahack-daily+pwn`), so tag links on posts open the blog already filtered. Old series hashes such as `#htb-sherlocks` still work.
- **Cards line up row by row.** Card grids use CSS subgrid: each card spans a fixed number of rows (`.card.r3` / `.r4` / `.r5`), so titles, text and tags start at the same height across a row. A card's direct children are its rows, so keep the markup flat when adding one.
- **Table of contents.** Long posts start with a collapsible `<details class="toc" markdown="1">` that holds kramdown's `* TOC` / `{:toc}`. That is the fallback without JavaScript: `site.js` builds an "On this page" list from the post's `h2`s (or its `h3`s when there are fewer than two `h2`s), puts it in the side rail under the "At a glance" box (a collapsed list above the post on narrow screens) and hides the inline one. Sections are numbered 01, 02 … in the list and on the headings, replacing numbering typed into a heading ("3.", "4.1", "Step 2:", "Phase 5 -"; "Stage N" is kept because it names a stage); a heading starting with "Appendix" gets a dot instead. Tables in posts are wrapped in a scrolling `.table-wrap` so they fill the column.
- **No long dashes.** The site uses no em or en dashes: "-" or a colon instead. The converter enforces this on converted posts.
- **`{% raw %}` around post bodies.** Liquid would otherwise try to evaluate `{{ … }}` and `{% … %}` inside code (Jinja, format strings and so on). Anything written by hand that contains braces needs the same wrapping.
- **Theme.** All colours are CSS variables on `:root`. The dark values appear **twice**: once under `@media (prefers-color-scheme: dark)` with `:root:not([data-theme="light"])`, and again under `:root[data-theme="dark"]`. When you change a colour, change it in both places. The nav button sets `data-theme` and saves the choice to `localStorage`. A small inline script in `head.html` re-applies that choice before the page draws, so the page doesn't flash the wrong theme. With no saved choice, the site follows the OS setting.
- **Code highlighting.** Rouge emits CSS classes, and their colours are the `--hl-*` tokens in `site.css`, so code blocks follow the theme too.

## Common tasks

### Preview locally

Run this from the repo root in PowerShell, then open http://localhost:4000. It rebuilds when you save a file.

```
docker run --rm --name site-preview -p 4000:4000 -v "${PWD}:/srv" -v jekyll-gems:/usr/local/bundle -w /srv ruby:3.3-slim bash tools/docker-serve.sh
```

Stop it with Ctrl+C, or with `docker stop site-preview`. The `jekyll-gems` volume keeps the installed gems, so only the first run is slow. For a one-off production build check, the same way GitHub builds it, run:

```
docker run --rm -v "${PWD}:/srv" -v jekyll-gems:/usr/local/bundle -w /srv ruby:3.3-slim bash tools/docker-build.sh
```

### Publish

Commit and push to `main`. GitHub rebuilds the site in about a minute. Watch the **Actions** tab ("pages build and deployment"). If the build fails, the error appears there, and `tools/docker-build.sh` reproduces it locally.

### Write a post by hand

Create `_posts/YYYY-MM-DD-slug.md` with the front matter above, write Markdown, and push. Put images in `assets/img/posts/` and link them as `/assets/img/posts/name.png`.

### Convert notes from Obsidian

1. Add an entry to `tools/posts.json` with `source` (path to the note in the vault), `slug`, `date`, `title`, `summary`, `tags`, and optionally `series`, `platform`, `"toc": false`, `append` and `replace`. `append` names a Markdown file (kept in `tools/extras/`) that's added to the end of the post: use it for site-only extras that aren't in the note. `replace` holds `[from, to]` pairs for that post only (the top-level `replace` applies to every post). A note that holds several writeups can be split on its top-level `# ` headings with `sections` (see the existing entries).
2. Run it with any Python 3. Only the standard library is used. `--only` limits the run to the given slugs:
   ```
   python tools/obsidian2post.py tools/posts.json --only blackhat-whisper-evidence
   ```
3. Add the post's "At a glance" entry to `_data/glance.yml`, check the new file in `_posts/`, then commit and push.

The converter drops the note's first H1, removes `table-of-contents` blocks and a "Contents" / "Table of Contents" heading left empty, replaces em and en dashes ("a - b" in text, "Stage 1: Load" in headings, just the character in code), turns `==highlight==` into `<mark>` and `[[link|alias]]` into plain text, copies `![[image.png]]` embeds into `assets/img/posts/`, applies the `replace` pairs (used to hide live challenge hosts), and wraps the body in `{% raw %}`.

> **Without `--only` it rewrites every post listed in `posts.json`.** Any hand edits to a converted post are lost, so make edits in the Obsidian note (or in an `append` file or `replace` pair) and re-run. Every `source` path also has to exist on the machine you run it on. Posts not listed in `posts.json` (the CTF recaps, the malware analysis, the side-channel writeup) are hand-written and never touched.

### Edit pages

- **Projects:** add or edit entries in `_data/projects.yml`. Its `home` list picks the three cards on the home page.
- **CTF results:** add a row at the top of `_data/ctf.yml`. With `rank` and `total` the table prints the placement, team count and the "ahead of" bar by itself. The three highlight cards at the top of `ctf.html` are written by hand.
- **Research:** `research.html` is plain HTML: copy a `<li>` in the `pubs` list to add a paper.
- **Home page:** `index.html` holds the hero, highlights, news and background; the writing and project sections read from `_data/`. Site-wide text and social links are in `_config.yml`.

### Update the CV

The CV source isn't in this repo. It's the LaTeX in `V:\Resume`, and the site uses the PhD-applicant version **with the phone number removed**:

```
cd V:\Resume
pdflatex -jobname=cv-public "\def\cvphone{}\def\cvtagline{Prospective PhD Student --- Systems Security \& Machine Learning}\def\cvshowlanguages{0}\input{cv-erasmus-masters}"
copy cv-public.pdf V:\Ho9pe.github.io\assets\cv\Md_Asif_Sajeed_CV.pdf
```

Keep the file name the same, because `cv_pdf` in `_config.yml` and every CV link point to it.

## Gotchas

- **The stylesheet is `site.css`, not `style.css`.** The `github-pages` gem applies its default Primer theme, which also builds an `assets/css/style.css`. Two files at one path means whichever Jekyll writes last wins, so the site's own CSS would sometimes be replaced by Primer's.
- **Plugins:** GitHub Pages runs only its [allow-listed plugins](https://pages.github.com/versions/). Anything else works locally and is silently ignored on GitHub. To use more, the site would have to switch to a GitHub Actions build.
- **Line endings:** `.gitattributes` forces LF and marks PDFs and images as binary. Leave it in place, or Windows checkouts will show every file as changed.
- **Ignored on purpose:** `_site/` (build output), `Gemfile.lock` (the `github-pages` gem pins versions), `.jekyll-cache/`, `vendor/` and `.bundle/`.
- **Excerpts:** `excerpt_separator` is set to `<!--more-->`, so Jekyll doesn't treat a post's first paragraph as its excerpt. Lists use `summary` instead.
- **Personal data:** keep the phone number and other private details off the site. This includes the CV PDF.
