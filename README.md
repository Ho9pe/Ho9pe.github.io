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
| Styling | One hand-written CSS file with no framework or preprocessor. Design tokens, with light and dark mode. | `assets/css/style.css` |
| JavaScript | One vanilla file with no dependencies and no build step | `assets/js/site.js` |
| Fonts | Inter (text) and JetBrains Mono (code), from Google Fonts | `_includes/head.html` |
| Content tooling | Obsidian note → post converter, plain Python standard library | `tools/obsidian2post.py`, `tools/posts.json` |
| Local preview | Docker (`ruby:3.3-slim`), so nothing gets installed on the host | `tools/docker-serve.sh`, `tools/docker-build.sh` |

## Repo layout

```
_config.yml          site settings: title, social links, CV path, permalinks, plugins
_layouts/
  default.html       HTML shell: <head>, nav, footer, site.js
  page.html          standard page: title + optional lede, then the content
  post.html          blog post: series, date, reading time, tags, older/newer links
_includes/
  head.html          meta tags, fonts, CSS, applies the saved theme before first paint
  nav.html           header, menu, dark-mode button
  footer.html        footer links (read from `social:` in _config.yml)
index.html           home page (HTML)
research.md          /research/   papers and the thesis
projects.md          /projects/   project cards
ctf.md               /ctf/        CTF results
blog/index.html      /blog/       post list + tag filter buttons
404.html             not-found page
_posts/              blog posts, YYYY-MM-DD-slug.md → /blog/slug/
assets/
  css/style.css      all styling
  js/site.js         theme toggle, copy buttons on code blocks, blog tag filter
  cv/Md_Asif_Sajeed_CV.pdf   the CV behind the "CV" / "Download CV" links
  img/               profile photo, favicon (post images go in img/posts/)
tools/               converter + Docker scripts (excluded from the built site)
```

## How the pieces fit

- **Layouts nest.** Every page ends up in `default.html`. Markdown pages use `layout: page`, which wraps the content in a title and lede. Posts get `layout: post` automatically, via `defaults:` in `_config.yml`.
- **URLs.** Pages set their own `permalink:`. Posts get `/blog/<slug>/`, where the slug comes from the file name (`permalink: /blog/:title/`).
- **Post front matter:**
  ```yaml
  ---
  title: "Name: one-line hook"
  date: 2026-10-08 20:00:00 +0600
  series: "AlpacaHack Daily"     # optional. Shown above the title; also a filter button
  platform: "AlpacaHack"         # optional. Shown in the date line
  summary: "One or two sentences." # shown under the title and in the blog list
  description: "Same as summary."  # used by jekyll-seo-tag for search/social previews
  tags: ["pwn"]
  ---
  ```
  The reading time is worked out in `post.html`, at about 220 words a minute.
- **Blog filter buttons are hard-coded.** `series_list` and `tag_list` at the top of `blog/index.html` decide which buttons appear. A new tag works on posts straight away, but it only gets a button once you add it there. Filtering happens in the browser (`site.js`) and uses `#tag` in the URL, so clicking a tag on a post opens the blog already filtered.
- **Table of contents.** Long posts start with a collapsible `<details class="toc" markdown="1">` that holds kramdown's `* TOC` / `{:toc}`.
- **`{% raw %}` around post bodies.** Liquid would otherwise try to evaluate `{{ … }}` and `{% … %}` inside code (Jinja, format strings and so on). Anything written by hand that contains braces needs the same wrapping.
- **Theme.** All colours are CSS variables on `:root`. The dark values appear **twice**: once under `@media (prefers-color-scheme: dark)` with `:root:not([data-theme="light"])`, and again under `:root[data-theme="dark"]`. When you change a colour, change it in both places. The nav button sets `data-theme` and saves the choice to `localStorage`. A small inline script in `head.html` re-applies that choice before the page draws, so the page doesn't flash the wrong theme. With no saved choice, the site follows the OS setting.
- **Code highlighting.** Rouge emits CSS classes, and their colours are the `--hl-*` tokens in `style.css`, so code blocks follow the theme too.

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

1. Add an entry to `tools/posts.json` with `source` (path to the note in the vault), `slug`, `date`, `title`, `summary`, `tags`, and optionally `series`, `platform`, and `"toc": false`. A note that holds several writeups can be split on its top-level `# ` headings with `sections` (see the existing entries).
2. Run it with any Python 3. Only the standard library is used.
   ```
   python tools/obsidian2post.py tools/posts.json
   ```
3. Check the new file in `_posts/`, then commit and push.

The converter drops the note's first H1, removes `table-of-contents` blocks, turns `==highlight==` into `<mark>` and `[[link|alias]]` into plain text, copies `![[image.png]]` embeds into `assets/img/posts/`, applies the `replace` pairs (used to hide live challenge hosts), and wraps the body in `{% raw %}`.

> **It rewrites every post listed in `posts.json` each time it runs.** Any hand edits to a converted post are lost, so make edits in the Obsidian note and re-run. Every `source` path also has to exist on the machine you run it on.

### Edit pages

`research.md`, `projects.md` and `ctf.md` are Markdown with some HTML card markup (`<div class="cards">`, `<article class="card">`). Copy an existing card to add one. The home page is `index.html`. Site-wide text and social links are in `_config.yml`.

### Update the CV

The CV source isn't in this repo. It's the LaTeX in `V:\Resume`, and the site uses the PhD-applicant version **with the phone number removed**:

```
cd V:\Resume
pdflatex -jobname=cv-public "\def\cvphone{}\def\cvtagline{Prospective PhD Student --- Systems Security \& Machine Learning}\def\cvshowlanguages{0}\input{cv-erasmus-masters}"
copy cv-public.pdf V:\Ho9pe.github.io\assets\cv\Md_Asif_Sajeed_CV.pdf
```

Keep the file name the same, because `cv_pdf` in `_config.yml` and every CV link point to it.

## Gotchas

- **Plugins:** GitHub Pages runs only its [allow-listed plugins](https://pages.github.com/versions/). Anything else works locally and is silently ignored on GitHub. To use more, the site would have to switch to a GitHub Actions build.
- **Line endings:** `.gitattributes` forces LF and marks PDFs and images as binary. Leave it in place, or Windows checkouts will show every file as changed.
- **Ignored on purpose:** `_site/` (build output), `Gemfile.lock` (the `github-pages` gem pins versions), `.jekyll-cache/`, `vendor/` and `.bundle/`.
- **Excerpts:** `excerpt_separator` is set to `<!--more-->`, so Jekyll doesn't treat a post's first paragraph as its excerpt. Lists use `summary` instead.
- **Personal data:** keep the phone number and other private details off the site. This includes the CV PDF.
