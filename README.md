# ho9pe.github.io

Personal site of Md Asif Sajeed: research, projects, CTF results and writeups.
Built with Jekyll and served by GitHub Pages from `main`.

## Adding a post from Obsidian

1. Add an entry for the note to `tools/posts.json` (source path, slug, date, title, summary, tags).
   A note holding several writeups can be split by its top-level `# ` headings using `sections`.
2. Run the converter (standard-library Python):

   ```
   python tools/obsidian2post.py tools/posts.json
   ```

3. Commit the new file in `_posts/` and push. GitHub rebuilds the site in about a minute.

## Local preview

```
docker run --rm -v "${PWD}:/srv" -w /srv -p 4000:4000 ruby:3.3-slim bash -c "apt-get update -qq && apt-get install -y -qq build-essential git >/dev/null && bundle install --quiet && bundle exec jekyll serve --host 0.0.0.0"
```
