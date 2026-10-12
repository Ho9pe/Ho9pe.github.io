#!/usr/bin/env bash
# Local build check that mirrors GitHub Pages (github-pages gem).
# Usage (from the repo root, PowerShell):
#   docker run --rm -v "${PWD}:/srv" -v jekyll-gems:/usr/local/bundle -w /srv ruby:3.3-slim bash tools/docker-build.sh
set -e
if ! command -v gcc >/dev/null; then
  apt-get update -qq && apt-get install -y -qq build-essential git >/dev/null
fi
bundle config set --local path /usr/local/bundle >/dev/null
bundle install --quiet
JEKYLL_ENV=production bundle exec jekyll build --trace 2>&1 | grep -v "Deprecation\|faraday-retry\|github-pages" || true
test -f _site/index.html && echo "BUILD OK: $(find _site -name '*.html' | wc -l) html files"
