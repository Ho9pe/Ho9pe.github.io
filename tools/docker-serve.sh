#!/usr/bin/env bash
# Live local preview at http://localhost:4000 that rebuilds when a file is saved.
# Usage (from the repo root, PowerShell); stop with Ctrl+C or `docker stop site-preview`:
#   docker run --rm --name site-preview -p 4000:4000 -v "${PWD}:/srv" -v jekyll-gems:/usr/local/bundle -w /srv ruby:3.3-slim bash tools/docker-serve.sh
set -e
if ! command -v gcc >/dev/null; then
  apt-get update -qq && apt-get install -y -qq build-essential git >/dev/null
fi
bundle config set --local path /usr/local/bundle >/dev/null
bundle install --quiet
# --force_polling: file-change events don't cross a Windows bind mount, so poll instead.
exec bundle exec jekyll serve --host 0.0.0.0 --force_polling
