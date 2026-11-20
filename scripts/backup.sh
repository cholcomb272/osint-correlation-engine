#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
output=${1:-"$repo_root/backups/osint-$timestamp.dump"}
mkdir -p "$(dirname "$output")"
umask 077

compose=(docker compose)
if [[ ${OSINT_DOCKER_SUDO:-0} == 1 ]]; then
  compose=(sudo -n docker compose)
fi

cd "$repo_root"
"${compose[@]}" exec -T db pg_dump \
  --username=osint \
  --dbname=osint \
  --format=custom \
  --no-owner \
  --no-acl > "$output"

test -s "$output"
printf 'Backup created: %s\n' "$output"
