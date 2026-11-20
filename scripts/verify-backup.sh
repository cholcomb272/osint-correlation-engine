#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'Usage: %s BACKUP.dump\n' "$0" >&2
  exit 2
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
backup=$1
test -s "$backup"

compose=(docker compose)
if [[ ${OSINT_DOCKER_SUDO:-0} == 1 ]]; then
  compose=(sudo -n docker compose)
fi

target="osint_restore_check_$(date -u +%Y%m%d%H%M%S)_$$"
if [[ ! $target =~ ^[a-zA-Z0-9_]+$ ]] || [[ $target == osint ]]; then
  printf 'Unsafe restore-check database name\n' >&2
  exit 2
fi

cd "$repo_root"
cleanup() {
  "${compose[@]}" exec -T db dropdb --username=osint --if-exists "$target" >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${compose[@]}" exec -T db createdb --username=osint "$target"
"${compose[@]}" exec -T db pg_restore \
  --username=osint \
  --dbname="$target" \
  --no-owner \
  --no-acl < "$backup"

"${compose[@]}" exec -T db psql --username=osint --dbname="$target" --tuples-only --no-align \
  --command="SELECT json_build_object('events', (SELECT count(*) FROM events), 'measurements', (SELECT count(*) FROM network_measurements), 'alembic_revision', (SELECT version_num FROM alembic_version));"
printf 'Restore verification passed in temporary database %s; it will now be removed.\n' "$target"
