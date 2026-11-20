#!/usr/bin/env bash
set -euo pipefail

# Reproduce a clean installation from the public repository in an isolated
# Compose project. The output bundle contains no generated secrets.
REVIEW_REPOSITORY="${REVIEW_REPOSITORY:-https://github.com/cholcomb272/osint-correlation-engine.git}"
REVIEW_REF="${REVIEW_REF:-main}"
REVIEW_PORT="${REVIEW_PORT:-18787}"
REVIEW_OUTPUT_DIR="${REVIEW_OUTPUT_DIR:-$PWD/artifacts/clean-install-review-$(date -u +%Y%m%dT%H%M%SZ)}"
REVIEW_PROJECT="osint_review_${$}"
DOCKER=(docker)
if [ "${OSINT_DOCKER_SUDO:-0}" = "1" ]; then
  DOCKER=(sudo -n docker)
fi

case "$REVIEW_PORT" in
  ''|*[!0-9]*) echo "REVIEW_PORT must be numeric" >&2; exit 2 ;;
esac
if [ "$REVIEW_PORT" -lt 1024 ] || [ "$REVIEW_PORT" -gt 65535 ]; then
  echo "REVIEW_PORT must be between 1024 and 65535" >&2
  exit 2
fi

for command in git docker curl python3; do
  command -v "$command" >/dev/null || { echo "Missing required command: $command" >&2; exit 2; }
done

review_root="$(mktemp -d -t osint-review.XXXXXXXX)"
checkout="$review_root/checkout"
mkdir -p "$REVIEW_OUTPUT_DIR"
chmod 700 "$REVIEW_OUTPUT_DIR"

cleanup() {
  status=$?
  if [ -d "$checkout" ]; then
    (cd "$checkout" && "${DOCKER[@]}" compose --project-name "$REVIEW_PROJECT" down -v --remove-orphans) >/dev/null 2>&1 || true
  fi
  case "$review_root" in
    /tmp/osint-review.*) rm -rf -- "$review_root" ;;
    *) echo "Refusing to remove unexpected review path: $review_root" >&2 ;;
  esac
  exit "$status"
}
trap cleanup EXIT INT TERM

git clone --depth 1 --branch "$REVIEW_REF" "$REVIEW_REPOSITORY" "$checkout"
cd "$checkout"

python3 - <<'PY' > .env
import secrets

for key in ("POSTGRES_PASSWORD", "APP_DB_PASSWORD", "API_TOKEN", "AUDIT_HASH_SALT"):
    print(f"{key}={secrets.token_urlsafe(48)}")
PY
{
  printf 'BIND_ADDRESS=127.0.0.1\n'
  printf 'HOST_PORT=%s\n' "$REVIEW_PORT"
  printf 'BGP_PREFIXES_PER_ASN=4\n'
  printf 'MAX_MONITORED_ASNS=12\n'
} >> .env
chmod 600 .env

git rev-parse HEAD > "$REVIEW_OUTPUT_DIR/commit.txt"
"${DOCKER[@]}" compose --project-name "$REVIEW_PROJECT" config --quiet
"${DOCKER[@]}" compose --project-name "$REVIEW_PROJECT" up --build -d

ready=0
for _attempt in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${REVIEW_PORT}/ready" > "$REVIEW_OUTPUT_DIR/readiness.json"; then
    ready=1
    break
  fi
  sleep 2
done
"${DOCKER[@]}" compose --project-name "$REVIEW_PROJECT" ps --all > "$REVIEW_OUTPUT_DIR/compose-ps.txt"
if [ "$ready" -ne 1 ]; then
  "${DOCKER[@]}" compose --project-name "$REVIEW_PROJECT" logs --no-color > "$REVIEW_OUTPUT_DIR/compose.log" 2>&1
  echo "Clean installation did not become ready; inspect $REVIEW_OUTPUT_DIR" >&2
  exit 1
fi

curl -fsS "http://127.0.0.1:${REVIEW_PORT}/health" > "$REVIEW_OUTPUT_DIR/health.json"
curl -fsS "http://127.0.0.1:${REVIEW_PORT}/api/public/incidents?days=30&page_size=5" > "$REVIEW_OUTPUT_DIR/incidents.json"
curl -fsS "http://127.0.0.1:${REVIEW_PORT}/api/public/topology?days=30&page_size=20" > "$REVIEW_OUTPUT_DIR/topology.json"
"${DOCKER[@]}" compose --project-name "$REVIEW_PROJECT" exec -T worker python -m app.cli benchmark > "$REVIEW_OUTPUT_DIR/benchmark.json"
"${DOCKER[@]}" compose --project-name "$REVIEW_PROJECT" logs --no-color > "$REVIEW_OUTPUT_DIR/compose.log" 2>&1

python3 - "$REVIEW_OUTPUT_DIR" "$REVIEW_REF" <<'PY'
import json
import pathlib
import sys

output = pathlib.Path(sys.argv[1])
benchmark = json.loads((output / "benchmark.json").read_text())
summary = {
    "review_ref": sys.argv[2],
    "clean_install_ready": True,
    "benchmark_passed": benchmark["passed"],
    "benchmark_scenarios": benchmark["scenario_count"],
    "secret_material_in_bundle": False,
    "review_status": "automation completed; human evidence-semantic review still required",
}
(output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
PY

echo "Review evidence written to: $REVIEW_OUTPUT_DIR"
