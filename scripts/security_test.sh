#!/usr/bin/env bash
# security_test.sh — rate_limit + scanner_block functional regression (real instance).
#
# Proves the end-to-end glue for the request security filter:
#   * an inbound request whose User-Agent matches security.scanner_block is
#     silently dropped in the dispatcher (no response), while a normal UA is
#     answered;
#   * once a source exceeds security.rate_limit.max_requests it is banned and
#     every further request from it is dropped.
# A build that fails to wire either filter answers the blocked requests -> the
# client exits 1 -> this script FAILS.
#
# Requires: docker, python3. Usage: scripts/security_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="siphon:security-test"
CONTAINER="siphon-security-test"
DIR="$REPO_ROOT/sipp/security"

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "=== build siphon image ==="
docker build -t "$IMAGE" "$REPO_ROOT" >/dev/null

echo "=== start siphon (host net; rate_limit max=5, scanner_block on) ==="
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" --network host \
  -v "$DIR/siphon-security.yaml:/etc/siphon/siphon.yaml:ro" \
  -v "$DIR:/etc/siphon/test_scripts:ro" \
  "$IMAGE" >/dev/null
sleep 4
echo "siphon status: $(docker ps --filter "name=$CONTAINER" --format '{{.Status}}')"

echo "=== run security client (scanner block + rate limit) ==="
if python3 "$DIR/security_client.py"; then
  echo "PASS: scanner UA dropped + source rate-limited as configured"
  exit 0
else
  rc=$?
  echo "FAIL ($rc): security filter did not drop scanner/rate-limited requests"
  echo "--- siphon log tail ---"
  docker logs "$CONTAINER" 2>&1 | tail -10
  exit 1
fi
