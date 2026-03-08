#!/usr/bin/env bash
#
# SIPhon INVITE scale test
#
# Usage:
#   ./scripts/scale_test.sh [total_calls] [cps] [num_uacs]
#
# Examples:
#   ./scripts/scale_test.sh 10000 1000 1     # 10k calls, 1k cps, 1 SIPp
#   ./scripts/scale_test.sh 100000 20000 4   # 100k calls, 20k cps, 4 SIPps
#
# Prerequisites:
#   - sipp installed
#   - cargo build --release done
#   - siphon.yaml with bob/secret in auth.users

set -euo pipefail

TOTAL=${1:-10000}
CPS=${2:-1000}
NUM_UACS=${3:-1}

CALLS_PER_UAC=$((TOTAL / NUM_UACS))
CPS_PER_UAC=$((CPS / NUM_UACS))
PROXY="127.0.0.1:5060"
UAS_PORT=5090
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

cd "$SCRIPT_DIR"

cleanup() {
    pkill -f "invite_uac" 2>/dev/null || true
    pkill -f "invite_uas" 2>/dev/null || true
    pkill -f "target/release/siphon" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== SIPhon Scale Test ==="
echo "  Total calls:  $TOTAL"
echo "  Target rate:  $CPS cps"
echo "  UAC instances: $NUM_UACS ($CALLS_PER_UAC calls @ $CPS_PER_UAC cps each)"
echo ""

# --- Start SIPhon ---
cleanup
sleep 1

RUST_LOG=warn PYO3_PYTHON=python3 ./target/release/siphon > /tmp/siphon_scale_proxy.log 2>&1 &
SIPHON_PID=$!
sleep 2

if ! kill -0 $SIPHON_PID 2>/dev/null; then
    echo "FAIL: siphon did not start"
    cat /tmp/siphon_scale_proxy.log
    exit 1
fi
echo "[+] siphon started (PID $SIPHON_PID)"

# --- Register bob ---
sipp -sf sipp/register.xml "$PROXY" -m 1 -p $UAS_PORT -s bob -au bob -ap secret \
    > /tmp/siphon_scale_register.log 2>&1 || true

if grep -q "Successful call.*1" /tmp/siphon_scale_register.log; then
    echo "[+] bob registered"
else
    echo "FAIL: registration failed"
    cat /tmp/siphon_scale_register.log
    exit 1
fi

# --- Start UAS ---
sipp -sf sipp/invite_uas_fast.xml -p $UAS_PORT -bg > /dev/null 2>&1 || true
sleep 1
echo "[+] UAS started on port $UAS_PORT"

# --- Launch UACs ---
echo ""
echo "--- Running $TOTAL calls at $CPS cps ---"
START_NS=$(date +%s%N)

for i in $(seq 1 "$NUM_UACS"); do
    port=$((5080 + i))
    sipp -sf sipp/invite_uac.xml "$PROXY" \
        -m "$CALLS_PER_UAC" -r "$CPS_PER_UAC" \
        -p "$port" -s bob \
        -trace_stat -stf "/tmp/sipp_uac_${i}.csv" \
        -bg > /dev/null 2>&1 || true
done

echo "[+] $NUM_UACS UAC(s) launched, waiting..."

# Poll until all UAC processes finish
while pgrep -f "invite_uac.xml" > /dev/null 2>&1; do
    sleep 1
done

END_NS=$(date +%s%N)
ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))

# --- Collect results from SIPp stat files ---
echo ""
echo "--- Results ---"

TOTAL_SUCCESS=0
TOTAL_FAILED=0

for i in $(seq 1 "$NUM_UACS"); do
    csv="/tmp/sipp_uac_${i}.csv"
    if [ -f "$csv" ]; then
        # Last data line has cumulative (C) stats
        # Field 16 = SuccessfulCall(C), field 18 = FailedCall(C)
        last_line=$(tail -1 "$csv" 2>/dev/null)
        s=$(echo "$last_line" | awk -F';' '{print $16}' 2>/dev/null || echo 0)
        f=$(echo "$last_line" | awk -F';' '{print $18}' 2>/dev/null || echo 0)
        TOTAL_SUCCESS=$((TOTAL_SUCCESS + ${s:-0}))
        TOTAL_FAILED=$((TOTAL_FAILED + ${f:-0}))
        echo "  UAC $i: success=$s failed=$f"
        rm -f "$csv"
    else
        echo "  UAC $i: no stats file"
    fi
done

ACTUAL_CPS=0
if [ "$ELAPSED_MS" -gt 0 ]; then
    ACTUAL_CPS=$(( (TOTAL_SUCCESS + TOTAL_FAILED) * 1000 / ELAPSED_MS ))
fi

# Check siphon errors
SIPHON_ERRORS=$(grep -aci "error" /tmp/siphon_scale_proxy.log 2>/dev/null || echo 0)

echo ""
echo "  Total successful: $TOTAL_SUCCESS"
echo "  Total failed:     $TOTAL_FAILED"
echo "  Elapsed:          ${ELAPSED_MS}ms"
echo "  Actual rate:      ~${ACTUAL_CPS} cps"
echo "  Proxy errors:     $SIPHON_ERRORS"

echo ""
if [ "$TOTAL_FAILED" -eq 0 ] && [ "$TOTAL_SUCCESS" -ge "$TOTAL" ]; then
    echo "=== PASS: $TOTAL_SUCCESS/$TOTAL calls at ~${ACTUAL_CPS} cps ==="
    exit 0
else
    echo "=== RESULT: $TOTAL_SUCCESS/$TOTAL calls ($TOTAL_FAILED failed) at ~${ACTUAL_CPS} cps ==="
    [ "$TOTAL_FAILED" -eq 0 ] && exit 0 || exit 1
fi
