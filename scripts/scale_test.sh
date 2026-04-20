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
#   - siphon.yaml with bob/secret in auth.users
#
# The release binary is rebuilt automatically (cargo is a no-op if fresh)
# to avoid running stale code against a modified tree.

set -euo pipefail

TOTAL=${1:-10000}
CPS=${2:-1000}
NUM_UACS=${3:-1}

CALLS_PER_UAC=$((TOTAL / NUM_UACS))
CPS_PER_UAC=$((CPS / NUM_UACS))
PROXY="127.0.0.1:5060"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ "$NUM_UACS" -gt 16 ]; then
    echo "FAIL: NUM_UACS > 16 not supported (siphon.yaml registers bob1..bob16)"
    exit 1
fi

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

# --- Build siphon release binary (no-op if already fresh) ---
echo "[*] Building siphon (release)..."
if ! PYO3_PYTHON=python3 cargo build --release --quiet > /tmp/siphon_scale_build.log 2>&1; then
    echo "FAIL: cargo build failed"
    tail -40 /tmp/siphon_scale_build.log
    exit 1
fi
echo "[+] build ok"

# --- Pick config: MODE=proxy (default) or MODE=b2bua ---
# B2BUA mode rewrites the Python script path in a temp config copy so the
# proxy_default.py routing logic is replaced by b2bua_default.py.
MODE="${MODE:-proxy}"
case "$MODE" in
    proxy)
        CONFIG_FILE="siphon.yaml"
        echo "[*] Mode: proxy"
        ;;
    b2bua)
        CONFIG_FILE="/tmp/siphon_scale_b2bua.yaml"
        sed 's|scripts/proxy_default.py|scripts/b2bua_default.py|' siphon.yaml > "$CONFIG_FILE"
        echo "[*] Mode: b2bua  (config: $CONFIG_FILE)"
        ;;
    *)
        echo "FAIL: unknown MODE='$MODE' (use 'proxy' or 'b2bua')"
        exit 1
        ;;
esac

# --- Start SIPhon ---
cleanup
sleep 1

RUST_LOG="${RUST_LOG:-warn}" PYO3_PYTHON=python3 ./target/release/siphon -c "$CONFIG_FILE" > /tmp/siphon_scale_proxy.log 2>&1 &
SIPHON_PID=$!
sleep 2

if ! kill -0 $SIPHON_PID 2>/dev/null; then
    echo "FAIL: siphon did not start"
    cat /tmp/siphon_scale_proxy.log
    exit 1
fi
echo "[+] siphon started (PID $SIPHON_PID)"

# --- Register one bob{i} per UAS so the proxy load fans out across N UASes ---
# Each UAS binds to a distinct loopback IP (127.0.0.{1+i}) on port 5060.
# Without distinct IPs, sipp's [local_ip] resolves to the host's hostname
# address (often 127.0.1.1 on Debian/Ubuntu), which differs from where the
# proxy receives — leading to weird Contact-header routing inconsistencies
# and lost in-dialog requests.
UAS_PORT=5061
UAC_PORT=5062
echo "[*] Registering bob1..bob${NUM_UACS} (one UAS per UAC, distinct IPs)..."
REG_FAILED=0
for i in $(seq 1 "$NUM_UACS"); do
    ip="127.0.0.$((1 + i))"
    user="bob${i}"
    log="/tmp/siphon_scale_register_${i}.log"
    sipp -sf sipp/register.xml "$PROXY" -m 1 -i "$ip" -p "$UAS_PORT" \
        -s "$user" -au "$user" -ap secret > "$log" 2>&1 || true
    if ! grep -q "Successful call.*1" "$log"; then
        echo "FAIL: registration of $user from $ip failed"
        cat "$log"
        REG_FAILED=1
    fi
done
[ "$REG_FAILED" -eq 0 ] || exit 1
echo "[+] $NUM_UACS bobs registered (127.0.0.2..127.0.0.$((1 + NUM_UACS)))"

# --- Start one UAS per UAC, each on its own loopback IP ---
for i in $(seq 1 "$NUM_UACS"); do
    ip="127.0.0.$((1 + i))"
    sipp -sf sipp/invite_uas_fast.xml -i "$ip" -p "$UAS_PORT" -bg > /dev/null 2>&1 || true
done
sleep 1
echo "[+] $NUM_UACS UAS processes started"

# --- Launch UACs ---
# Each UAC also binds to a distinct loopback IP so its [local_ip] in
# Via/Contact is unambiguous. UACs use 127.0.0.{50+i}.
# -fd 1 = 1-second snapshot resolution so we can see peak rate, not avg.
echo ""
echo "--- Running $TOTAL calls at $CPS cps target ---"
START_NS=$(date +%s%N)

for i in $(seq 1 "$NUM_UACS"); do
    ip="127.0.0.$((50 + i))"
    user="bob${i}"
    sipp -sf sipp/invite_uac_fast.xml "$PROXY" \
        -m "$CALLS_PER_UAC" -r "$CPS_PER_UAC" \
        -i "$ip" -p "$UAC_PORT" -s "$user" \
        -trace_stat -stf "/tmp/sipp_uac_${i}.csv" -fd 1 \
        -trace_msg -message_file "/tmp/sipp_uac_${i}.msg.log" \
        -bg > /dev/null 2>&1 || true
done

echo "[+] $NUM_UACS UAC(s) launched, waiting..."

# --- Sample siphon CPU% during the run via pidstat ---
# pidstat -u  -h  -p PID 1 → 1-second samples; we keep the *peak* sample value
# as "Peak CPU%" (the max instantaneous CPU consumption observed during the
# test). 100% = one fully-saturated logical core.
PIDSTAT_LOG="/tmp/siphon_scale_pidstat.log"
> "$PIDSTAT_LOG"
pidstat -u -h -p "$SIPHON_PID" 1 > "$PIDSTAT_LOG" 2>/dev/null &
PIDSTAT_PID=$!

# Poll until all UAC processes finish
while pgrep -f "invite_uac_fast.xml" > /dev/null 2>&1; do
    sleep 1
done

kill "$PIDSTAT_PID" 2>/dev/null || true
wait "$PIDSTAT_PID" 2>/dev/null || true

END_NS=$(date +%s%N)
ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))

# pidstat -h output: header lines start with '#'; data lines have a numeric
# %CPU column. Column layout: # Time UID PID %usr %system %guest %wait %CPU CPU Command
PEAK_CPU=$(awk '/^[ \t]*[0-9]/ {if ($8+0 > p) p=$8+0} END {printf "%.0f", p+0}' "$PIDSTAT_LOG")

# --- Collect results from SIPp stat files ---
# Column reference (sipp -h stat):
#   5  ElapsedTime(C)
#   8  CallRate(C)        — cumulative average call rate
#  16  SuccessfulCall(C)
#  18  FailedCall(C)
#  58  Retransmissions(C)
#  70  ResponseTime1(C)   — INVITE→200 OK ms (mean)
echo ""
echo "--- Results ---"

TOTAL_SUCCESS=0
TOTAL_FAILED=0
TOTAL_RETRANS=0
PEAK_CPS=0
RT_SUM=0
RT_COUNT=0

for i in $(seq 1 "$NUM_UACS"); do
    csv="/tmp/sipp_uac_${i}.csv"
    if [ -f "$csv" ]; then
        last=$(tail -1 "$csv")
        s=$(echo "$last" | awk -F';' '{print $16+0}')
        f=$(echo "$last" | awk -F';' '{print $18+0}')
        rt=$(echo "$last" | awk -F';' '{print $70+0}')
        retrans=$(echo "$last" | awk -F';' '{print $58+0}')
        # Peak periodic CallRate(P) = column 7
        peak=$(awk -F';' 'NR>1 {if ($7+0 > p) p=$7+0} END {print p+0}' "$csv")
        TOTAL_SUCCESS=$((TOTAL_SUCCESS + s))
        TOTAL_FAILED=$((TOTAL_FAILED + f))
        TOTAL_RETRANS=$((TOTAL_RETRANS + retrans))
        if [ "$peak" -gt "$PEAK_CPS" ]; then PEAK_CPS=$peak; fi
        RT_SUM=$(awk "BEGIN {print $RT_SUM + $rt}")
        RT_COUNT=$((RT_COUNT + 1))
        printf "  UAC %d: success=%d failed=%d peak=%d cps  invite_rt=%dms  retrans=%d\n" \
            "$i" "$s" "$f" "$peak" "$rt" "$retrans"
        # Keep CSV for post-mortem analysis
        mv "$csv" "/tmp/sipp_uac_${i}.last.csv"
    else
        echo "  UAC $i: no stats file"
    fi
done

# Aggregate peak across all UACs (sum, since they ran in parallel)
AGG_PEAK_CPS=$(awk "BEGIN {printf \"%d\", $PEAK_CPS * $NUM_UACS}")
# Mean response time across UACs
MEAN_RT=0
if [ "$RT_COUNT" -gt 0 ]; then
    MEAN_RT=$(awk "BEGIN {printf \"%.0f\", $RT_SUM / $RT_COUNT}")
fi
# Wall-clock throughput including ramp+drain (apples-to-apples for sustained load)
WALL_CPS=0
if [ "$ELAPSED_MS" -gt 0 ]; then
    WALL_CPS=$(( (TOTAL_SUCCESS + TOTAL_FAILED) * 1000 / ELAPSED_MS ))
fi

# Check siphon errors
SIPHON_ERRORS=$(grep -aci "error" /tmp/siphon_scale_proxy.log 2>/dev/null || echo 0)

echo ""
echo "  Successful:        $TOTAL_SUCCESS / $TOTAL"
echo "  Failed:            $TOTAL_FAILED"
echo "  Retransmissions:   $TOTAL_RETRANS"
echo "  Wall elapsed:      ${ELAPSED_MS}ms"
echo "  Peak CPS (1s):     ~${AGG_PEAK_CPS}  (per-UAC peak: ${PEAK_CPS})"
echo "  Wall avg CPS:      ~${WALL_CPS}  (includes ramp+drain)"
echo "  Mean INVITE→200:   ${MEAN_RT}ms"
echo "  Peak siphon CPU:   ${PEAK_CPU}%  (100% = 1 logical core)"
echo "  Proxy errors:      $SIPHON_ERRORS"

echo ""
if [ "$TOTAL_FAILED" -eq 0 ] && [ "$TOTAL_SUCCESS" -ge "$TOTAL" ]; then
    echo "=== PASS: $TOTAL_SUCCESS/$TOTAL  peak ${AGG_PEAK_CPS} cps  cpu ${PEAK_CPU}%  rt ${MEAN_RT}ms ==="
    exit 0
else
    echo "=== RESULT: $TOTAL_SUCCESS/$TOTAL ($TOTAL_FAILED failed)  peak ${AGG_PEAK_CPS} cps  cpu ${PEAK_CPU}%  rt ${MEAN_RT}ms ==="
    [ "$TOTAL_FAILED" -eq 0 ] && exit 0 || exit 1
fi
