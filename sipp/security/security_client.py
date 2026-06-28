"""rate_limit + scanner_block functional regression client.

Runs against a siphon container (scripts/security_test.sh) configured with:
    security.rate_limit:    window 60s / max_requests 5 / ban 60s
    security.scanner_block: sipvicious, friendly-scanner, sipcli

A request that the security filter drops is silently discarded by the
dispatcher BEFORE it reaches the script (no response at all — that is the
deliberate no-fingerprinting policy). A request that passes reaches the
handler, which answers 200 OK. So "did a 200 come back?" is the signal.

The two phases use DISTINCT loopback source IPs (127.0.0.x all route to `lo`)
so their per-source rate-limit state never cross-contaminates:

  Phase A — scanner_block (src 127.0.0.10):
    * OPTIONS with User-Agent "friendly-scanner" -> silently dropped (no 200)
    * OPTIONS with a normal User-Agent           -> 200 OK
  Phase B — rate_limit (src 127.0.0.20):
    * a burst of OPTIONS -> exactly max_requests (5) answered, the rest dropped

exit 0 = all checks pass, 1 = a regression, 2 = setup error.
"""
import socket
import sys
import time

DST = ("127.0.0.1", 5060)
# Keep in sync with sipp/security/siphon-security.yaml.
MAX_REQUESTS = 5

# Distinct loopback source IPs (+ fixed ports echoed in the Via sent-by so the
# UDP response routes straight back to our bound socket regardless of whether
# siphon replies to received-addr or Via sent-by).
SCANNER_SRC = ("127.0.0.10", 6010)
RATELIMIT_SRC = ("127.0.0.20", 6020)


def options(src, user_agent, index):
    host, port = src
    return (
        f"OPTIONS sip:ping@127.0.0.1 SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {host}:{port};branch=z9hG4bK-sec-{index}\r\n"
        f"From: <sip:probe@{host}>;tag=sec{index}\r\n"
        f"To: <sip:ping@127.0.0.1>\r\n"
        f"Call-ID: sec-{index}@{host}\r\n"
        f"CSeq: {index} OPTIONS\r\n"
        f"Max-Forwards: 70\r\n"
        f"User-Agent: {user_agent}\r\n"
        f"Content-Length: 0\r\n\r\n"
    ).encode()


def make_socket(src):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(src)
    sock.settimeout(2.0)
    return sock


def send_and_wait(sock, src, user_agent, index):
    """Send one OPTIONS; return True if a 200 came back, False on silence."""
    sock.sendto(options(src, user_agent, index), DST)
    try:
        data = sock.recv(4096)
    except socket.timeout:
        return False
    return data.startswith(b"SIP/2.0 200")


# ── Phase A — scanner_block ──────────────────────────────────────────────────
scanner_sock = make_socket(SCANNER_SRC)

blocked = send_and_wait(scanner_sock, SCANNER_SRC, "friendly-scanner", 1)
if blocked:  # got a 200 -> NOT blocked
    print("phase A: scanner User-Agent got a 200 (NOT blocked) -> FAIL", flush=True)
    sys.exit(1)
print("phase A: scanner User-Agent silently dropped -> ok", flush=True)

baseline = send_and_wait(scanner_sock, SCANNER_SRC, "Acme-SIP/1.0", 2)
scanner_sock.close()
if not baseline:
    print(
        "phase A: a normal User-Agent got no 200 either — siphon/handler not up "
        "(setup error)",
        flush=True,
    )
    sys.exit(2)
print("phase A: normal User-Agent answered 200 -> PASS", flush=True)

# ── Phase B — rate_limit ─────────────────────────────────────────────────────
rate_sock = make_socket(RATELIMIT_SRC)

allowed = 0
dropped_after_allowed = 0
for index in range(1, MAX_REQUESTS + 4):  # a few past the limit
    if send_and_wait(rate_sock, RATELIMIT_SRC, "Acme-SIP/1.0", index):
        allowed += 1
    elif allowed > 0:
        dropped_after_allowed += 1
    time.sleep(0.05)
rate_sock.close()

print(
    f"phase B: {allowed} answered, {dropped_after_allowed} dropped after the "
    f"limit (max_requests={MAX_REQUESTS})",
    flush=True,
)

if allowed == 0:
    print("phase B: nothing answered — siphon/handler not up (setup error)", flush=True)
    sys.exit(2)
if allowed != MAX_REQUESTS or dropped_after_allowed == 0:
    print(
        f"phase B: expected exactly {MAX_REQUESTS} answered then drops -> FAIL",
        flush=True,
    )
    sys.exit(1)
print("phase B: rate limit banned the source after max_requests -> PASS", flush=True)

print("ALL PHASES PASS", flush=True)
sys.exit(0)
