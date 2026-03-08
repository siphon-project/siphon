#!/usr/bin/env python3
"""Mock RTPEngine NG protocol server for functional testing.

Listens on UDP port 22222 (default NG protocol port) and responds to
offer/answer/delete/ping/query commands with bencode-encoded responses.

For offer/answer: rewrites the SDP c-line to MOCK_MEDIA_IP and the
m-line port to MOCK_MEDIA_PORT, simulating media anchoring.
"""

import os
import re
import socket
import sys

LISTEN_PORT = int(os.environ.get("RTPENGINE_PORT", "22222"))
MOCK_MEDIA_IP = os.environ.get("MOCK_MEDIA_IP", "203.0.113.1")
MOCK_MEDIA_PORT = os.environ.get("MOCK_MEDIA_PORT", "30000")


# ---------------------------------------------------------------------------
# Minimal bencode encoder/decoder
# ---------------------------------------------------------------------------

def bencode_encode(value):
    """Encode a Python value to bencode bytes."""
    if isinstance(value, int):
        return f"i{value}e".encode()
    if isinstance(value, bytes):
        return f"{len(value)}:".encode() + value
    if isinstance(value, str):
        encoded = value.encode()
        return f"{len(encoded)}:".encode() + encoded
    if isinstance(value, list):
        return b"l" + b"".join(bencode_encode(item) for item in value) + b"e"
    if isinstance(value, dict):
        parts = b"d"
        for key in sorted(value.keys()):
            parts += bencode_encode(key) + bencode_encode(value[key])
        parts += b"e"
        return parts
    raise TypeError(f"Cannot bencode {type(value)}")


def bencode_decode(data, index=0):
    """Decode bencode data starting at index. Returns (value, next_index)."""
    if data[index:index + 1] == b"i":
        end = data.index(b"e", index)
        return int(data[index + 1:end]), end + 1
    if data[index:index + 1] == b"l":
        result = []
        index += 1
        while data[index:index + 1] != b"e":
            value, index = bencode_decode(data, index)
            result.append(value)
        return result, index + 1
    if data[index:index + 1] == b"d":
        result = {}
        index += 1
        while data[index:index + 1] != b"e":
            key, index = bencode_decode(data, index)
            val, index = bencode_decode(data, index)
            if isinstance(key, bytes):
                key = key.decode(errors="replace")
            result[key] = val
        return result, index + 1
    # String: <length>:<data>
    colon = data.index(b":", index)
    length = int(data[index:colon])
    start = colon + 1
    return data[start:start + length], start + length


def bencode_decode_full(data):
    """Decode a full bencode value from data."""
    value, _ = bencode_decode(data, 0)
    return value


# ---------------------------------------------------------------------------
# SDP rewriting
# ---------------------------------------------------------------------------

def rewrite_sdp(sdp_bytes):
    """Rewrite SDP c-line IP and m-line port to mock values."""
    sdp = sdp_bytes.decode(errors="replace") if isinstance(sdp_bytes, bytes) else sdp_bytes

    # Replace c= line IP
    sdp = re.sub(
        r"(c=IN IP[46] )\S+",
        rf"\g<1>{MOCK_MEDIA_IP}",
        sdp,
    )
    # Replace m= line port
    sdp = re.sub(
        r"(m=audio )\d+",
        rf"\g<1>{MOCK_MEDIA_PORT}",
        sdp,
    )
    # Replace o= line IP
    sdp = re.sub(
        r"(o=\S+ \d+ \d+ IN IP[46] )\S+",
        rf"\g<1>{MOCK_MEDIA_IP}",
        sdp,
    )
    return sdp


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def handle_command(command):
    """Process an NG protocol command dict and return a response dict."""
    cmd = command.get("command", b"unknown")
    if isinstance(cmd, bytes):
        cmd = cmd.decode(errors="replace")

    if cmd == "ping":
        return {"result": "pong"}

    if cmd in ("offer", "answer"):
        sdp = command.get("sdp", b"")
        rewritten = rewrite_sdp(sdp)
        print(f"  {cmd}: rewritten SDP ({len(rewritten)} bytes)", flush=True)
        return {"result": "ok", "sdp": rewritten}

    if cmd == "delete":
        call_id = command.get("call-id", b"?")
        if isinstance(call_id, bytes):
            call_id = call_id.decode(errors="replace")
        print(f"  delete: call-id={call_id}", flush=True)
        return {"result": "ok"}

    if cmd == "query":
        return {
            "result": "ok",
            "totals": {
                "RTP": {"packets": 1000, "bytes": 160000},
            },
        }

    return {"result": "error", "error-reason": f"unknown command: {cmd}"}


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", LISTEN_PORT))
    print(f"Mock RTPEngine listening on UDP port {LISTEN_PORT}", flush=True)
    print(f"  Media IP: {MOCK_MEDIA_IP}, Media port: {MOCK_MEDIA_PORT}", flush=True)

    while True:
        data, address = sock.recvfrom(65535)
        try:
            # NG protocol: "<cookie> <bencode-dict>"
            space_index = data.index(b" ")
            cookie = data[:space_index]
            payload = data[space_index + 1:]

            command = bencode_decode_full(payload)
            cmd_name = command.get("command", b"?")
            if isinstance(cmd_name, bytes):
                cmd_name = cmd_name.decode(errors="replace")
            print(f"[{address[0]}:{address[1]}] {cmd_name}", flush=True)

            response = handle_command(command)
            encoded = bencode_encode(response)

            reply = cookie + b" " + encoded
            sock.sendto(reply, address)

        except Exception as error:
            print(f"Error processing request from {address}: {error}", flush=True)
            # Try to send an error response
            try:
                error_response = bencode_encode(
                    {"result": "error", "error-reason": str(error)}
                )
                sock.sendto(cookie + b" " + error_response, address)
            except Exception:
                pass


if __name__ == "__main__":
    main()
