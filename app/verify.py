"""One-shot acceptance service for the CFDP Class 2 auditor.

Execution order (the whole run reports a single process exit code):

1. Build check: byte-compile every package module and import the service.
2. Start the audit service (or wait for one given by CFDP_AUDIT_BASE_URL, as
   the compose ``verify`` service does) and poll ``/health``.
3. HTTP smoke test: submit a complete closed-loop capture over HTTP and
   assert closure, full coverage, matching CRC32C and both sides' phase
   evidence; then prove freeze semantics (identical resubmission returns the
   frozen verdict, altered capture returns a conflict).
4. Code tests for the two mandated recovery/failure paths:
   * missing middle segment -> exact NAK interval -> retransmission closes;
   * conflicting retransmission -> conflict verdict naming the first
     offending PDU and the stage.

Exit code 0 means the acceptance passed, non-zero means it failed.

Configuration:

CFDP_AUDIT_BASE_URL  use an already running service (compose mode)
CFDP_AUDIT_HOST      bind host when spawning in-process (default 127.0.0.1)
CFDP_AUDIT_PORT      service port (default 8080)
"""

from __future__ import annotations

import base64
import compileall
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import cfdp  # noqa: E402
from app.audit import audit_capture  # noqa: E402
from tests import captures as cap  # noqa: E402

PAYLOAD = bytes((i * 61 + 17) % 256 for i in range(4096))
GAP = (1500, 1560)  # exact missing middle segment


class AcceptanceFailure(AssertionError):
    pass


def check(name: bool, message: str) -> None:
    if not name:
        raise AcceptanceFailure(message)
    print(f"  PASS  {message}")


# ---------------------------------------------------------------------------
# Step 1: build check
# ---------------------------------------------------------------------------

def build_check() -> None:
    print("[1/4] build check")
    ok = compileall.compile_dir(str(ROOT / "app"), quiet=1, maxlevels=10)
    check(ok, "all application modules byte-compile")
    # Import-time wiring check for the HTTP entry point.
    from app.server import build_server  # noqa: F401
    check(cfdp.crc32c(b"123456789") == 0xE3069283,
          "CRC32C implementation matches the Castagnoli check vector")


# ---------------------------------------------------------------------------
# Step 2: service lifecycle
# ---------------------------------------------------------------------------

class InProcessServer:
    def __init__(self) -> None:
        from app.server import build_server
        host = os.environ.get("CFDP_AUDIT_HOST", "127.0.0.1")
        port = int(os.environ.get("CFDP_AUDIT_PORT", "8080"))
        self.server = build_server(host=host, port=port)
        self.base_url = (
            f"http://{host}:{self.server.server_address[1]}"
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )

    def __enter__(self):
        self.thread.start()
        print(f"[2/4] started in-process audit service at {self.base_url}")
        return self.base_url

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def wait_for_health(base_url: str, attempts: int = 60) -> None:
    last_error = None
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(
                f"{base_url}/health", timeout=2
            ) as resp:
                body = json.loads(resp.read())
                if resp.status == 200 and body.get("status") == "ok":
                    print(f"  PASS  {base_url}/health is healthy")
                    return
        except (urllib.error.URLError, ConnectionError, OSError) as exc:
            last_error = exc
        time.sleep(0.5)
    raise AcceptanceFailure(f"service never became healthy: {last_error}")


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def http_json(method: str, url: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def encode(items):
    return [
        {"direction": d, "pdu_base64": base64.b64encode(raw).decode("ascii")}
        for d, raw in items
    ]


# ---------------------------------------------------------------------------
# Step 3: HTTP smoke - complete closed loop + freeze semantics
# ---------------------------------------------------------------------------

def http_smoke(base_url: str) -> None:
    print("[3/4] HTTP smoke: complete closed-loop submission")
    capture = cap.closed_loop_capture(PAYLOAD, chunk_size=1024)
    audit_id = "acceptance-closed-0001"

    status, body = http_json(
        "POST", f"{base_url}/audit",
        {"audit_id": audit_id, "pdus": encode(capture)},
    )
    check(status == 200, f"POST /audit accepted the capture (HTTP {status})")
    report = body["report"]
    check(report["verdict"] == "closed",
          f"verdict is closed (got {report['verdict']!r})")
    check(report["coverage"] == [[0, len(PAYLOAD)]],
          "frozen coverage is the full [0,4096) interval")
    check(report["uncovered"] == [], "no uncovered interval remains")
    check(report["checksum_match"] is True
          and report["crc32c"] == report["eof_checksum"],
          "frozen CRC32C matches the EOF checksum")
    evidence = report["stages"]["evidence"]
    sender_phases = {e["sender_phase"] for e in evidence}
    receiver_phases = {e["receiver_phase"] for e in evidence}
    check("eof_sent" in sender_phases and "eof_received" in receiver_phases,
          "sender/receiver EOF phase evidence present")
    check("ack_finished_sent" in sender_phases
          and "finished_acked" in receiver_phases,
          "sender/receiver terminal Finished-handshake evidence present")
    check(report["stages"]["closed_loop"] is True,
          "stage evidence reports the loop closed")

    status, frozen = http_json("GET", f"{base_url}/audit/{audit_id}")
    check(status == 200 and frozen["report"] == report,
          "GET returns the identical frozen verdict")

    status, again = http_json(
        "POST", f"{base_url}/audit",
        {"audit_id": audit_id, "pdus": encode(capture)},
    )
    check(status == 200 and again["replayed"] is False
          and again["report"] == report,
          "identical resubmission returns the original frozen verdict")

    altered = list(capture[:-3])  # drop Finished + its ACK (+ ACK EOF? keep)
    status, conflict = http_json(
        "POST", f"{base_url}/audit",
        {"audit_id": audit_id, "pdus": encode(altered)},
    )
    check(status == 409 and conflict["error"] == "frozen_conflict",
          "a changed capture under the same id returns frozen_conflict")


# ---------------------------------------------------------------------------
# Step 4: code tests - missing-segment repair and conflicting retransmission
# ---------------------------------------------------------------------------

def code_test_missing_segment_repair() -> None:
    print("[4/4] code test: missing middle segment -> NAK -> repair -> closed")
    items, gap = cap.capture_with_gap(PAYLOAD, [GAP])
    report = audit_capture(items)
    check(report["verdict"] == "incomplete",
          "partial capture freezes as incomplete, not closed")
    expected = report["expected_nak"]["requests"]
    check(expected == [list(GAP)],
          f"uncovered interval localised precisely to [{GAP[0]},{GAP[1]})")
    check(report["coverage"] == [[0, GAP[0]], [GAP[1], len(PAYLOAD)]],
          "covered ranges flank the missing segment exactly")

    # The receiver must NAK exactly the uncovered interval after EOF.
    repaired = items + cap.recovery_tail(PAYLOAD, gap)
    fixed = audit_capture(repaired)
    check(fixed["verdict"] == "closed",
          "exact NAK plus retransmission closes the transaction")
    check(fixed["coverage"] == [[0, len(PAYLOAD)]]
          and fixed["checksum_match"] is True,
          "post-repair coverage is complete and CRC32C matches")

    # A NAK asking for the wrong span is itself a violation.
    bad = items + [
        ("to_sender", cfdp.ack(0x2222, 0x1111, 1, cfdp.CODE_EOF, 0)),
        ("to_sender", cfdp.nak(0x2222, 0x1111, 1, 0, len(PAYLOAD),
                               [(GAP[0], GAP[1] + 10)])),
    ]
    bad_report = audit_capture(bad)
    check(bad_report["verdict"] == "conflict"
          and bad_report["first_violation"]["code"] == "bad_nak",
          "an inexact post-EOF NAK is the first named violation")


def code_test_conflicting_retransmission() -> None:
    print("[4/4] code test: conflicting retransmission revokes success")
    size = len(PAYLOAD)
    good = cap.closed_loop_capture(PAYLOAD, chunk_size=2048)
    check(audit_capture(good)["verdict"] == "closed",
          "baseline identical-overlap retransmission closes")

    corrupt = bytearray(PAYLOAD[GAP[0]:GAP[1]])
    corrupt[3] ^= 0xA5
    conflicting = [
        ("to_receiver", cfdp.metadata(0x1111, 0x2222, 1, size)),
        ("to_receiver", cfdp.file_data(0x1111, 0x2222, 1, 0,
                                       PAYLOAD[: GAP[0] + 10])),
        ("to_receiver", cfdp.file_data(0x1111, 0x2222, 1, GAP[0],
                                       bytes(corrupt))),
        ("to_receiver", cfdp.eof(0x1111, 0x2222, 1,
                                 cfdp.crc32c(PAYLOAD), size)),
    ]
    report = audit_capture(conflicting)
    v = report["first_violation"]
    check(report["verdict"] == "conflict",
          "verdict is conflict, never closed")
    check(v is not None and v["code"] == "conflicting_retransmission"
          and v["pdu"] == "FileData" and v["index"] == 2,
          "first offending PDU is the retransmitted FileData at index 2")
    check(v["stage"] == "transfer",
          f"violation records the stage at the time ({v['stage']})")
    check(f"offset {GAP[0] + 3}" in v["reason"],
          "the first disagreeing byte offset is named")


def main() -> int:
    print("CFDP Class 2 audit acceptance (one-shot verify)")
    base_url_env = os.environ.get("CFDP_AUDIT_BASE_URL")
    try:
        build_check()
        if base_url_env:
            print(f"[2/4] using orchestrated service at {base_url_env}")
            wait_for_health(base_url_env)
            http_smoke(base_url_env)
        else:
            with InProcessServer() as base_url:
                wait_for_health(base_url)
                http_smoke(base_url)
        code_test_missing_segment_repair()
        code_test_conflicting_retransmission()
    except AcceptanceFailure as exc:
        print(f"  FAIL  {exc}")
        print("ACCEPTANCE FAILED")
        return 1
    except Exception as exc:  # noqa: BLE001 - report any harness failure
        print(f"  ERROR {type(exc).__name__}: {exc}")
        return 2
    print("ACCEPTANCE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
