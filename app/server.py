"""HTTP front-end for the CFDP Class 2 closed-loop auditor.

Endpoints
---------
GET  /health                    liveness / readiness response
POST /audit                     submit a capture under an audit identifier
GET  /audit/<audit_id>          read the frozen verdict

The submission body is::

    {
      "audit_id": "job-2026-0001",
      "pdus": [
        {"direction": "to_receiver", "pdu_base64": "..."},
        {"direction": "to_sender",   "pdu_base64": "..."}
      ]
    }

Directions are capture-direction labels: ``to_receiver`` (sender->receiver)
or ``to_sender`` (receiver->sender).  PDUs are replayed strictly in array
order.

Freeze rules: the first capture seen for an audit identifier freezes a
verdict keyed by the exact (direction, raw PDU octets) sequence.  Re-posting
the identical capture returns the original frozen verdict.  Posting the same
identifier with any changed direction or PDU octets returns HTTP 409 and a
``frozen_conflict`` body; the original verdict stays retrievable.

Host and port are configurable through ``CFDP_AUDIT_HOST`` and
``CFDP_AUDIT_PORT``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

from .audit import audit_capture


VALID_DIRECTIONS = {"to_receiver", "to_sender"}


class AuditStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._frozen: dict[str, dict] = {}

    @staticmethod
    def _capture_fingerprint(items: list[tuple[str, bytes]]) -> str:
        digest = hashlib.sha256()
        for direction, raw in items:
            digest.update(direction.encode("ascii"))
            digest.update(b"|")
            digest.update(str(len(raw)).encode("ascii"))
            digest.update(b"|")
            digest.update(raw)
            digest.update(b"\n")
        return digest.hexdigest()

    def submit(self, audit_id: str,
               items: list[tuple[str, bytes]]) -> tuple[int, dict]:
        fingerprint = self._capture_fingerprint(items)
        with self._lock:
            existing = self._frozen.get(audit_id)
            if existing is not None:
                if existing["capture_fingerprint"] == fingerprint:
                    return 200, {
                        "frozen": True,
                        "replayed": False,
                        "audit_id": audit_id,
                        "capture_fingerprint": fingerprint,
                        "report": existing["report"],
                    }
                return 409, {
                    "frozen": True,
                    "replayed": False,
                    "audit_id": audit_id,
                    "error": "frozen_conflict",
                    "reason": (
                        "the audit identifier already holds a verdict; the "
                        "new capture differs in a direction or PDU"
                    ),
                    "capture_fingerprint": fingerprint,
                    "original_fingerprint": existing["capture_fingerprint"],
                    "original_report": existing["report"],
                }

            report = audit_capture(items)
            record = {
                "capture_fingerprint": fingerprint,
                "report": report,
            }
            self._frozen[audit_id] = record
            return 200, {
                "frozen": True,
                "replayed": True,
                "audit_id": audit_id,
                "capture_fingerprint": fingerprint,
                "report": report,
            }

    def get(self, audit_id: str) -> dict | None:
        with self._lock:
            existing = self._frozen.get(audit_id)
            if existing is None:
                return None
            return {
                "frozen": True,
                "replayed": False,
                "audit_id": audit_id,
                "capture_fingerprint": existing["capture_fingerprint"],
                "report": existing["report"],
            }


def parse_submission(payload: bytes) -> tuple[str, list[tuple[str, bytes]]]:
    try:
        body = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"request body must be JSON: {exc}") from exc
    if not isinstance(body, dict):
        raise ValueError("request body must be a JSON object")
    audit_id = body.get("audit_id")
    if not isinstance(audit_id, str) or not audit_id.strip():
        raise ValueError("audit_id must be a non-empty string")
    pdu_entries = body.get("pdus")
    if not isinstance(pdu_entries, list) or not pdu_entries:
        raise ValueError("pdus must be a non-empty array")

    items: list[tuple[str, bytes]] = []
    for pos, entry in enumerate(pdu_entries):
        if not isinstance(entry, dict):
            raise ValueError(f"pdus[{pos}] must be an object")
        direction = entry.get("direction")
        if direction not in VALID_DIRECTIONS:
            raise ValueError(
                f"pdus[{pos}].direction must be one of "
                f"{sorted(VALID_DIRECTIONS)}"
            )
        encoded = entry.get("pdu_base64")
        if not isinstance(encoded, str):
            raise ValueError(f"pdus[{pos}].pdu_base64 must be a string")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise ValueError(
                f"pdus[{pos}].pdu_base64 is not valid strict Base64: {exc}"
            ) from exc
        if not raw:
            raise ValueError(f"pdus[{pos}] decodes to an empty PDU")
        items.append((direction, raw))
    return audit_id.strip(), items


def make_handler(store: AuditStore):
    class Handler(BaseHTTPRequestHandler):
        server_version = "CfdpAudit/1.0"

        def _send_json(self, status: int, payload: dict) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0] == "/health":
                self._send_json(
                    200,
                    {"status": "ok", "service": "cfdp-class2-audit"},
                )
                return
            prefix = "/audit/"
            path = self.path.split("?", 1)[0]
            if path.startswith(prefix) and len(path) > len(prefix):
                audit_id = unquote(path[len(prefix):])
                record = store.get(audit_id)
                if record is None:
                    self._send_json(
                        404,
                        {
                            "error": "not_found",
                            "audit_id": audit_id,
                            "reason": "no frozen verdict for this audit id",
                        },
                    )
                else:
                    self._send_json(200, record)
                return
            self._send_json(
                404,
                {"error": "not_found",
                 "routes": ["GET /health", "POST /audit",
                            "GET /audit/<audit_id>"]},
            )

        def do_POST(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0] != "/audit":
                self._send_json(404, {"error": "not_found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send_json(400, {"error": "bad_request",
                                      "reason": "invalid Content-Length"})
                return
            if length <= 0 or length > 8 * 1024 * 1024:
                self._send_json(
                    400,
                    {"error": "bad_request",
                     "reason": "Content-Length must be in (0, 8 MiB]"},
                )
                return
            payload = self.rfile.read(length)
            try:
                audit_id, items = parse_submission(payload)
            except ValueError as exc:
                self._send_json(
                    400, {"error": "bad_request", "reason": str(exc)}
                )
                return
            status, response = store.submit(audit_id, items)
            self._send_json(status, response)

        def log_message(self, fmt: str, *args) -> None:  # noqa: A003
            if os.environ.get("CFDP_AUDIT_QUIET"):
                return
            super().log_message(fmt, *args)

    return Handler


def build_server(host: str | None = None,
                 port: int | None = None,
                 store: AuditStore | None = None) -> ThreadingHTTPServer:
    host = host if host is not None else os.environ.get(
        "CFDP_AUDIT_HOST", "0.0.0.0"
    )
    if port is None:
        port = int(os.environ.get("CFDP_AUDIT_PORT", "8080"))
    return ThreadingHTTPServer((host, port), make_handler(store or AuditStore()))


def main() -> None:
    server = build_server()
    host, port = server.server_address[:2]
    print(f"CFDP Class 2 audit service listening on {host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
