import base64
import json
import threading
import urllib.request
from http.client import RemoteDisconnected

import pytest

from app.server import AuditStore, build_server, parse_submission
from tests import captures as cap
from tests.captures import R

PAYLOAD = bytes((i * 19 + 3) % 256 for i in range(1000))


def encode(items):
    return [
        {"direction": d, "pdu_base64": base64.b64encode(raw).decode("ascii")}
        for d, raw in items
    ]


# ---------------------------------------------------------------------------
# Freeze semantics at store level
# ---------------------------------------------------------------------------

def test_identical_capture_returns_original_frozen_verdict():
    store = AuditStore()
    capture = cap.closed_loop_capture(PAYLOAD)
    status1, first = store.submit("job-1", capture)
    assert status1 == 200 and first["replayed"] is True
    status2, second = store.submit("job-1", list(capture))
    assert status2 == 200 and second["replayed"] is False
    assert second["report"] == first["report"]
    assert second["capture_fingerprint"] == first["capture_fingerprint"]


def test_changed_pdu_returns_frozen_conflict_and_keeps_original():
    store = AuditStore()
    capture = cap.closed_loop_capture(PAYLOAD)
    _, first = store.submit("job-1", capture)

    altered = list(capture)
    # Corrupt one byte inside a FileData PDU.
    raw = bytearray(altered[1][1])
    raw[-1] ^= 0x01
    altered[1] = (altered[1][0], bytes(raw))

    status, response = store.submit("job-1", altered)
    assert status == 409
    assert response["error"] == "frozen_conflict"
    assert response["original_fingerprint"] == first["capture_fingerprint"]
    assert response["capture_fingerprint"] != first["capture_fingerprint"]

    # The original frozen verdict is still served unchanged.
    assert store.get("job-1")["report"] == first["report"]


def test_changed_direction_label_is_a_frozen_conflict():
    store = AuditStore()
    capture = cap.closed_loop_capture(PAYLOAD)
    _, first = store.submit("job-9", capture)
    altered = list(capture)
    altered[0] = ("to_sender", altered[0][1])  # flip one direction label
    status, response = store.submit("job-9", altered)
    assert status == 409 and response["error"] == "frozen_conflict"
    assert store.get("job-9")["capture_fingerprint"] == \
        first["capture_fingerprint"]


def test_distinct_audit_ids_are_independent():
    store = AuditStore()
    capture = cap.closed_loop_capture(PAYLOAD)
    status, _ = store.submit("a", capture)
    assert status == 200
    status, response = store.submit("b", capture)
    assert status == 200 and response["replayed"] is True
    assert store.get("c") is None


# ---------------------------------------------------------------------------
# Submission parsing
# ---------------------------------------------------------------------------

def test_parse_submission_decodes_base64_in_order():
    capture = cap.closed_loop_capture(PAYLOAD[:10])
    body = json.dumps({"audit_id": "x", "pdus": encode(capture)}).encode()
    audit_id, items = parse_submission(body)
    assert audit_id == "x" and items == capture


def test_parse_submission_rejects_bad_base64():
    body = json.dumps(
        {"audit_id": "x",
         "pdus": [{"direction": R, "pdu_base64": "not@base64"}]}
    ).encode()
    with pytest.raises(ValueError):
        parse_submission(body)


def test_parse_submission_rejects_bad_direction():
    body = json.dumps(
        {"audit_id": "x",
         "pdus": [{"direction": "sideways",
                   "pdu_base64": base64.b64encode(b"\x10").decode()}]}
    ).encode()
    with pytest.raises(ValueError):
        parse_submission(body)


# ---------------------------------------------------------------------------
# End-to-end HTTP
# ---------------------------------------------------------------------------

class ServerThread:
    def __init__(self):
        self.server = build_server(host="127.0.0.1", port=0)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def request(port, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=data, method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_http_health_submit_freeze_and_conflict():
    with ServerThread() as srv:
        status, body = request(srv.port, "GET", "/health")
        assert status == 200 and body["status"] == "ok"

        capture = cap.closed_loop_capture(PAYLOAD, chunk_size=512)
        submission = {"audit_id": "http-job", "pdus": encode(capture)}
        status, body = request(srv.port, "POST", "/audit", submission)
        assert status == 200
        assert body["report"]["verdict"] == "closed"
        assert body["report"]["coverage"] == [[0, 1000]]
        fingerprint = body["capture_fingerprint"]

        status, body = request(srv.port, "GET", "/audit/http-job")
        assert status == 200 and body["capture_fingerprint"] == fingerprint

        status, body = request(srv.port, "POST", "/audit", submission)
        assert status == 200 and body["replayed"] is False

        altered_pdus = submission["pdus"][:-3]  # drop the final handshake
        status, body = request(
            srv.port, "POST", "/audit",
            {"audit_id": "http-job", "pdus": altered_pdus},
        )
        assert status == 409 and body["error"] == "frozen_conflict"

        status, body = request(srv.port, "GET", "/audit/missing")
        assert status == 404


def test_http_bad_requests():
    with ServerThread() as srv:
        status, body = request(srv.port, "POST", "/audit", {"audit_id": "z"})
        assert status == 400
        status, _ = request(srv.port, "POST", "/audit",
                            {"audit_id": "z", "pdus": []})
        assert status == 400
