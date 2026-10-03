import pytest

from app import cfdp
from app.audit import (
    V_BAD_NAK,
    V_CHECKSUM,
    V_CONFLICTING_RETRANSMIT,
    V_POST_TERMINAL,
    V_PREMATURE_ACK,
    V_PROTOCOL_ORDER,
    V_WRONG_ACK_TYPE,
    V_WRONG_TRANSACTION,
    VERDICT_CLOSED,
    VERDICT_CONFLICT,
    VERDICT_INCOMPLETE,
    audit_capture,
)

from tests import captures as cap
from tests.captures import R, S

SENDER, RECEIVER, SEQ = 0x1111, 0x2222, 7
PAYLOAD = bytes((i * 37 + 11) % 256 for i in range(300))


def run(payload=PAYLOAD, **kw):
    return audit_capture(cap.closed_loop_capture(payload, **kw))


# ---------------------------------------------------------------------------
# Complete closure
# ---------------------------------------------------------------------------

def test_full_capture_closes_with_full_coverage_and_evidence():
    report = run()
    assert report["verdict"] is VERDICT_CLOSED
    assert report["file_length"] == 300
    assert report["received_bytes"] == 300
    assert report["coverage"] == [[0, 300]]
    assert report["uncovered"] == []
    assert report["checksum_match"] is True
    assert report["crc32c"] == report["eof_checksum"]
    assert report["stages"]["closed_loop"] is True
    assert report["first_violation"] is None
    kinds = [(e["pdu"], e["direction"]) for e in report["stages"]["evidence"]]
    assert ("Metadata", "to_receiver") in kinds
    assert ("EOF", "to_receiver") in kinds
    assert ("ACK", "to_sender") in kinds       # ACK(EOF)
    assert ("Finished", "to_sender") in kinds
    assert ("ACK", "to_receiver") in kinds     # ACK(Finished)
    # Both parties' terminal phase evidence.
    final = report["stages"]["evidence"][-1]
    assert final["sender_phase"] == "ack_finished_sent"
    assert final["receiver_phase"] == "finished_acked"


def test_close_after_eof_with_no_data_is_incomplete_with_full_nak():
    items = [
        (R, cfdp.metadata(SENDER, RECEIVER, SEQ, 300)),
        (R, cfdp.eof(SENDER, RECEIVER, SEQ, cap.crc(PAYLOAD), 300)),
    ]
    report = audit_capture(items)
    assert report["verdict"] == VERDICT_INCOMPLETE
    assert report["expected_nak"]["requests"] == [[0, 300]]


def test_empty_file_closes():
    report = run(b"")
    assert report["verdict"] == VERDICT_CLOSED
    assert report["file_length"] == 0
    assert report["coverage"] == []


# ---------------------------------------------------------------------------
# Missing middle: precise NAK localisation and recovery
# ---------------------------------------------------------------------------

def test_missing_middle_localises_exact_nak_interval():
    items, gap = cap.capture_with_gap(PAYLOAD, [(120, 180)])
    report = audit_capture(items)
    assert report["verdict"] == VERDICT_INCOMPLETE
    assert report["uncovered"] == [[120, 180]]
    assert report["expected_nak"]["scope_start"] == 0
    assert report["expected_nak"]["scope_end"] == 300
    assert report["expected_nak"]["requests"] == [[120, 180]]
    assert report["coverage"] == [[0, 120], [180, 300]]


def test_multiple_missing_intervals_are_all_listed():
    items, gap = cap.capture_with_gap(PAYLOAD, [(10, 40), (100, 140), (290, 300)])
    report = audit_capture(items)
    assert report["expected_nak"]["requests"] == [[10, 40], [100, 140], [290, 300]]


def test_nak_must_match_uncovered_intervals():
    items, gap = cap.capture_with_gap(
        PAYLOAD, [(120, 180)],
        sender=SENDER, receiver=RECEIVER, sequence=SEQ,
    )
    items.append((S, cfdp.ack(RECEIVER, SENDER, SEQ, cfdp.CODE_EOF, 0)))
    # Receiver wrongly asks for already-covered bytes.
    items.append((S, cfdp.nak(RECEIVER, SENDER, SEQ, 0, 300, [(120, 200)])))
    report = audit_capture(items)
    assert report["verdict"] == VERDICT_CONFLICT
    v = report["first_violation"]
    assert v["code"] == V_BAD_NAK
    assert v["pdu"] == "NAK"
    assert v["stage"] == "eof_acked"


def test_gap_then_exact_nak_and_retransmission_closes():
    kw = dict(sender=SENDER, receiver=RECEIVER, sequence=SEQ)
    items, gap = cap.capture_with_gap(PAYLOAD, [(120, 180)], **kw)
    items += cap.recovery_tail(PAYLOAD, gap, **kw)
    report = audit_capture(items)
    assert report["verdict"] == VERDICT_CLOSED
    assert report["coverage"] == [[0, 300]]
    assert report["checksum_match"] is True


def test_retransmitted_overlap_with_identical_bytes_is_accepted():
    items = [
        (R, cfdp.metadata(SENDER, RECEIVER, SEQ, 10)),
        (R, cfdp.file_data(SENDER, RECEIVER, SEQ, 0, PAYLOAD[:10])),
        (R, cfdp.file_data(SENDER, RECEIVER, SEQ, 5, PAYLOAD[5:10])),
        (R, cfdp.eof(SENDER, RECEIVER, SEQ, cap.crc(PAYLOAD[:10]), 10)),
        (S, cfdp.ack(RECEIVER, SENDER, SEQ, cfdp.CODE_EOF, 0)),
        (S, cfdp.finished(RECEIVER, SENDER, SEQ, 0)),
        (R, cfdp.ack(SENDER, RECEIVER, SEQ, cfdp.CODE_FINISHED, 1)),
    ]
    assert audit_capture(items)["verdict"] == VERDICT_CLOSED


# ---------------------------------------------------------------------------
# Violations: first offending PDU, stage, verdict revoked
# ---------------------------------------------------------------------------

def test_conflicting_retransmission_is_flagged_at_first_offending_pdu():
    bad = bytearray(PAYLOAD[120:180])
    bad[7] ^= 0xFF
    items = [
        (R, cfdp.metadata(SENDER, RECEIVER, SEQ, 300)),
        (R, cfdp.file_data(SENDER, RECEIVER, SEQ, 0, PAYLOAD[:130])),
        (R, cfdp.file_data(SENDER, RECEIVER, SEQ, 120, bytes(bad))),
    ]
    report = audit_capture(items)
    assert report["verdict"] == VERDICT_CONFLICT
    v = report["first_violation"]
    assert v["index"] == 2
    assert v["code"] == V_CONFLICTING_RETRANSMIT
    assert v["pdu"] == "FileData"
    assert v["stage"] == "transfer"
    assert "offset 127" in v["reason"]


def test_wrong_transaction_association_is_flagged():
    items = [
        (R, cfdp.metadata(SENDER, RECEIVER, SEQ, 10)),
        (R, cfdp.file_data(0x9999, RECEIVER, SEQ, 0, PAYLOAD[:10])),
    ]
    report = audit_capture(items)
    v = report["first_violation"]
    assert report["verdict"] == VERDICT_CONFLICT
    assert v["code"] == V_WRONG_TRANSACTION and v["index"] == 1


def test_premature_finished_before_coverage_is_flagged():
    items = [
        (R, cfdp.metadata(SENDER, RECEIVER, SEQ, 300)),
        (R, cfdp.file_data(SENDER, RECEIVER, SEQ, 0, PAYLOAD[:100])),
        (R, cfdp.eof(SENDER, RECEIVER, SEQ, cap.crc(PAYLOAD), 300)),
        (S, cfdp.ack(RECEIVER, SENDER, SEQ, cfdp.CODE_EOF, 0)),
        (S, cfdp.finished(RECEIVER, SENDER, SEQ, 0)),
    ]
    report = audit_capture(items)
    v = report["first_violation"]
    assert v["code"] == V_PREMATURE_ACK and v["pdu"] == "Finished"
    assert report["verdict"] == VERDICT_CONFLICT


def test_premature_ack_of_eof_is_flagged():
    items = [
        (R, cfdp.metadata(SENDER, RECEIVER, SEQ, 10)),
        (S, cfdp.ack(RECEIVER, SENDER, SEQ, cfdp.CODE_EOF, 0)),
    ]
    report = audit_capture(items)
    assert report["first_violation"]["code"] == V_PREMATURE_ACK


def test_wrong_ack_type_is_flagged():
    # ACK claiming EOF but with the Finished subtype.
    items, gap = cap.capture_with_gap(
        PAYLOAD[:50], [],
        sender=SENDER, receiver=RECEIVER, sequence=SEQ,
    )
    items.append((S, cfdp.ack(RECEIVER, SENDER, SEQ, cfdp.CODE_EOF, 0x01)))
    report = audit_capture(items)
    assert report["first_violation"]["code"] == V_WRONG_ACK_TYPE


def test_ack_direction_mismatch_is_wrong_ack_type():
    # ACK(EOF) travelling sender->receiver (hand-built with forward header).
    wrong_ack = (
        cfdp.encode_header(
            cfdp.DIR_TO_RECEIVER, SENDER, RECEIVER, SEQ, cfdp.TYPE_DIRECTIVE
        )
        + bytes([cfdp.CODE_ACK, cfdp.CODE_EOF, cfdp.SUBTYPE_EOF])
    )
    items = [
        (R, cfdp.metadata(SENDER, RECEIVER, SEQ, 10)),
        (R, cfdp.file_data(SENDER, RECEIVER, SEQ, 0, PAYLOAD[:10])),
        (R, cfdp.eof(SENDER, RECEIVER, SEQ, cap.crc(PAYLOAD[:10]), 10)),
        (R, wrong_ack),
    ]
    report = audit_capture(items)
    assert report["first_violation"]["code"] == V_WRONG_ACK_TYPE


def test_write_after_terminal_is_flagged():
    items = cap.closed_loop_capture(
        PAYLOAD[:40], sender=SENDER, receiver=RECEIVER, sequence=SEQ
    )
    items.append((R, cfdp.file_data(SENDER, RECEIVER, SEQ, 0, PAYLOAD[:40])))
    report = audit_capture(items)
    v = report["first_violation"]
    assert v["code"] == V_POST_TERMINAL and v["stage"] == "closed"
    assert report["verdict"] == VERDICT_CONFLICT


def test_checksum_mismatch_blocks_finished():
    items = [
        (R, cfdp.metadata(SENDER, RECEIVER, SEQ, 10)),
        (R, cfdp.file_data(SENDER, RECEIVER, SEQ, 0, PAYLOAD[:10])),
        (R, cfdp.eof(SENDER, RECEIVER, SEQ, 0x00000000, 10)),
        (S, cfdp.ack(RECEIVER, SENDER, SEQ, cfdp.CODE_EOF, 0)),
        (S, cfdp.finished(RECEIVER, SENDER, SEQ, 0)),
    ]
    report = audit_capture(items)
    assert report["first_violation"]["code"] == V_CHECKSUM
    assert report["verdict"] == VERDICT_CONFLICT


def test_nak_before_eof_is_rejected():
    items = [
        (R, cfdp.metadata(SENDER, RECEIVER, SEQ, 300)),
        (R, cfdp.file_data(SENDER, RECEIVER, SEQ, 0, PAYLOAD[:100])),
        (S, cfdp.nak(RECEIVER, SENDER, SEQ, 0, 300, [(100, 300)])),
    ]
    report = audit_capture(items)
    assert report["first_violation"]["code"] == V_PROTOCOL_ORDER


def test_malformed_pdu_is_conflict():
    report = audit_capture([(R, b"\x00not a pdu")])
    assert report["verdict"] == VERDICT_CONFLICT
    assert report["first_violation"]["code"] == "malformed_pdu"


def test_direction_label_mismatch_is_wrong_transaction():
    items = [
        (S, cfdp.metadata(SENDER, RECEIVER, SEQ, 10)),  # labelled wrong way
    ]
    report = audit_capture(items)
    assert report["first_violation"]["code"] == V_WRONG_TRANSACTION
