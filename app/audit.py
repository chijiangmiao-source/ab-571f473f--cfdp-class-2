"""CFDP Class 2 transaction closed-loop audit state machine.

A capture is an ordered list of PDUs as seen on the wire (each item carrying
its submission direction label and the raw PDU octets).  The auditor replays
the capture in capture order, reassembles the file, verifies Class 2 closure
rules and freezes a verdict:

* ``closed``     - Finished handshake completed on top of full coverage and a
                   matching CRC32C; both sides' phase evidence is present.
* ``incomplete`` - no protocol violation, but the loop is not closed; the
                   precise NAK interval list for the uncovered bytes is given.
* ``conflict``   - a protocol violation was found; ``first_violation`` names
                   the offending PDU, the stage at which it occurred and why.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import cfdp
from .cfdp import (
    CODE_ACK,
    CODE_EOF,
    CODE_FINISHED,
    CODE_METADATA,
    CODE_NAK,
    DIR_TO_RECEIVER,
    DIR_TO_SENDER,
    PduParseError,
    crc32c,
)

# Violation codes (the five mandated categories plus supporting precision).
V_CONFLICTING_RETRANSMIT = "conflicting_retransmission"
V_WRONG_TRANSACTION = "wrong_transaction"
V_PREMATURE_ACK = "premature_acknowledgment"
V_WRONG_ACK_TYPE = "wrong_ack_type"
V_POST_TERMINAL = "post_terminal_write"
V_MALFORMED = "malformed_pdu"
V_PROTOCOL_ORDER = "protocol_order"
V_BAD_NAK = "bad_nak"
V_SIZE_MISMATCH = "size_mismatch"
V_OUT_OF_BOUNDS = "data_out_of_bounds"
V_CHECKSUM = "checksum_mismatch"
V_FAULT_FINISH = "finished_with_fault_status"

VERDICT_CLOSED = "closed"
VERDICT_INCOMPLETE = "incomplete"
VERDICT_CONFLICT = "conflict"


@dataclass
class Violation:
    index: int
    code: str
    reason: str
    stage: str
    sender_phase: str
    receiver_phase: str
    kind: str = "?"
    direction: str = "?"

    def as_dict(self) -> dict:
        return {
            "index": self.index,
            "pdu": self.kind,
            "direction": self.direction,
            "code": self.code,
            "stage": self.stage,
            "sender_phase": self.sender_phase,
            "receiver_phase": self.receiver_phase,
            "reason": self.reason,
        }


@dataclass
class _Evidence:
    index: int
    kind: str
    direction: int
    sender_phase: str
    receiver_phase: str
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "index": self.index,
            "pdu": self.kind,
            "direction": cfdp.DIR_NAMES[self.direction],
            "sender_phase": self.sender_phase,
            "receiver_phase": self.receiver_phase,
            "note": self.note,
        }


@dataclass
class AuditState:
    # Transaction identity, established by the opening Metadata PDU.
    sender: int | None = None
    receiver: int | None = None
    sequence: int | None = None
    declared_size: int | None = None

    buffer: bytearray = field(default_factory=bytearray)
    covered: bytearray = field(default_factory=bytearray)

    eof_seen: bool = False
    eof_checksum: int | None = None
    eof_size: int | None = None
    eof_raw_sig: tuple | None = None
    ack_eof_seen: bool = False
    finished_seen: bool = False
    finished_status: int | None = None
    closed: bool = False

    stage: str = "idle"
    sender_phase: str = "idle"
    receiver_phase: str = "idle"
    evidence: list[_Evidence] = field(default_factory=list)
    log: list[dict] = field(default_factory=list)
    violation: Violation | None = None

    # -- helpers -----------------------------------------------------------

    def _record(self, index: int, desc: dict, sender_phase: str,
                receiver_phase: str, note: str = "") -> None:
        self.sender_phase = sender_phase
        self.receiver_phase = receiver_phase
        self.evidence.append(
            _Evidence(
                index, desc["kind"], desc["direction"],
                sender_phase, receiver_phase, note,
            )
        )

    def _fail(self, index: int, desc: dict | None, code: str,
              reason: str) -> None:
        kind = desc["kind"] if desc else "undecodable"
        direction = (
            cfdp.DIR_NAMES[desc["direction"]] if desc else "unknown"
        )
        self.violation = Violation(
            index=index,
            code=code,
            reason=reason,
            stage=self.stage,
            sender_phase=self.sender_phase,
            receiver_phase=self.receiver_phase,
            kind=kind,
            direction=direction,
        )

    def uncovered(self) -> list[tuple[int, int]]:
        if self.declared_size is None:
            return []
        intervals: list[tuple[int, int]] = []
        start = None
        for pos, flag in enumerate(self.covered):
            if not flag and start is None:
                start = pos
            elif flag and start is not None:
                intervals.append((start, pos))
                start = None
        if start is not None:
            intervals.append((start, self.declared_size))
        return intervals

    def coverage(self) -> list[tuple[int, int]]:
        if self.declared_size is None:
            return []
        intervals: list[tuple[int, int]] = []
        start = None
        for pos, flag in enumerate(self.covered):
            if flag and start is None:
                start = pos
            elif not flag and start is not None:
                intervals.append((start, pos))
                start = None
        if start is not None:
            intervals.append((start, self.declared_size))
        return intervals

    def received_bytes(self) -> int:
        return sum(self.covered) if self.declared_size is not None else 0

    def crc_received(self) -> int:
        crc = 0
        for start, end in self.coverage():
            crc = crc32c(memoryview(self.buffer)[start:end], crc)
        return crc


def _association_ok(state: AuditState, desc: dict) -> bool:
    if desc["sequence"] != state.sequence:
        return False
    if desc["direction"] == DIR_TO_RECEIVER:
        return desc["source"] == state.sender and desc["destination"] == state.receiver
    return desc["source"] == state.receiver and desc["destination"] == state.sender


def _add_file_data(state: AuditState, index: int, desc: dict) -> bool:
    """Merge one FileData PDU. Returns False if a violation was recorded."""
    offset = desc["offset"]
    data = desc["data"]
    end = offset + len(data)
    if offset < 0 or end > state.declared_size:  # offset is u32, stays >= 0
        state._fail(
            index, desc, V_OUT_OF_BOUNDS,
            f"FileData [{offset},{end}) exceeds declared file size "
            f"{state.declared_size}",
        )
        return False
    for pos in range(offset, end):
        if state.covered[pos] and state.buffer[pos] != data[pos - offset]:
            state._fail(
                index, desc, V_CONFLICTING_RETRANSMIT,
                f"overlapping byte at offset {pos} differs from previously "
                f"accepted data (old=0x{state.buffer[pos]:02x}, "
                f"new=0x{data[pos - offset]:02x})",
            )
            return False
    state.buffer[offset:end] = data
    state.covered[offset:end] = b"\x01" * len(data)
    return True


def _process(state: AuditState, index: int, direction_label: str,
             raw: bytes) -> bool:
    """Process one captured PDU. Returns False when auditing must stop."""
    try:
        desc = cfdp.parse(raw)
    except PduParseError as exc:
        state.violation = Violation(
            index, V_MALFORMED, f"undecodable PDU: {exc}", state.stage,
            state.sender_phase, state.receiver_phase,
        )
        return False
    state.log.append(
        {
            "index": index,
            "pdu": desc["kind"],
            "direction": cfdp.DIR_NAMES[desc["direction"]],
        }
    )

    if cfdp.DIR_NAMES[desc["direction"]] != direction_label:
        state._fail(
            index, desc, V_WRONG_TRANSACTION,
            f"submitted direction label {direction_label!r} does not match "
            f"PDU header direction {cfdp.DIR_NAMES[desc['direction']]!r}",
        )
        return False

    # The transaction opens with a forward Metadata PDU.
    if state.sender is None:
        if desc["kind"] != "Metadata" or desc["direction"] != DIR_TO_RECEIVER:
            state._fail(
                index, desc, V_PROTOCOL_ORDER,
                "a transaction capture must open with a sender->receiver "
                "Metadata PDU",
            )
            return False
        state.sender = desc["source"]
        state.receiver = desc["destination"]
        state.sequence = desc["sequence"]
        state.declared_size = desc["file_size"]
        state.buffer = bytearray(desc["file_size"])
        state.covered = bytearray(desc["file_size"])
        state.stage = "metadata"
        state._record(index, desc, "metadata_sent", "metadata_received")
        return True

    if not _association_ok(state, desc):
        state._fail(
            index, desc, V_WRONG_TRANSACTION,
            f"PDU belongs to transaction "
            f"{desc['source']}->{desc['destination']} seq="
            f"{desc['sequence']} dir={cfdp.DIR_NAMES[desc['direction']]}, "
            f"expected {state.sender}->{state.receiver} "
            f"seq={state.sequence}",
        )
        return False

    kind = desc["kind"]

    # Once the Finished handshake has completed the transaction is frozen.
    if state.closed:
        state._fail(
            index, desc, V_POST_TERMINAL,
            "PDU delivered after the Finished handshake closed the transaction",
        )
        return False

    if kind == "Metadata":
        state._fail(
            index, desc, V_PROTOCOL_ORDER,
            "second Metadata PDU for an established transaction",
        )
        return False

    if kind == "FileData":
        if state.finished_seen:
            state._fail(
                index, desc, V_POST_TERMINAL,
                "file data written after receiver sent Finished",
            )
            return False
        if not _add_file_data(state, index, desc):
            return False
        recovery = state.stage in ("eof", "eof_acked", "nak", "recovery")
        state.stage = "recovery" if recovery else "transfer"
        if recovery:
            state._record(
                index, desc, "retransmitted", "retransmission_received",
                "retransmission after NAK",
            )
        else:
            state._record(index, desc, "data_sent", "data_received")
        return True

    if kind == "EOF":
        if state.finished_seen:
            state._fail(
                index, desc, V_POST_TERMINAL,
                "EOF after receiver sent Finished",
            )
            return False
        if desc["file_size"] != state.declared_size:
            state._fail(
                index, desc, V_SIZE_MISMATCH,
                f"EOF file_size={desc['file_size']} disagrees with Metadata "
                f"declared size {state.declared_size}",
            )
            return False
        sig = (desc["checksum"], desc["file_size"])
        if state.eof_seen:
            if sig != state.eof_raw_sig:
                state._fail(
                    index, desc, V_CONFLICTING_RETRANSMIT,
                    "retransmitted EOF carries a different checksum/size",
                )
                return False
            # Identical EOF retransmission: benign, no new evidence.
            return True
        state.eof_seen = True
        state.eof_checksum = desc["checksum"]
        state.eof_size = desc["file_size"]
        state.eof_raw_sig = sig
        state.stage = "eof"
        state._record(index, desc, "eof_sent", "eof_received",
                      f"checksum=0x{desc['checksum']:08x}")
        return True

    if kind == "ACK":
        acked = desc["acked_code"]
        subtype = desc["subtype"]
        valid_pair = (
            (acked == CODE_EOF and subtype == cfdp.SUBTYPE_EOF
             and desc["direction"] == DIR_TO_SENDER)
            or (acked == CODE_FINISHED and subtype == cfdp.SUBTYPE_FINISHED
                and desc["direction"] == DIR_TO_RECEIVER)
        )
        if not valid_pair:
            expected = "EOF/0x00 (receiver->sender)" if acked == CODE_EOF else \
                "Finished/0x01 (sender->receiver)"
            state._fail(
                index, desc, V_WRONG_ACK_TYPE,
                f"ACK acks directive 0x{acked:02x} with subtype 0x{subtype:02x} "
                f"on {cfdp.DIR_NAMES[desc['direction']]}; legal pairs are "
                f"{expected}",
            )
            return False

        if acked == CODE_EOF:
            if state.finished_seen:
                state._fail(
                    index, desc, V_POST_TERMINAL,
                    "stale ACK(EOF) after receiver already sent Finished",
                )
                return False
            if not state.eof_seen:
                state._fail(
                    index, desc, V_PREMATURE_ACK,
                    "ACK(EOF) sent before any EOF was observed",
                )
                return False
            state.ack_eof_seen = True
            state.stage = "eof_acked"
            state._record(index, desc, "eof_acked", "ack_eof_sent")
            return True

        # ACK(Finished)
        if not state.finished_seen:
            state._fail(
                index, desc, V_PREMATURE_ACK,
                "ACK(Finished) sent before receiver sent Finished",
            )
            return False
        state.closed = True
        state.stage = "closed"
        state._record(index, desc, "ack_finished_sent", "finished_acked",
                      "transaction closed")
        return True

    if kind == "NAK":
        if state.finished_seen:
            state._fail(
                index, desc, V_POST_TERMINAL,
                "NAK after receiver sent Finished",
            )
            return False
        if not state.eof_seen:
            state._fail(
                index, desc, V_PROTOCOL_ORDER,
                "NAK before EOF: missing intervals can only be derived after EOF",
            )
            return False
        size = state.declared_size
        if (desc["scope_start"], desc["scope_end"]) != (0, size):
            state._fail(
                index, desc, V_BAD_NAK,
                f"NAK scope [{desc['scope_start']},{desc['scope_end']}) "
                f"must be [0,{size})",
            )
            return False
        requests = desc["requests"]
        if not requests:
            state._fail(
                index, desc, V_BAD_NAK,
                "NAK carries no segment requests",
            )
            return False
        prev_end = 0
        for start, end in requests:
            if not (0 <= start < end <= size) or start < prev_end:
                state._fail(
                    index, desc, V_BAD_NAK,
                    f"NAK request [{start},{end}) is not a valid ordered "
                    f"sub-interval of [0,{size})",
                )
                return False
            prev_end = end
        expected = state.uncovered()
        if requests != expected:
            state._fail(
                index, desc, V_BAD_NAK,
                f"NAK requests {_fmt_ranges(requests)} do not match the "
                f"uncovered intervals after EOF {_fmt_ranges(expected)}",
            )
            return False
        state.stage = "nak"
        state._record(
            index, desc, "nak_received", "nak_sent",
            f"requests={_fmt_ranges(requests)}",
        )
        return True

    if kind == "Finished":
        if desc["status"] != 0:
            state._fail(
                index, desc, V_FAULT_FINISH,
                f"Finished carries non-complete status 0x{desc['status']:02x} "
                f"(condition code {desc['condition_code']})",
            )
            return False
        if state.finished_seen:
            # Benign retransmission of an identical complete Finished.
            return True
        missing = state.uncovered()
        if missing:
            state._fail(
                index, desc, V_PREMATURE_ACK,
                f"Finished sent while intervals remain uncovered: "
                f"{_fmt_ranges(missing)}; NAK recovery must finish first",
            )
            return False
        actual = state.crc_received()
        if actual != state.eof_checksum:
            state._fail(
                index, desc, V_CHECKSUM,
                f"Finished sent with CRC32C mismatch: reassembled "
                f"0x{actual:08x} vs EOF 0x{state.eof_checksum:08x}",
            )
            return False
        if not state.eof_seen:
            state._fail(
                index, desc, V_PREMATURE_ACK,
                "Finished sent before EOF",
            )
            return False
        state.finished_seen = True
        state.finished_status = desc["status"]
        state.stage = "finished"
        state._record(index, desc, "finished_received", "finished_sent",
                      "complete, checksum verified")
        return True

    state._fail(index, desc, V_MALFORMED, f"unhandled PDU kind {kind}")  # pragma: no cover
    return False


def _fmt_ranges(ranges: list[tuple[int, int]]) -> str:
    return "[" + ", ".join(f"[{s},{e})" for s, e in ranges) + "]"


def audit_capture(items: list[tuple[str, bytes]]) -> dict:
    """Replay one capture and return the frozen report dict."""
    state = AuditState()
    for index, (direction_label, raw) in enumerate(items):
        if not _process(state, index, direction_label, raw):
            break

    expected_nak = None
    if state.declared_size is not None:
        missing = state.uncovered()
        expected_nak = {
            "scope_start": 0,
            "scope_end": state.declared_size,
            "requests": [[s, e] for s, e in missing],
        }

    crc_received = state.crc_received() if state.declared_size is not None else None
    checksum_match = (
        state.eof_seen
        and not state.uncovered()
        and crc_received == state.eof_checksum
    )

    if state.violation is not None:
        verdict = VERDICT_CONFLICT
    elif state.closed:
        verdict = VERDICT_CLOSED
    else:
        verdict = VERDICT_INCOMPLETE

    report = {
        "verdict": verdict,
        "transaction": (
            {
                "sender": state.sender,
                "receiver": state.receiver,
                "sequence": state.sequence,
            }
            if state.sender is not None
            else None
        ),
        "file_length": state.declared_size,
        "received_bytes": state.received_bytes(),
        "crc32c": (
            f"0x{crc_received:08x}" if crc_received is not None else None
        ),
        "eof_checksum": (
            f"0x{state.eof_checksum:08x}"
            if state.eof_checksum is not None
            else None
        ),
        "checksum_match": bool(checksum_match),
        "coverage": [[s, e] for s, e in state.coverage()],
        "uncovered": [[s, e] for s, e in state.uncovered()],
        "expected_nak": expected_nak,
        "stages": {
            "current": state.stage,
            "sender": state.sender_phase,
            "receiver": state.receiver_phase,
            "closed_loop": state.closed,
            "evidence": [ev.as_dict() for ev in state.evidence],
        },
        "processed_pdus": state.log,
        "first_violation": (
            state.violation.as_dict() if state.violation else None
        ),
    }
    return report
