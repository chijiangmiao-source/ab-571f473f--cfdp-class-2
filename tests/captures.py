"""Helpers for assembling CFDP captures in tests and acceptance checks."""

from __future__ import annotations

from app import cfdp

R = "to_receiver"
S = "to_sender"


def crc(data: bytes) -> int:
    return cfdp.crc32c(data)


def closed_loop_capture(
    payload: bytes,
    sender: int = 0x1111,
    receiver: int = 0x2222,
    sequence: int = 1,
    chunk_size: int | None = None,
) -> list[tuple[str, bytes]]:
    """Build a perfectly closing Class 2 exchange for ``payload``."""
    size = len(payload)
    if chunk_size is None:
        chunk_size = max(1, size)
    items: list[tuple[str, bytes]] = [
        (R, cfdp.metadata(sender, receiver, sequence, size))
    ]
    for offset in range(0, size, chunk_size):
        block = payload[offset:offset + chunk_size]
        items.append(
            (R, cfdp.file_data(sender, receiver, sequence, offset, block))
        )
    items.append((R, cfdp.eof(sender, receiver, sequence, crc(payload), size)))
    items.append((S, cfdp.ack(receiver, sender, sequence,
                              cfdp.CODE_EOF, cfdp.SUBTYPE_EOF)))
    items.append((S, cfdp.finished(receiver, sender, sequence, 0)))
    items.append((R, cfdp.ack(sender, receiver, sequence,
                              cfdp.CODE_FINISHED, cfdp.SUBTYPE_FINISHED)))
    return items


def split_payload(payload: bytes, missing: list[tuple[int, int]]):
    """Return (present_blocks, missing_blocks) as (offset, data) lists."""
    missing = sorted(missing)
    present: list[tuple[int, bytes]] = []
    gap: list[tuple[int, bytes]] = []
    cursor = 0
    for start, end in missing:
        if cursor < start:
            present.append((cursor, payload[cursor:start]))
        gap.append((start, payload[start:end]))
        cursor = end
    if cursor < len(payload):
        present.append((cursor, payload[cursor:]))
    return present, gap


def capture_with_gap(
    payload: bytes,
    missing: list[tuple[int, int]],
    sender: int = 0x1111,
    receiver: int = 0x2222,
    sequence: int = 1,
) -> tuple[list[tuple[str, bytes]], list[tuple[int, bytes]]]:
    """Capture stopped at EOF with ``missing`` intervals absent."""
    size = len(payload)
    present, gap = split_payload(payload, missing)
    items: list[tuple[str, bytes]] = [
        (R, cfdp.metadata(sender, receiver, sequence, size))
    ]
    for offset, block in present:
        items.append(
            (R, cfdp.file_data(sender, receiver, sequence, offset, block))
        )
    items.append((R, cfdp.eof(sender, receiver, sequence, crc(payload), size)))
    return items, gap


def nak_for(
    gap: list[tuple[int, int]],
    size: int,
    sender: int = 0x1111,
    receiver: int = 0x2222,
    sequence: int = 1,
) -> bytes:
    return cfdp.nak(
        receiver, sender, sequence, 0, size,
        [(start, start + len(block)) for start, block in gap],
    )


def recovery_tail(
    payload: bytes,
    gap: list[tuple[int, bytes]],
    *,
    sender: int = 0x1111,
    receiver: int = 0x2222,
    sequence: int = 1,
) -> list[tuple[str, bytes]]:
    """ACK(EOF), NAK, retransmissions, then the Finished handshake.

    Appended to a capture that stopped right after EOF.
    """
    size = len(payload)
    items: list[tuple[str, bytes]] = [
        (S, cfdp.ack(receiver, sender, sequence,
                     cfdp.CODE_EOF, cfdp.SUBTYPE_EOF)),
        (S, nak_for(gap, size, sender, receiver, sequence)),
    ]
    for offset, block in gap:
        items.append(
            (R, cfdp.file_data(sender, receiver, sequence, offset, block))
        )
    items.append((S, cfdp.finished(receiver, sender, sequence, 0)))
    items.append((R, cfdp.ack(sender, receiver, sequence,
                              cfdp.CODE_FINISHED, cfdp.SUBTYPE_FINISHED)))
    return items
