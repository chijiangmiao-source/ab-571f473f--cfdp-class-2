"""Short-header CFDP PDU (de)serialisation.

Only the restricted form required by the archive is supported:

* 8-octet short fixed header
* 16-bit entity IDs and 16-bit transaction sequence number
* acknowledged mode (Class 2) only
* file size <= 64 KiB
* PDU kinds: Metadata, File Data, EOF, ACK, NAK, Finished

Header layout (8 octets, multi-octet integers big-endian):

    octet 0  : VVVV.DMR   V=version(=1) D=direction(0 sender->receiver,
               1 receiver->sender) M=mode(1 acknowledged) R=reserved(0)
    octets 1-2: source entity ID (u16)
    octets 3-4: destination entity ID (u16)
    octets 5-6: transaction sequence number (u16)
    octet 7  : PDU type, 0 = file directive, 1 = file data

Directives start with a one-octet directive code (CCSDS-style):

    Metadata 0x08, EOF 0x04, ACK 0x06, NAK 0x09, Finished 0x0D

Bodies:

    Metadata : seg-ctrl(u8=0) file_size(u32)
               src_len(u8) src_name dst_len(u8) dst_name
    File Data: offset(u32) data...
    EOF      : checksum(u32, CRC32C/ Castagnoli) file_size(u32)
    ACK      : acked_directive_code(u8) directive_subtype(u8)
                 EOF -> code 0x04 subtype 0x00
                 Finished -> code 0x0D subtype 0x01
    NAK      : scope_start(u32) scope_end(u32)
               request_start(u32) request_end(u32) ...   (end exclusive)
    Finished : status(u8, 0 = complete, high nibble condition code)
               filestore_responses_length(u8 = 0)
"""

from __future__ import annotations

import struct

VERSION = 1
MAX_FILE_SIZE = 64 * 1024

TYPE_DIRECTIVE = 0
TYPE_FILE_DATA = 1

DIR_TO_RECEIVER = 0  # sender -> receiver
DIR_TO_SENDER = 1    # receiver -> sender

DIR_NAMES = {DIR_TO_RECEIVER: "to_receiver", DIR_TO_SENDER: "to_sender"}

CODE_EOF = 0x04
CODE_ACK = 0x06
CODE_METADATA = 0x08
CODE_NAK = 0x09
CODE_FINISHED = 0x0D

DIRECTIVE_NAMES = {
    CODE_EOF: "EOF",
    CODE_ACK: "ACK",
    CODE_METADATA: "Metadata",
    CODE_NAK: "NAK",
    CODE_FINISHED: "Finished",
}

# ACK directive subtype for the acknowledged PDU.
SUBTYPE_EOF = 0x00
SUBTYPE_FINISHED = 0x01


class PduParseError(ValueError):
    """Raised when an octet string cannot be parsed as an accepted PDU."""


# ---------------------------------------------------------------------------
# CRC-32C (Castagnoli, reflected polynomial 0x82F63B78)
# ---------------------------------------------------------------------------

def _build_crc32c_table() -> list[int]:
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if (crc & 1) else crc >> 1
        table.append(crc)
    return table


_CRC32C_TABLE = _build_crc32c_table()


def crc32c(data: bytes | bytearray, crc: int = 0) -> int:
    crc ^= 0xFFFFFFFF
    table = _CRC32C_TABLE
    for octet in data:
        crc = table[(crc ^ octet) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

def _encode_first_octet(direction: int, acknowledged: bool = True) -> int:
    return (
        (VERSION << 4)
        | ((direction & 1) << 3)
        | ((1 if acknowledged else 0) << 2)
    )


def encode_header(
    direction: int,
    source: int,
    destination: int,
    sequence: int,
    pdu_type: int,
    acknowledged: bool = True,
) -> bytes:
    for name, value in (("source", source), ("destination", destination),
                        ("sequence", sequence)):
        if not 0 <= value <= 0xFFFF:
            raise ValueError(f"{name} must be a 16-bit entity/sequence number")
    if pdu_type not in (TYPE_DIRECTIVE, TYPE_FILE_DATA):
        raise ValueError("unsupported PDU type")
    return struct.pack(
        ">BHHHB",
        _encode_first_octet(direction, acknowledged),
        source,
        destination,
        sequence,
        pdu_type,
    )


# ---------------------------------------------------------------------------
# PDU builders
# ---------------------------------------------------------------------------

def metadata(
    source: int,
    destination: int,
    sequence: int,
    file_size: int,
    source_name: str = "src.bin",
    destination_name: str = "dst.bin",
) -> bytes:
    if not 0 <= file_size <= MAX_FILE_SIZE:
        raise ValueError("file size must be <= 64 KiB")
    src = source_name.encode("utf-8")
    dst = destination_name.encode("utf-8")
    if len(src) > 255 or len(dst) > 255:
        raise ValueError("file names must be <= 255 octets")
    body = struct.pack(">BI", 0, file_size)
    body += bytes([len(src)]) + src + bytes([len(dst)]) + dst
    return (
        encode_header(
            DIR_TO_RECEIVER, source, destination, sequence, TYPE_DIRECTIVE
        )
        + bytes([CODE_METADATA])
        + body
    )


def file_data(
    source: int,
    destination: int,
    sequence: int,
    offset: int,
    data: bytes,
) -> bytes:
    if not 0 <= offset <= 0xFFFFFFFF:
        raise ValueError("offset out of range")
    return (
        encode_header(
            DIR_TO_RECEIVER, source, destination, sequence, TYPE_FILE_DATA
        )
        + struct.pack(">I", offset)
        + data
    )


def eof(
    source: int,
    destination: int,
    sequence: int,
    checksum: int,
    file_size: int,
) -> bytes:
    return (
        encode_header(
            DIR_TO_RECEIVER, source, destination, sequence, TYPE_DIRECTIVE
        )
        + bytes([CODE_EOF])
        + struct.pack(">II", checksum & 0xFFFFFFFF, file_size)
    )


def ack(
    receiver_entity: int,
    sender_entity: int,
    sequence: int,
    acked_code: int,
    subtype: int,
) -> bytes:
    """Receiver ACKs EOF; sender ACKs Finished.

    The entity IDs are the *sender of this ACK* first, as carried on the wire.
    """
    direction = (
        DIR_TO_SENDER if acked_code == CODE_EOF else DIR_TO_RECEIVER
    )
    return (
        encode_header(
            direction, receiver_entity, sender_entity, sequence, TYPE_DIRECTIVE
        )
        + bytes([CODE_ACK, acked_code, subtype])
    )


def nak(
    receiver_entity: int,
    sender_entity: int,
    sequence: int,
    scope_start: int,
    scope_end: int,
    requests: list[tuple[int, int]],
) -> bytes:
    body = struct.pack(">II", scope_start, scope_end)
    for start, end in requests:
        body += struct.pack(">II", start, end)
    return (
        encode_header(
            DIR_TO_SENDER, receiver_entity, sender_entity,
            sequence, TYPE_DIRECTIVE,
        )
        + bytes([CODE_NAK])
        + body
    )


def finished(
    receiver_entity: int,
    sender_entity: int,
    sequence: int,
    status: int = 0,
) -> bytes:
    return (
        encode_header(
            DIR_TO_SENDER, receiver_entity, sender_entity,
            sequence, TYPE_DIRECTIVE,
        )
        + bytes([CODE_FINISHED, status & 0xFF, 0])
    )


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse(raw: bytes) -> dict:
    """Parse one PDU into a descriptor dict.

    Raises PduParseError for anything outside the supported short-header
    acknowledged-mode subset.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise PduParseError("PDU must be octets")
    if len(raw) < 8:
        raise PduParseError("PDU shorter than 8-octet header")
    first, source, destination, sequence, pdu_type = struct.unpack(
        ">BHHHB", raw[:8]
    )
    version = first >> 4
    direction = (first >> 3) & 1
    mode_ack = bool((first >> 2) & 1)
    reserved = first & 3
    if version != VERSION:
        raise PduParseError(f"unsupported PDU version {version}")
    if reserved != 0:
        raise PduParseError("reserved header bits must be zero")
    if not mode_ack:
        raise PduParseError("only acknowledged-mode (Class 2) PDUs are accepted")
    if direction not in (DIR_TO_RECEIVER, DIR_TO_SENDER):  # pragma: no cover
        raise PduParseError("bad direction bit")

    desc = {
        "direction": direction,
        "source": source,
        "destination": destination,
        "sequence": sequence,
        "type": pdu_type,
        "raw_length": len(raw),
    }
    body = raw[8:]

    if pdu_type == TYPE_FILE_DATA:
        if len(body) < 4:
            raise PduParseError("file data PDU missing offset")
        (offset,) = struct.unpack(">I", body[:4])
        desc.update(kind="FileData", offset=offset, data=bytes(body[4:]))
        return desc

    if pdu_type != TYPE_DIRECTIVE:
        raise PduParseError(f"unsupported PDU type field {pdu_type}")
    if not body:
        raise PduParseError("directive PDU missing directive code")
    code = body[0]
    if code not in DIRECTIVE_NAMES:
        raise PduParseError(f"unsupported directive code 0x{code:02x}")
    desc["code"] = code
    desc["kind"] = DIRECTIVE_NAMES[code]
    payload = body[1:]

    if code == CODE_METADATA:
        if len(payload) < 5:
            raise PduParseError("truncated Metadata body")
        seg_ctrl, file_size = struct.unpack(">BI", payload[:5])
        if seg_ctrl & 0xFE:
            raise PduParseError("bad segmentation control byte")
        pos = 5
        try:
            (src_len,) = struct.unpack(">B", payload[pos:pos + 1])
            pos += 1
            src_name = payload[pos:pos + src_len].decode("utf-8")
            pos += src_len
            (dst_len,) = struct.unpack(">B", payload[pos:pos + 1])
            pos += 1
            dst_name = payload[pos:pos + dst_len].decode("utf-8")
            pos += dst_len
        except (struct.error, UnicodeDecodeError) as exc:
            raise PduParseError("truncated Metadata file names") from exc
        if pos != len(payload):
            raise PduParseError("trailing octets in Metadata body")
        if file_size > MAX_FILE_SIZE:
            raise PduParseError("declared file exceeds 64 KiB")
        desc.update(
            file_size=file_size, source_name=src_name,
            destination_name=dst_name, segmentation=bool(seg_ctrl & 1),
        )
    elif code == CODE_EOF:
        if len(payload) != 8:
            raise PduParseError("EOF body must be 8 octets")
        checksum, file_size = struct.unpack(">II", payload)
        desc.update(checksum=checksum, file_size=file_size)
    elif code == CODE_ACK:
        if len(payload) != 2:
            raise PduParseError("ACK body must be 2 octets")
        acked_code, subtype = struct.unpack(">BB", payload)
        desc.update(acked_code=acked_code, subtype=subtype)
    elif code == CODE_NAK:
        if len(payload) < 8 or (len(payload) - 8) % 8 != 0:
            raise PduParseError("malformed NAK segment request list")
        scope_start, scope_end = struct.unpack(">II", payload[:8])
        requests = [
            tuple(struct.unpack(">II", payload[8 + 8 * i:16 + 8 * i]))
            for i in range((len(payload) - 8) // 8)
        ]
        desc.update(
            scope_start=scope_start, scope_end=scope_end, requests=requests
        )
    elif code == CODE_FINISHED:
        if len(payload) != 2:
            raise PduParseError("Finished body must be 2 octets")
        status, filestore_len = struct.unpack(">BB", payload)
        if filestore_len != 0:
            raise PduParseError("filestore responses are not supported")
        desc.update(status=status, condition_code=status >> 4)
    return desc
