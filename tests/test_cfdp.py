import struct

import pytest

from app import cfdp


def test_crc32c_known_vectors():
    # Castagnoli check values for 1..4 zero bytes / small ASCII vector.
    assert cfdp.crc32c(b"") == 0x00000000
    assert cfdp.crc32c(b"123456789") == 0xE3069283


def test_header_round_trip():
    pdu = cfdp.metadata(0x0001, 0x0002, 0xABCD, 16)
    desc = cfdp.parse(pdu)
    assert desc["kind"] == "Metadata"
    assert desc["source"] == 1 and desc["destination"] == 2
    assert desc["sequence"] == 0xABCD
    assert desc["file_size"] == 16
    assert desc["direction"] == cfdp.DIR_TO_RECEIVER
    assert len(pdu) == 8 + 1 + 5 + 1 + 7 + 1 + 7  # header+code+body


def test_file_data_round_trip():
    raw = cfdp.file_data(1, 2, 3, 100, b"hello")
    desc = cfdp.parse(raw)
    assert desc["kind"] == "FileData"
    assert desc["offset"] == 100 and desc["data"] == b"hello"


def test_ack_encodes_direction_and_pair():
    desc = cfdp.parse(cfdp.ack(2, 1, 9, cfdp.CODE_EOF, cfdp.SUBTYPE_EOF))
    assert desc["direction"] == cfdp.DIR_TO_SENDER
    assert desc["acked_code"] == cfdp.CODE_EOF and desc["subtype"] == 0
    desc = cfdp.parse(
        cfdp.ack(1, 2, 9, cfdp.CODE_FINISHED, cfdp.SUBTYPE_FINISHED)
    )
    assert desc["direction"] == cfdp.DIR_TO_RECEIVER
    assert desc["acked_code"] == cfdp.CODE_FINISHED and desc["subtype"] == 1


def test_nak_round_trip():
    raw = cfdp.nak(2, 1, 5, 0, 64, [(10, 20), (30, 40)])
    desc = cfdp.parse(raw)
    assert desc["requests"] == [(10, 20), (30, 40)]
    assert (desc["scope_start"], desc["scope_end"]) == (0, 64)


def test_finished_round_trip():
    desc = cfdp.parse(cfdp.finished(2, 1, 5, 0))
    assert desc["kind"] == "Finished" and desc["status"] == 0


def test_eof_round_trip():
    desc = cfdp.parse(cfdp.eof(1, 2, 3, 0xDEADBEEF, 64))
    assert desc["checksum"] == 0xDEADBEEF and desc["file_size"] == 64


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\x10",
        b"\x00" + b"\x00" * 7,                 # wrong version
        b"\x14" + b"\x00" * 7,                 # unacknowledged mode
        b"\x11" + b"\x00" * 7,                 # reserved bits set
        b"\x18" + b"\x00" * 7 + b"\xff",       # unknown directive
        b"\x18" + b"\x00" * 6 + b"\x01",       # file data with no offset
    ],
)
def test_malformed_pdus_rejected(raw):
    with pytest.raises(cfdp.PduParseError):
        cfdp.parse(raw)


def test_metadata_over_64kib_rejected():
    body = struct.pack(">BI", 0, 64 * 1024 + 1)
    raw = cfdp.encode_header(0, 1, 2, 3, 0) + bytes([cfdp.CODE_METADATA]) + body
    with pytest.raises(cfdp.PduParseError):
        cfdp.parse(raw)
