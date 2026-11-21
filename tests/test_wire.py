"""Tests for query building and message parsing."""

from __future__ import annotations

import struct

import pytest

from pinkeyeballs.errors import MessageFormatError, QueryBuildError
from pinkeyeballs.wire import (
    FLAG_QR,
    TYPE_A,
    TYPE_AAAA,
    TYPE_CNAME,
    ascii_name,
    build_query,
    parse_message,
    rcode_name,
    type_name,
)
from tests.conftest import RR, build_reply, encode_name, rr_a, rr_aaaa, rr_cname


def test_build_query_header_and_question() -> None:
    query = build_query("example.com", TYPE_A, qid=0x1234)
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", query[:12])
    assert qid == 0x1234
    assert flags == 0x0100  # recursion desired
    assert (qdcount, ancount, nscount, arcount) == (1, 0, 0, 0)
    assert query[12:] == encode_name("example.com") + struct.pack("!HH", TYPE_A, 1)


def test_build_query_gets_a_fresh_id_each_time() -> None:
    ids = {int.from_bytes(build_query("example.com")[:2], "big") for _ in range(8)}
    assert len(ids) > 1


def test_build_query_accepts_ascii_and_idna_names() -> None:
    assert (
        build_query("例子.中国")[12:] == encode_name("xn--fsqu00a.xn--fiqs8s") + b"\x00\x01\x00\x01"
    )
    assert build_query(".")[12:] == b"\x00\x00\x01\x00\x01"


@pytest.mark.parametrize("name", ["a..b", "a" * 64 + ".com", "example.com.."])
def test_build_query_rejects_bad_names(name: str) -> None:
    with pytest.raises(QueryBuildError):
        build_query(name)


def test_ascii_name_normalizes() -> None:
    assert ascii_name("Example.COM.") == "Example.COM"
    assert ascii_name(".") == "."
    assert ascii_name("例子.中国") == "xn--fsqu00a.xn--fiqs8s"


def test_type_and_rcode_names() -> None:
    assert type_name(TYPE_AAAA) == "AAAA"
    assert type_name(1234) == "TYPE1234"
    assert rcode_name(3) == "NXDOMAIN"
    assert rcode_name(99) == "RCODE99"


def test_parse_reply_with_compressed_names() -> None:
    query = build_query("www.example.com", TYPE_A, qid=0xABCD)
    raw = build_reply(
        query,
        answers=[
            rr_cname("www.example.com", "www.example.com"),
            rr_a("www.example.com", "93.184.216.34", 42),
        ],
    )
    # The answer names must have been compressed into pointers.
    assert b"\xc0\x0c" in raw[12:]
    message = parse_message(raw)
    assert message.id == 0xABCD
    assert message.qr is True
    assert message.rcode == 0
    assert message.rcode_name == "NOERROR"
    assert message.truncated is False
    assert [(q.name, q.rtype) for q in message.questions] == [("www.example.com", TYPE_A)]
    assert [record.type_name for record in message.answers] == ["CNAME", "A"]
    assert message.answers[0].target == "www.example.com"
    assert message.answers[1].ip == "93.184.216.34"
    assert message.answers[1].ttl == 42
    assert message.answers[1].data == b"\x5d\xb8\xd8\x22"


def test_parse_aaaa_and_root_records() -> None:
    query = build_query(".", TYPE_AAAA)
    raw = build_reply(
        query,
        answers=[rr_aaaa(".", "2001:db8::1", 7)],
        authorities=[rr_a("a.root-servers.net", "198.41.0.4")],
    )
    message = parse_message(raw)
    assert message.questions[0].name == "."
    assert message.answers[0].name == "."
    assert message.answers[0].ip == "2001:db8::1"
    assert message.authorities[0].ip == "198.41.0.4"
    assert message.records(TYPE_AAAA) == message.answers


def test_parse_escapes_binary_labels() -> None:
    query = build_query("example.com", TYPE_A)
    # A label holding a byte that is not printable must come back escaped.
    rdata = b"\x06wei\xc2rd\x00"
    raw = build_reply(query, answers=[RR("example.com", TYPE_CNAME, rdata)])
    message = parse_message(raw)
    assert message.answers[0].target == "wei\\194rd"


def test_parse_reads_flags_and_rcode() -> None:
    query = build_query("example.com", TYPE_A)
    message = parse_message(build_reply(query, rcode=3))
    assert message.rcode == 3
    assert message.rcode_name == "NXDOMAIN"
    assert message.truncated is False
    assert parse_message(build_reply(query, truncated=True)).truncated is True
    assert parse_message(build_reply(query, flags=0x0180)).qr is False


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\x00" * 11,
        # claims one answer that is not there
        struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0) + b"\x07example\x03com\x00\x00\x01\x00\x01",
        # trailing garbage behind a complete message
        build_reply(build_query("example.com", TYPE_A)) + b"\x00\x00",
    ],
)
def test_parse_rejects_malformed_messages(raw: bytes) -> None:
    with pytest.raises(MessageFormatError):
        parse_message(raw)


def test_parse_rejects_compression_loops() -> None:
    query = build_query("example.com", TYPE_A)
    raw = build_reply(query, answers=[rr_a("example.com", "1.2.3.4")])
    # Point the answer's name at the pointer itself.
    offset = raw.index(b"\xc0\x0c")
    looping = raw[:offset] + struct.pack("!H", 0xC000 | offset) + raw[offset + 2 :]
    with pytest.raises(MessageFormatError):
        parse_message(looping)


def test_parse_keeps_raw_rdata() -> None:
    query = build_query("example.com", TYPE_A)
    message = parse_message(build_reply(query, answers=[rr_a("example.com", "1.2.3.4")]))
    assert message.answers[0].data == b"\x01\x02\x03\x04"
    assert message.answers[0].rclass == 1


def test_two_messages_can_be_parsed_repeatedly() -> None:
    query = build_query("example.com", TYPE_AAAA)
    raw = build_reply(query, answers=[rr_aaaa("example.com", "::1")])
    first = parse_message(raw)
    second = parse_message(raw)
    assert first == second


def test_parse_message_matches_hand_built_compression() -> None:
    query = build_query("a.root-servers.net", TYPE_A)
    raw = build_reply(query, answers=[rr_a("a.root-servers.net", "198.41.0.4")])
    assert parse_message(raw).answers[0].name == "a.root-servers.net"
    assert parse_message(raw).flags & FLAG_QR
