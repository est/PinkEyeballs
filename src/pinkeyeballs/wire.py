"""DNS wire format: libc builds the query, libc walks the answer.

Both halves of the message handling are delegated to the C library through
:mod:`ctypes`, so the package needs no third-party DNS code and still relies on
the same routines ``dig`` uses:

* :c:func:`res_mkquery` assembles a query, including label escaping and IDNA
  handling (the symbol is ``res_9_mkquery`` on macOS and the BSDs);
* :c:func:`ns_initparse`, :c:func:`ns_parserr` and
  :c:func:`ns_name_uncompress` walk a reply, following compression pointers
  inside the C library.

Names come back from libresolv **without** a trailing dot (the root is ``"."``),
and that is the convention the rest of the package uses.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import functools
import secrets
import socket
import struct
from dataclasses import dataclass
from typing import Any, Final

from .errors import MessageFormatError, PlatformError, QueryBuildError

HEADER_SIZE: Final = 12
SECTIONS: Final = 4

OPCODE_QUERY: Final = 0
CLASS_IN: Final = 1

TYPE_A: Final = 1
TYPE_NS: Final = 2
TYPE_MD: Final = 3
TYPE_MF: Final = 4
TYPE_CNAME: Final = 5
TYPE_SOA: Final = 6
TYPE_MB: Final = 7
TYPE_MG: Final = 8
TYPE_MR: Final = 9
TYPE_PTR: Final = 12
TYPE_MX: Final = 15
TYPE_TXT: Final = 16
TYPE_AAAA: Final = 28
TYPE_SRV: Final = 33
TYPE_DNAME: Final = 39
TYPE_OPT: Final = 41
TYPE_DS: Final = 43
TYPE_RRSIG: Final = 46
TYPE_NSEC: Final = 47
TYPE_DNSKEY: Final = 48
TYPE_SVCB: Final = 64
TYPE_HTTPS: Final = 65
TYPE_ANY: Final = 255
TYPE_CAA: Final = 257

FLAG_QR: Final = 0x8000
FLAG_TC: Final = 0x0200
FLAG_RD: Final = 0x0100
FLAG_RA: Final = 0x0080

RCODES: Final[dict[int, str]] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
}

TYPE_NAMES: Final[dict[int, str]] = {
    TYPE_A: "A",
    TYPE_NS: "NS",
    TYPE_MD: "MD",
    TYPE_MF: "MF",
    TYPE_CNAME: "CNAME",
    TYPE_SOA: "SOA",
    TYPE_MB: "MB",
    TYPE_MG: "MG",
    TYPE_MR: "MR",
    TYPE_PTR: "PTR",
    TYPE_MX: "MX",
    TYPE_TXT: "TXT",
    TYPE_AAAA: "AAAA",
    TYPE_SRV: "SRV",
    TYPE_DNAME: "DNAME",
    TYPE_OPT: "OPT",
    TYPE_DS: "DS",
    TYPE_RRSIG: "RRSIG",
    TYPE_NSEC: "NSEC",
    TYPE_DNSKEY: "DNSKEY",
    TYPE_SVCB: "SVCB",
    TYPE_HTTPS: "HTTPS",
    TYPE_ANY: "ANY",
    TYPE_CAA: "CAA",
}

#: Record types whose RDATA is exactly one (possibly compressed) domain name.
SINGLE_NAME_TYPES: Final[frozenset[int]] = frozenset(
    {TYPE_NS, TYPE_MD, TYPE_MF, TYPE_CNAME, TYPE_MB, TYPE_MG, TYPE_MR, TYPE_PTR, TYPE_DNAME}
)

_MKQUERY_SYMBOLS: Final = ("res_mkquery", "res_9_mkquery", "__res_mkquery")
_INITPARSE_SYMBOLS: Final = ("ns_initparse", "res_9_ns_initparse", "__ns_initparse")
_PARSERR_SYMBOLS: Final = ("ns_parserr", "res_9_ns_parserr", "__ns_parserr")
_UNCOMPRESS_SYMBOLS: Final = (
    "ns_name_uncompress",
    "res_9_ns_name_uncompress",
    "__ns_name_uncompress",
)
_LIBRARY_CANDIDATES: Final = ("resolv", "libresolv.so.2", "/usr/lib/libresolv.dylib")

_NS_MAXDNAME: Final = 1025
_BUFFER_SLACK: Final = 16
_SECTION_NAMES: Final = ("question", "answer", "authority", "additional")

_U8 = ctypes.c_ubyte
_U8P = ctypes.POINTER(_U8)


def type_name(rtype: int) -> str:
    """Return the mnemonic for a record type, or ``TYPE<n>`` when unknown."""
    return TYPE_NAMES.get(rtype, f"TYPE{rtype}")


def rcode_name(rcode: int) -> str:
    """Return the mnemonic for a response code, or ``RCODE<n>`` when unknown."""
    return RCODES.get(rcode, f"RCODE{rcode}")


@functools.cache
def _libresolv() -> ctypes.CDLL:
    """Load libresolv once, trying the usual names for it."""
    failures: list[str] = []
    for candidate in _LIBRARY_CANDIDATES:
        path = ctypes.util.find_library(candidate) if candidate == "resolv" else candidate
        if not path:
            continue
        try:
            return ctypes.CDLL(path)
        except OSError as exc:  # pragma: no cover - depends on the platform
            failures.append(f"{path}: {exc}")
    raise PlatformError(
        "libresolv is not available"
        + (f" ({'; '.join(failures)})" if failures else "; this platform cannot resolve DNS")
    )


def _bind(library: ctypes.CDLL, symbols: tuple[str, ...], argtypes: tuple[Any, ...]) -> Any:
    """Bind the first symbol that exists and declare its C signature."""
    for symbol in symbols:
        function = getattr(library, symbol, None)
        if function is None:
            continue
        function.argtypes = argtypes
        function.restype = ctypes.c_int
        return function
    raise PlatformError(f"libresolv exports none of {', '.join(symbols)}")


@functools.cache
def _mkquery() -> Any:
    return _bind(
        _libresolv(),
        _MKQUERY_SYMBOLS,
        (
            ctypes.c_int,  # opcode
            ctypes.c_char_p,  # dname
            ctypes.c_int,  # class
            ctypes.c_int,  # type
            ctypes.c_char_p,  # data
            ctypes.c_int,  # datalen
            ctypes.c_char_p,  # newrr
            _U8P,  # buf
            ctypes.c_int,  # buflen
        ),
    )


@functools.cache
def _ns_library() -> tuple[Any, Any, Any]:
    """Bind the three libresolv functions used to walk a message."""
    library = _libresolv()
    initparse = _bind(
        library,
        _INITPARSE_SYMBOLS,
        (_U8P, ctypes.c_int, ctypes.POINTER(_NsMsg)),
    )
    parserr = _bind(
        library,
        _PARSERR_SYMBOLS,
        (ctypes.POINTER(_NsMsg), ctypes.c_int, ctypes.c_int, ctypes.POINTER(_NsRR)),
    )
    uncompress = _bind(
        library,
        _UNCOMPRESS_SYMBOLS,
        (_U8P, _U8P, _U8P, ctypes.c_char_p, ctypes.c_size_t),
    )
    return initparse, parserr, uncompress


class _NsMsg(ctypes.Structure):
    """C ``ns_msg`` from ``<arpa/nameser.h>``, with guard bytes."""

    _fields_ = [
        ("_msg", _U8P),
        ("_eom", _U8P),
        ("_id", ctypes.c_ushort),
        ("_flags", ctypes.c_ushort),
        ("_counts", ctypes.c_ushort * SECTIONS),
        ("_sections", _U8P * SECTIONS),
        ("_sect", ctypes.c_int),
        ("_rrnum", ctypes.c_int),
        ("_msg_ptr", _U8P),
        ("_guard", _U8 * 64),
    ]


class _NsRR(ctypes.Structure):
    """C ``ns_rr`` from ``<arpa/nameser.h>``, with guard bytes."""

    _fields_ = [
        ("name", ctypes.c_char * _NS_MAXDNAME),
        ("type", ctypes.c_ushort),
        ("rr_class", ctypes.c_ushort),
        ("ttl", ctypes.c_uint),
        ("rdlength", ctypes.c_ushort),
        ("rdata", _U8P),
        ("_guard", _U8 * 64),
    ]


def _wire_name(name: str) -> bytes:
    """Turn a hostname into the NUL-terminated C string ``res_mkquery`` wants."""
    if not isinstance(name, str):
        raise TypeError("name must be a str")
    if "\x00" in name:
        raise QueryBuildError("a domain name cannot contain NUL bytes")
    if name in {"", "."}:
        return b"."
    if not name.isascii():
        try:
            name = name.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise QueryBuildError(f"cannot IDNA-encode {name!r}: {exc}") from exc
    if not name.endswith("."):
        name += "."
    return name.encode("ascii")


def ascii_name(name: str) -> str:
    """Return the wire form of ``name``: IDNA-encoded, without the root dot."""
    text = _wire_name(name).decode("ascii")
    return "." if text == "." else text.rstrip(".")


def build_query(name: str, rtype: int = TYPE_A, *, qid: int | None = None) -> bytes:
    """Build a recursive DNS query for ``name``/``rtype``.

    The transaction ID is drawn from :mod:`secrets` unless ``qid`` is given, so
    the answer is hard to spoof.  The flags are not libc's: every query is a
    plain recursion-desired one, on every machine (see below).  The returned
    bytes are ready for UDP, or for a length-prefixed TCP exchange.
    """
    if not 0 <= rtype <= 0xFFFF:
        raise QueryBuildError(f"record type out of range: {rtype}")
    if qid is not None and not 0 <= qid <= 0xFFFF:
        raise QueryBuildError(f"transaction id out of range: {qid}")

    encoded = _wire_name(name)
    buffer = (_U8 * 512)()
    length = _mkquery()(
        OPCODE_QUERY,
        encoded,
        CLASS_IN,
        rtype,
        None,
        0,
        None,
        buffer,
        len(buffer),
    )
    if length <= 0:
        raise QueryBuildError(f"res_mkquery rejected {name!r}")
    message = bytearray(buffer[:length])
    message[0:2] = (secrets.randbits(16) if qid is None else qid).to_bytes(2, "big")
    # libc leaks the local resolver's options into the header: it sets AD when
    # the host has ``options trust-ad`` and CD when it has ``options dnssec``, so
    # the query would differ from machine to machine.  This package never reads
    # either bit back, and a measurement should not depend on the operator's
    # ``resolv.conf``, so the flags are ours: one standard query, recursion
    # desired, nothing else.
    message[2:4] = FLAG_RD.to_bytes(2, "big")
    return bytes(message)


@dataclass(frozen=True, slots=True)
class Question:
    """One entry of the question section."""

    name: str
    rtype: int
    rclass: int

    @property
    def type_name(self) -> str:
        return type_name(self.rtype)


@dataclass(frozen=True, slots=True)
class Record:
    """One resource record from any section."""

    name: str
    rtype: int
    rclass: int
    ttl: int
    data: bytes
    ip: str | None = None
    target: str | None = None

    @property
    def type_name(self) -> str:
        return type_name(self.rtype)


@dataclass(frozen=True, slots=True)
class Message:
    """A parsed DNS message."""

    id: int
    flags: int
    questions: tuple[Question, ...]
    answers: tuple[Record, ...]
    authorities: tuple[Record, ...]
    additionals: tuple[Record, ...]

    @property
    def qr(self) -> bool:
        """True for responses."""
        return bool(self.flags & FLAG_QR)

    @property
    def truncated(self) -> bool:
        """True when the sender could not fit the whole answer in one message."""
        return bool(self.flags & FLAG_TC)

    @property
    def rcode(self) -> int:
        """Response code (``0`` means NOERROR)."""
        return self.flags & 0x000F

    @property
    def rcode_name(self) -> str:
        return rcode_name(self.rcode)

    def records(self, rtype: int) -> tuple[Record, ...]:
        """Answer records of one type, in wire order."""
        return tuple(record for record in self.answers if record.rtype == rtype)


def _normalize_name(raw: bytes) -> str:
    """Turn a libresolv name into the package convention (no trailing dot)."""
    text = raw.decode("ascii", "backslashreplace")
    if text in {"", "."}:
        return "."
    if not text.endswith("."):
        return text
    backslashes = 0
    index = len(text) - 2
    while index >= 0 and text[index] == "\\":
        backslashes += 1
        index -= 1
    return text if backslashes % 2 else text[:-1]


def _parse_question(handle: _NsMsg, parserr: Any, section: int, index: int) -> Question:
    rr = _NsRR()
    if parserr(ctypes.byref(handle), section, index, ctypes.byref(rr)) < 0:
        raise MessageFormatError(f"libc could not parse {_SECTION_NAMES[section]} {index + 1}")
    return Question(_normalize_name(rr.name), rr.type, rr.rr_class)


def _parse_record(
    handle: _NsMsg,
    parserr: Any,
    uncompress: Any,
    base: Any,
    eom: Any,
    section: int,
    index: int,
) -> Record:
    rr = _NsRR()
    if parserr(ctypes.byref(handle), section, index, ctypes.byref(rr)) < 0:
        raise MessageFormatError(
            f"libc could not parse {_SECTION_NAMES[section]} record {index + 1}"
        )
    data = b"" if not rr.rdlength else ctypes.string_at(rr.rdata, rr.rdlength)

    ip: str | None = None
    target: str | None = None
    if rr.type == TYPE_A and len(data) == 4:
        ip = socket.inet_ntop(socket.AF_INET, data)
    elif rr.type == TYPE_AAAA and len(data) == 16:
        ip = socket.inet_ntop(socket.AF_INET6, data)
    elif rr.type in SINGLE_NAME_TYPES:
        name = ctypes.create_string_buffer(_NS_MAXDNAME)
        if uncompress(base, eom, rr.rdata, name, _NS_MAXDNAME) < 0:
            raise MessageFormatError(
                f"{type_name(rr.type)} record {index + 1} carries an unreadable name"
            )
        target = _normalize_name(name.value)

    return Record(
        name=_normalize_name(rr.name),
        rtype=rr.type,
        rclass=rr.rr_class,
        ttl=rr.ttl,
        data=data,
        ip=ip,
        target=target,
    )


def parse_message(data: bytes) -> Message:
    """Parse a complete DNS message, raising :class:`MessageFormatError`."""
    raw = bytes(data)
    if len(raw) < HEADER_SIZE:
        raise MessageFormatError("message is shorter than the 12-byte header")
    qid, flags = struct.unpack_from("!HH", raw, 0)
    counts = struct.unpack_from("!HHHH", raw, 4)

    initparse, parserr, uncompress = _ns_library()
    buffer = (_U8 * (len(raw) + _BUFFER_SLACK)).from_buffer_copy(raw + bytes(_BUFFER_SLACK))
    base = ctypes.cast(buffer, _U8P)
    eom = ctypes.cast(ctypes.byref(buffer, len(raw)), _U8P)
    handle = _NsMsg()
    if initparse(base, len(raw), ctypes.byref(handle)) < 0:
        raise MessageFormatError("libc rejected the message as malformed")
    if handle._id != qid or tuple(handle._counts) != counts:
        raise MessageFormatError(
            "libc read a different header than the wire; the C struct layout is not what we expect"
        )

    questions = tuple(_parse_question(handle, parserr, 0, index) for index in range(counts[0]))
    answers = tuple(
        _parse_record(handle, parserr, uncompress, base, eom, 1, index)
        for index in range(counts[1])
    )
    authorities = tuple(
        _parse_record(handle, parserr, uncompress, base, eom, 2, index)
        for index in range(counts[2])
    )
    additionals = tuple(
        _parse_record(handle, parserr, uncompress, base, eom, 3, index)
        for index in range(counts[3])
    )
    return Message(qid, flags, questions, answers, authorities, additionals)


__all__ = [
    "CLASS_IN",
    "FLAG_QR",
    "FLAG_RA",
    "FLAG_RD",
    "FLAG_TC",
    "HEADER_SIZE",
    "TYPE_A",
    "TYPE_AAAA",
    "TYPE_CNAME",
    "TYPE_NS",
    "TYPE_PTR",
    "Message",
    "Question",
    "Record",
    "ascii_name",
    "build_query",
    "parse_message",
    "rcode_name",
    "type_name",
]
