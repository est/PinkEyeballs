"""Fixtures for the test suite.

The interesting tests need a DNS server that misbehaves in a controlled way, so
this file grows a small message builder (independent of the library, so that
parsing is tested against something other than itself) and a fake resolver.

The fake resolver can also emulate *distance*: on loopback the IP TTL of a
datagram arrives unchanged, so it can answer only when the query's hop limit is
at least ``min_ttl``, exactly like a host that many hops away.  It can equally
well lie about its own TTL, which is what a hijacker does.
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
import socket
import ssl
import struct
import subprocess
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass, field

import pytest

from pinkeyeballs import ResolverSpec
from pinkeyeballs.wire import TYPE_A, TYPE_AAAA, TYPE_CNAME

IP_RECVTTL = getattr(socket, "IP_RECVTTL", 12)
IP_TTL = getattr(socket, "IP_TTL", 2)

# --------------------------------------------------------------------------- wire


def encode_name(name: str) -> bytes:
    """Encode a name the boring way, without compression."""
    if name in {"", "."}:
        return b"\x00"
    encoded = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        encoded.append(len(raw))
        encoded += raw
    return bytes(encoded) + b"\x00"


def question_end(query: bytes) -> int:
    """Offset just past the (single) question of ``query``."""
    offset = 12
    while True:
        length = query[offset]
        if length == 0:
            return offset + 5
        offset += length + 1


@dataclass(frozen=True)
class RR:
    """One answer record as the tests want to describe it."""

    name: str
    rtype: int
    rdata: bytes
    ttl: int = 300
    rclass: int = 1


def rr_a(name: str, ip: str, ttl: int = 300) -> RR:
    return RR(name, TYPE_A, socket.inet_aton(ip), ttl)


def rr_aaaa(name: str, ip: str, ttl: int = 300) -> RR:
    return RR(name, TYPE_AAAA, socket.inet_pton(socket.AF_INET6, ip), ttl)


def rr_cname(name: str, target: str, ttl: int = 300) -> RR:
    return RR(name, TYPE_CNAME, encode_name(target), ttl)


def build_reply(
    query: bytes,
    *,
    answers: Sequence[RR] = (),
    authorities: Sequence[RR] = (),
    additionals: Sequence[RR] = (),
    rcode: int = 0,
    truncated: bool = False,
    reply_id: int | None = None,
    flags: int = 0x8180,
) -> bytes:
    """Build a response to ``query``, compressing repeated names."""
    qid = struct.unpack_from("!H", query, 0)[0] if reply_id is None else reply_id
    header_flags = flags | (rcode & 0x0F) | (0x0200 if truncated else 0)
    body = bytearray(query[12 : question_end(query)])
    # The question name sits at offset 12; later records may point at it.
    offsets: dict[str, int] = {question_name(query): 12}

    def write_name(name: str) -> None:
        if name in offsets:
            body.extend(struct.pack("!H", 0xC000 | offsets[name]))
            return
        position = 12 + len(body)
        encoded = encode_name(name)
        body.extend(encoded)
        if len(encoded) + position <= 0x3FFF:
            offsets.setdefault(name, position)

    def write_section(records: Sequence[RR]) -> None:
        for record in records:
            write_name(record.name)
            rdata = record.rdata
            if record.rtype in {2, 5, 12}:  # NS, CNAME, PTR carry one name
                target = _name_of(rdata)
                if target is not None and target in offsets:
                    rdata = struct.pack("!H", 0xC000 | offsets[target])
            body.extend(struct.pack("!HHIH", record.rtype, record.rclass, record.ttl, len(rdata)))
            body.extend(rdata)

    write_section(answers)
    write_section(authorities)
    write_section(additionals)

    header = struct.pack(
        "!HHHHHH",
        qid,
        header_flags,
        1,
        len(answers),
        len(authorities),
        len(additionals),
    )
    return header + bytes(body)


def _name_of(encoded: bytes) -> str | None:
    """Decode an uncompressed name, or return ``None`` when it points elsewhere."""
    labels: list[str] = []
    offset = 0
    while offset < len(encoded):
        length = encoded[offset]
        if length & 0xC0:
            return None
        if length == 0:
            return ".".join(labels)
        try:
            labels.append(encoded[offset + 1 : offset + 1 + length].decode("ascii"))
        except UnicodeDecodeError:
            return None
        offset += length + 1
    return None


def question_name(query: bytes) -> str:
    """The name a query asks for."""
    labels: list[str] = []
    offset = 12
    while query[offset]:
        length = query[offset]
        labels.append(query[offset + 1 : offset + 1 + length].decode("ascii"))
        offset += length + 1
    return ".".join(labels)


# ------------------------------------------------------------------------ network


def _received_ttl(ancdata: Sequence[tuple[int, int, bytes]]) -> int | None:
    for level, _type, data in ancdata:
        if level != socket.IPPROTO_IP:
            continue
        if len(data) == 1:
            return data[0]
        if len(data) == 4:
            return int.from_bytes(data, "little") & 0xFF
    return None


def loopback_ttl_works() -> bool:
    """True when a loopback datagram keeps the hop limit it was sent with."""
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
        server.bind(("127.0.0.1", 0))
        client.settimeout(2.0)
        client.setsockopt(socket.IPPROTO_IP, IP_TTL, 7)
        client.sendto(b"probe", server.getsockname())
        _data, ancdata, _flags, _address = server.recvmsg(64, socket.CMSG_SPACE(64))
    except OSError:
        return False
    finally:
        server.close()
        client.close()
    return _received_ttl(ancdata) == 7


@pytest.fixture(scope="session")
def ttl_capture() -> bool:
    """Whether this machine reports TTLs on loopback at all."""
    return loopback_ttl_works()


@pytest.fixture
def requires_ttl(ttl_capture: bool) -> None:
    if not ttl_capture:
        pytest.skip("loopback does not report the IP TTL here")


@dataclass
class FakeResolver:
    """A tiny DNS server on loopback, optionally dishonest.

    It answers for the names that appear in ``answers`` and, by default, replies
    NXDOMAIN for anything else, so a probe asking an impossible name gets the
    honest answer.  ``unknown="answers"`` turns it into the kind of resolver
    that hands out an address for anything, which is what a hijack looks like.
    """

    answers: Sequence[RR] = ()
    rcode: int = 0
    unknown: str = "nxdomain"
    truncated: bool = False
    min_ttl: int = 1
    reply_ttl: int | None = None
    tcp: bool = False
    drop: bool = False
    reply_builder: Callable[[bytes], bytes] | None = None
    forgery: Callable[[bytes], bytes] | None = None
    """A reply to send *before* the real one, standing in for an injected one."""
    lag: float = 0.0
    """Seconds to wait before the real answer, so a forgery wins the race."""
    strays: int = 0
    """Datagrams to send with the wrong transaction id."""
    duplicate: int = 1
    """How many times to send the real answer."""
    queries: list[tuple[bytes, int | None]] = field(default_factory=list)
    saw_ttl: bool = False
    port: int = 0

    _udp: socket.socket | None = None
    _server: asyncio.Server | None = None

    async def start(self) -> FakeResolver:
        loop = asyncio.get_running_loop()
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
        if self.reply_ttl is not None:
            self._udp.setsockopt(socket.IPPROTO_IP, IP_TTL, self.reply_ttl)
        self._udp.bind(("127.0.0.1", 0))
        self._udp.setblocking(False)
        self.port = self._udp.getsockname()[1]
        loop.add_reader(self._udp.fileno(), self._on_datagram)
        if self.tcp:
            self._server = await asyncio.start_server(self._on_tcp, "127.0.0.1", self.port)
        return self

    @property
    def spec(self) -> ResolverSpec:
        return ResolverSpec("127.0.0.1", self.port)

    @property
    def address(self) -> str:
        return f"127.0.0.1#{self.port}"

    def _answer_for(self, query: bytes, ttl: int | None) -> bytes | None:
        self.queries.append((query, ttl))
        if ttl is not None:
            self.saw_ttl = True
        if self.drop:
            return None
        if ttl is not None and ttl < self.min_ttl:
            return None
        if self.reply_builder is not None:
            return self.reply_builder(query)
        known = {record.name.rstrip(".") for record in self.answers}
        if question_name(query) not in known and self.unknown != "answers":
            return build_reply(
                query, rcode=3 if self.unknown == "nxdomain" else 0, truncated=self.truncated
            )
        return build_reply(query, answers=self.answers, rcode=self.rcode, truncated=self.truncated)

    def _send(self, reply: bytes, address: tuple[str, int]) -> None:
        """Send something, unless the test already tore the resolver down."""
        sock = self._udp
        if sock is None:
            return
        with contextlib.suppress(OSError):
            sock.sendto(reply, address)

    def _on_datagram(self) -> None:
        assert self._udp is not None
        data, ancdata, _flags, address = self._udp.recvmsg(65535, socket.CMSG_SPACE(64))
        qid = int.from_bytes(data[:2], "big") if len(data) >= 2 else 0
        for _ in range(self.strays):
            self._send(build_reply(data, answers=self.answers, reply_id=qid ^ 0xFFFF), address)
        if self.forgery is not None:
            self._send(self.forgery(data), address)
        reply = self._answer_for(data, _received_ttl(ancdata))
        if reply is None:
            return
        for _ in range(self.duplicate):
            if self.lag:
                asyncio.get_running_loop().call_later(self.lag, self._send, reply, address)
            else:
                self._send(reply, address)

    async def _on_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                length = int.from_bytes(await reader.readexactly(2), "big")
                query = await reader.readexactly(length)
                self.queries.append((query, None))
                reply = (
                    self.reply_builder(query)
                    if self.reply_builder is not None
                    else build_reply(query, answers=self.answers, rcode=self.rcode)
                )
                writer.write(len(reply).to_bytes(2, "big") + reply)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    def close(self) -> None:
        if self._udp is not None:
            # The loop may already be gone when the test session ends.
            with contextlib.suppress(RuntimeError, ValueError):
                asyncio.get_running_loop().remove_reader(self._udp.fileno())
            self._udp.close()
            self._udp = None
        if self._server is not None:
            self._server.close()
            self._server = None


#: Type of the fixture that starts fake resolvers, for the tests' signatures.
MakeResolver = Callable[..., Awaitable[FakeResolver]]


@pytest.fixture
async def make_resolver() -> AsyncIterator[MakeResolver]:
    """Start fake resolvers and clean them up afterwards."""
    created: list[FakeResolver] = []

    async def make(**kwargs: object) -> FakeResolver:
        resolver = await FakeResolver(**kwargs).start()  # type: ignore[arg-type]
        created.append(resolver)
        return resolver

    yield make
    for resolver in created:
        resolver.close()


@pytest.fixture
async def echo_server() -> AsyncIterator[tuple[str, int]]:
    """A TCP server that accepts connections and closes them."""
    sockets: list[asyncio.Server] = []

    async def handler(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    sockets.append(server)
    host, port = server.sockets[0].getsockname()[:2]
    yield host, port
    for item in sockets:
        item.close()


@pytest.fixture
async def second_echo_server() -> AsyncIterator[tuple[str, int]]:
    """A second accepting endpoint on loopback, for multi-candidate tests."""

    async def handler(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    yield "127.0.0.1", port
    server.close()


@pytest.fixture(scope="session")
def tls_certificate(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, str]:
    """A throwaway self-signed certificate, or a skip when openssl is missing."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not available to make a test certificate")
    directory = tmp_path_factory.mktemp("certs")
    certificate, key = directory / "cert.pem", directory / "key.pem"
    result = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
        ],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:  # pragma: no cover - depends on the platform
        pytest.skip(f"openssl could not make a certificate: {result.stderr.decode()[:200]}")
    return str(certificate), str(key)


@pytest.fixture
async def tls_server(tls_certificate: tuple[str, str]) -> AsyncIterator[tuple[str, int]]:
    """A TLS server whose certificate nothing trusts."""
    certificate, key = tls_certificate
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)

    async def handler(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=context)
    port = server.sockets[0].getsockname()[1]
    yield "127.0.0.1", port
    server.close()


@pytest.fixture
def closed_port() -> int:
    """A port nothing listens on on loopback."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port
