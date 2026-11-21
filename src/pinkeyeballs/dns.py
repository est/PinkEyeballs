"""Resolving names through one or more recursive servers.

Each resolver gets its own socket, its own question and its own timeout, and
answers stream back in arrival order.  The IP TTL of every UDP reply is captured
into :attr:`Reply.reply_ttl`; ``verify=True`` adds the interception checks of
:func:`random_invalid_name` and :func:`walk_hop_limits`.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import ipaddress
import secrets
import socket
import struct
import sys
from collections.abc import AsyncGenerator, Iterable
from dataclasses import dataclass
from typing import Final

from .errors import DnsTimeout, MessageFormatError, describe_error
from .wire import (
    TYPE_A,
    TYPE_AAAA,
    TYPE_CNAME,
    Message,
    ascii_name,
    build_query,
    parse_message,
    rcode_name,
    type_name,
)

DEFAULT_RESOLVERS: Final[tuple[str, ...]] = ("1.1.1.1", "8.8.8.8", "9.9.9.9")
DEFAULT_RECORD_TYPES: Final[tuple[int, ...]] = (TYPE_A, TYPE_AAAA)
MAX_UDP_PAYLOAD: Final = 65535
DEFAULT_DNS_TIMEOUT: Final = 2.0
DEFAULT_PROBE_TIMEOUT: Final = 1.0

#: How long to keep listening after the last reply, before deciding that a
#: resolver has said all it is going to say.  ``None`` means "until the timeout
#: runs out", which is what a caller who suspects injection wants.
DEFAULT_SETTLE: Final = 0.25

#: Values a sender uses as its initial IP TTL / hop limit.
INITIAL_TTLS: Final = (64, 128, 255)

#: How many hops the reply TTL may overstate the real distance before a reply is
#: called injected.  Routes are not symmetric, so the two numbers never match
#: exactly; a few hops of drift is normal, ten is not.
DEFAULT_TTL_SLACK: Final = 6

_SOCKET_BYTES: Final = socket.CMSG_SPACE(64)
_IP_RECVTTL: Final = getattr(socket, "IP_RECVTTL", 12 if sys.platform == "linux" else 24)
_IPV6_RECVHOPLIMIT: Final = getattr(socket, "IPV6_RECVHOPLIMIT", 37)


@dataclass(frozen=True, slots=True)
class ResolverSpec:
    """A DNS server to query, optionally on a non-standard port."""

    address: str
    port: int = 53

    def __post_init__(self) -> None:
        if not isinstance(self.address, str):
            raise TypeError("resolver address must be a str")
        try:
            parsed = ipaddress.ip_address(self.address)
        except ValueError as exc:
            raise ValueError(f"invalid resolver address {self.address!r}") from exc
        if not 0 < self.port < 65536:
            raise ValueError(f"resolver port out of range: {self.port}")
        object.__setattr__(self, "address", str(parsed))

    @property
    def family(self) -> int:
        """Address family of the server, ``4`` or ``6``."""
        return ipaddress.ip_address(self.address).version

    def __str__(self) -> str:
        return self.address if self.port == 53 else f"{self.address}#{self.port}"


def as_resolver(resolver: ResolverSpec | str) -> ResolverSpec:
    """Coerce a resolver address into a :class:`ResolverSpec`."""
    return resolver if isinstance(resolver, ResolverSpec) else ResolverSpec(resolver)


def normalize_resolvers(
    resolvers: Iterable[ResolverSpec | str] = DEFAULT_RESOLVERS,
) -> tuple[ResolverSpec, ...]:
    """Accept strings or specs and return a non-empty tuple of specs."""
    specs = tuple(as_resolver(resolver) for resolver in resolvers)
    if not specs:
        raise ValueError("at least one resolver is required")
    return specs


def hop_distance(reply_ttl: int) -> int:
    """Best guess at how many hops away the sender of a reply is.

    A reply arrives with ``initial - hops`` in its TTL field, where ``initial``
    is one of :data:`INITIAL_TTLS`.  Picking the smallest candidate that is not
    below the observed value recovers the hop count.
    """
    if not 1 <= reply_ttl <= 255:
        raise ValueError(f"reply TTL out of range: {reply_ttl}")
    initial = next((candidate for candidate in INITIAL_TTLS if candidate >= reply_ttl), 255)
    return initial - reply_ttl


def hop_budget(reply_ttl: int) -> int | None:
    """Hop limit that a reply's own TTL says cannot reach the sender.

    This is the starting rung of the interception probe: one less than the
    distance the reply TTL implies.  ``None`` is returned when the sender looks
    zero or one hop away, where no hop limit can distinguish it from a middlebox
    on the same segment.
    """
    hops = hop_distance(reply_ttl)
    return hops - 1 if hops >= 2 else None


@dataclass(frozen=True, slots=True)
class HopLadder:
    """How far away the responder really is, measured by lowering the hop limit.

    A datagram reaches a host ``h`` hops away only when its hop limit is at least
    ``h + 1``.  Walking the limit down until replies stop therefore pins the
    responder's distance without assuming anything about routing symmetry, which
    is exactly what a reply TTL cannot do on its own.

    ``expected_hops`` is what the reply TTL implied; the two numbers agreeing is
    the sign of an honest answer, and a big disagreement means the TTL did not
    come from a sender that far away.
    """

    expected_hops: int
    slack: int = DEFAULT_TTL_SLACK
    probed: tuple[int, ...] = ()
    answered: tuple[int, ...] = ()

    @property
    def limit(self) -> int | None:
        """Highest hop limit that produced no reply, when the walk reached it."""
        return None if len(self.answered) == len(self.probed) else self.probed[-1]

    @property
    def responder_hops(self) -> int | None:
        """Upper bound on the distance to whatever answered, if anything did."""
        return min(self.answered) - 1 if self.answered else None

    @property
    def intercepted(self) -> bool:
        """True when replies keep coming from much closer than their TTL claims."""
        responder = self.responder_hops
        return responder is not None and self.expected_hops - responder > self.slack


def random_invalid_name() -> str:
    """A random name in the reserved ``.invalid`` zone.

    Nothing can legitimately resolve it, so any address that comes back was
    invented by the resolver or by something on the way to it.
    """
    return f"probe-{secrets.token_hex(6)}.invalid"


async def _impossible_answers(resolver: ResolverSpec, timeout: float) -> tuple[str, ...]:
    """Ask a name that cannot exist; return whatever addresses came back."""
    try:
        result = await query(
            random_invalid_name(), resolver, TYPE_A, timeout=timeout, settle=DEFAULT_SETTLE
        )
    except (OSError, DnsTimeout, MessageFormatError):
        return ()
    return result.hosts


@dataclass(frozen=True, slots=True)
class Address:
    """One address learned from a resolver."""

    ip: str
    ttl: int | None = None
    source: str | None = None

    def __post_init__(self) -> None:
        try:
            ipaddress.ip_address(self.ip)
        except ValueError as exc:
            raise ValueError(f"invalid IP address {self.ip!r}") from exc

    @property
    def family(self) -> int:
        """Address family, ``4`` or ``6``."""
        return ipaddress.ip_address(self.ip).version

    def __str__(self) -> str:
        return self.ip


@dataclass(frozen=True, slots=True)
class Datagram:
    """A raw UDP reply, before any parsing."""

    data: bytes
    reply_ttl: int | None = None
    elapsed: float = 0.0


@dataclass(frozen=True, slots=True)
class Poll:
    """Everything one UDP question heard back, in arrival order.

    A resolver answers a question once.  More than one answer to the same
    question, or an answer carrying the wrong transaction id, means somebody
    else is writing replies too — which is what DNS interception looks like from
    the client side.
    """

    datagrams: tuple[Datagram, ...] = ()
    strays: int = 0
    """Datagrams that did not carry the transaction id we sent."""
    mismatches: int = 0
    """Datagrams that did, but were not an answer to the question."""

    @property
    def repeated(self) -> bool:
        """True when the question was answered more than once."""
        return len(self.datagrams) > 1

    @property
    def poisoned(self) -> bool:
        """True when anything on the wire suggests an injected reply."""
        return self.repeated or self.strays > 0 or self.mismatches > 0


@dataclass(frozen=True, slots=True)
class Arrival:
    """One reply that came back for one question."""

    after: float
    """Seconds between sending the question and this reply."""
    addresses: tuple[Address, ...] = ()
    rcode: int = 0
    chosen: bool = False
    """True for the reply that was used: the last one, as the early ones are forged."""
    reply_ttl: int | None = None


@dataclass(frozen=True, slots=True)
class Evidence:
    """What the wire showed for one question, beyond the answer itself."""

    received: int = 1
    """How many datagrams answered the question."""
    strays: int = 0
    mismatches: int = 0
    alternatives: tuple[tuple[str, ...], ...] = ()
    """What the replies we did not use said, when they disagreed with ours."""
    arrivals: tuple[Arrival, ...] = ()
    """Every reply that came back, in arrival order."""

    @property
    def first(self) -> float:
        """Seconds until the first reply."""
        return self.arrivals[0].after if self.arrivals else 0.0

    @property
    def last(self) -> float:
        """Seconds until the last reply."""
        return self.arrivals[-1].after if self.arrivals else 0.0

    @property
    def contested(self) -> bool:
        """True when the replies to one question disagreed with each other."""
        return bool(self.alternatives)

    @property
    def poisoned(self) -> bool:
        """True when something here is worth reporting."""
        return self.contested or self.received > 1 or self.strays > 0 or self.mismatches > 0

    @property
    def spread(self) -> float:
        """Seconds between the first and the last reply."""
        return self.last - self.first

    def describe(self) -> str | None:
        """The evidence in one sentence, or nothing when there is none."""
        if not self.poisoned:
            return None
        parts: list[str] = []
        if self.contested:
            parts.append(
                f"{self.received} answers to one question, sent "
                f"{self.first * 1000:.1f}ms to {self.last * 1000:.1f}ms apart"
            )
            for alternative in self.alternatives:
                parts.append("not " + ", ".join(alternative))
        elif self.received > 1:
            parts.append(f"{self.received} identical answers to one question")
        if self.strays:
            parts.append(f"{self.strays} datagrams with a wrong transaction id")
        if self.mismatches:
            parts.append(f"{self.mismatches} that were not answers to the question")
        return "; ".join(parts)


@dataclass(frozen=True, slots=True)
class Exchange:
    """A parsed reply plus what the transport could tell us about it.

    ``message`` is the reply to use; ``datagrams`` is everything that came back,
    so a caller can see how many answers the question got and how far apart they
    arrived.
    """

    message: Message
    reply_ttl: int | None = None
    elapsed: float = 0.0
    used_tcp: bool = False
    evidence: Evidence | None = None
    datagrams: tuple[Datagram, ...] = ()

    @property
    def rcode(self) -> int:
        return self.message.rcode

    @property
    def hosts(self) -> tuple[str, ...]:
        """Addresses in the answer section, in wire order."""
        return tuple(record.ip for record in self.message.answers if record.ip is not None)


@dataclass(frozen=True, slots=True)
class Reply:
    """The outcome of one question (one record type) sent to one resolver.

    ``reply_ttl`` is the IP TTL of the UDP reply, ``hop_limit`` is the hop limit
    the verification verdict rests on, and ``verified`` is ``True`` for a reply
    whose TTL matches the distance the probe measured, ``False`` for an injected
    one, ``None`` when nothing was checked.
    """

    rtype: int
    rcode: int | None = None
    addresses: tuple[Address, ...] = ()
    cname: str | None = None
    error: str | None = None
    reply_ttl: int | None = None
    hop_limit: int | None = None
    verified: bool | None = None
    evidence: Evidence | None = None

    @property
    def type_name(self) -> str:
        return type_name(self.rtype)

    @property
    def rcode_name(self) -> str | None:
        """Mnemonic for :attr:`rcode`, when the reply carried one."""
        return None if self.rcode is None else rcode_name(self.rcode)

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def intercepted(self) -> bool:
        """True when this answer was shown not to come from where it claims."""
        return self.verified is False

    @property
    def contested(self) -> bool:
        """True when one question got several answers that disagreed."""
        return self.evidence is not None and self.evidence.contested

    @property
    def poisoned(self) -> bool:
        """True when the wire showed signs of injected replies."""
        return self.evidence is not None and self.evidence.poisoned

    @property
    def accepted(self) -> bool:
        """True when this reply may be used for dialing."""
        return self.error is None and self.verified is not False


@dataclass(frozen=True, slots=True)
class Answer:
    """Everything one resolver said about a hostname.

    ``elapsed`` runs until the listening window closed; :attr:`latency` is the
    time to the first reply, which is what "how fast was that resolver" means.
    ``fabricated`` is set when the resolver answered a name that cannot exist,
    which :func:`resolve_stream` only tests with ``verify=True``.
    """

    resolver: ResolverSpec
    replies: tuple[Reply, ...] = ()
    elapsed: float = 0.0
    fabricated: bool = False

    @property
    def addresses(self) -> tuple[Address, ...]:
        """Unique addresses across the accepted replies, in wire order."""
        unique: dict[str, Address] = {}
        for reply in self.replies:
            if not reply.accepted:
                continue
            for address in reply.addresses:
                unique.setdefault(address.ip, address)
        return tuple(unique.values())

    @property
    def error(self) -> str | None:
        """Errors from the individual questions, without repeating one."""
        errors: list[str] = []
        for reply in self.replies:
            if reply.error is not None and reply.error not in errors:
                errors.append(reply.error)
        return "; ".join(errors) if errors else None

    @property
    def rcode(self) -> int | None:
        """First non-NOERROR rcode, ``0`` when all succeeded, ``None`` on failure."""
        for reply in self.replies:
            if reply.rcode not in (None, 0):
                return reply.rcode
        return 0 if any(reply.rcode is not None for reply in self.replies) else None

    @property
    def latency(self) -> float:
        """Seconds until this resolver's first reply, not until the window closed."""
        firsts = [
            reply.evidence.first
            for reply in self.replies
            if reply.evidence is not None and reply.evidence.received
        ]
        return min(firsts) if firsts else self.elapsed

    @property
    def rcode_name(self) -> str | None:
        """Mnemonic for :attr:`rcode`, when any reply carried one."""
        rcode = self.rcode
        return None if rcode is None else rcode_name(rcode)

    @property
    def reply_ttl(self) -> int | None:
        """IP TTL of the first UDP reply, when the platform reports it."""
        for reply in self.replies:
            if reply.reply_ttl is not None:
                return reply.reply_ttl
        return None

    @property
    def intercepted(self) -> bool:
        """True when any question was answered by something closer than the server."""
        return any(reply.intercepted for reply in self.replies)

    @property
    def poisoned(self) -> bool:
        """True when the wire showed signs of injected replies for this resolver."""
        return any(reply.poisoned for reply in self.replies)

    @property
    def evidence(self) -> tuple[Evidence, ...]:
        """The wire evidence of every question that has any."""
        return tuple(reply.evidence for reply in self.replies if reply.evidence is not None)


@dataclass(frozen=True, slots=True)
class Lookup:
    """Merged view of all resolver answers."""

    host: str
    answers: tuple[Answer, ...] = ()
    elapsed: float = 0.0
    complete: bool = True

    @property
    def addresses(self) -> tuple[Address, ...]:
        """Unique addresses across resolvers; the first answer keeps the credit."""
        unique: dict[str, Address] = {}
        for answer in self.answers:
            for address in answer.addresses:
                unique.setdefault(address.ip, address)
        return tuple(unique.values())

    @property
    def responders(self) -> int:
        """Number of resolvers that returned at least one usable address."""
        return sum(1 for answer in self.answers if answer.addresses)

    @property
    def errors(self) -> tuple[str, ...]:
        return tuple(answer.error for answer in self.answers if answer.error is not None)

    @property
    def intercepted(self) -> tuple[ResolverSpec, ...]:
        """Resolvers that answered from closer than the real server."""
        return tuple(answer.resolver for answer in self.answers if answer.intercepted)

    @property
    def poisoned(self) -> tuple[ResolverSpec, ...]:
        """Resolvers whose replies showed signs of injection."""
        return tuple(answer.resolver for answer in self.answers if answer.poisoned)


def _canonical(name: str) -> str:
    text = name.casefold()
    if text.endswith(".") and not text.endswith("\\."):
        text = text[:-1]
    return text


def _enable_ttl_capture(sock: socket.socket, family: int) -> None:
    """Ask the kernel to attach the received TTL to each datagram."""
    try:
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, _IPV6_RECVHOPLIMIT, 1)
        else:
            sock.setsockopt(socket.IPPROTO_IP, _IP_RECVTTL, 1)
    except OSError:  # pragma: no cover - platform without TTL capture
        pass


def _set_hop_limit(sock: socket.socket, family: int, hop_limit: int) -> None:
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, hop_limit)
    else:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, hop_limit)


def _ttl_from_ancillary(ancdata: Iterable[tuple[int, int, bytes]]) -> int | None:
    """Pull the received TTL out of ``recvmsg`` control data.

    Linux reports it as an ``int`` under ``IP_TTL``, macOS as a single byte under
    ``IP_RECVTTL``; both arrive at level ``IPPROTO_IP`` (or ``IPPROTO_IPV6`` for
    a hop limit).
    """
    for level, _, data in ancdata:
        if level not in (socket.IPPROTO_IP, socket.IPPROTO_IPV6):
            continue
        if len(data) == 1:
            return data[0]
        if len(data) == 4:
            return int.from_bytes(data, sys.byteorder) & 0xFF
    return None


class _DatagramReader:
    """Await datagrams on a non-blocking socket via ``loop.add_reader``.

    asyncio has ``sock_recvfrom`` but no ``sock_recvmsg``, and the ancillary
    data is the whole point, so the socket is drained by the event loop and the
    results are handed to a queue.
    """

    __slots__ = ("_closed", "_loop", "_queue", "_sock")

    def __init__(self, sock: socket.socket, loop: asyncio.AbstractEventLoop) -> None:
        self._sock = sock
        self._loop = loop
        self._queue: asyncio.Queue[tuple[bytes, list[tuple[int, int, bytes]]] | OSError] = (
            asyncio.Queue()
        )
        self._closed = False
        loop.add_reader(sock.fileno(), self._ready)

    def _ready(self) -> None:
        try:
            data, ancdata, _flags, _address = self._sock.recvmsg(MAX_UDP_PAYLOAD, _SOCKET_BYTES)
        except (BlockingIOError, InterruptedError):
            return
        except OSError as exc:
            self._queue.put_nowait(exc)
            return
        self._queue.put_nowait((data, ancdata))

    async def get(self) -> tuple[bytes, list[tuple[int, int, bytes]]]:
        item = await self._queue.get()
        if isinstance(item, OSError):
            raise item
        return item

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._loop.remove_reader(self._sock.fileno())


async def listen(
    packet: bytes,
    resolver: ResolverSpec | str,
    *,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    settle: float | None = None,
    hop_limit: int | None = None,
) -> Poll:
    """Send ``packet`` over UDP and hear out everything that answers it.

    ``settle`` is how long to keep listening after the last answer before
    calling it a day; ``None`` keeps listening until ``timeout`` runs out, so a
    reply that arrives late — after an injected one — is still seen.  ``hop_limit``
    sets the IPv4 TTL / IPv6 hop limit of the query, which is how the
    interception probe expires a packet before it can reach a remote resolver.
    """
    spec = as_resolver(resolver)
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if settle is not None and settle < 0:
        raise ValueError(f"settle must not be negative: {settle}")
    if hop_limit is not None and not 1 <= hop_limit <= 255:
        raise ValueError(f"hop limit out of range: {hop_limit}")
    if len(packet) < 2:
        raise ValueError("packet is too short to carry a transaction id")

    loop = asyncio.get_running_loop()
    family = socket.AF_INET6 if spec.family == 6 else socket.AF_INET
    qid = int.from_bytes(packet[:2], "big")
    started = loop.time()
    deadline = started + timeout
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        _enable_ttl_capture(sock, family)
        if hop_limit is not None:
            _set_hop_limit(sock, family, hop_limit)
        await loop.sock_connect(sock, (spec.address, spec.port))
        await loop.sock_sendall(sock, packet)
        reader = _DatagramReader(sock, loop)
        try:
            datagrams: list[Datagram] = []
            strays = 0
            quiet_until: float | None = None
            while True:
                now = loop.time()
                if now >= deadline or (quiet_until is not None and now >= quiet_until):
                    break
                wait = deadline - now
                if quiet_until is not None:
                    wait = min(wait, quiet_until - now)
                try:
                    async with asyncio.timeout(wait):
                        data, ancdata = await reader.get()
                except TimeoutError:
                    break
                if len(data) >= 2 and int.from_bytes(data[:2], "big") != qid:
                    # Someone is guessing transaction ids at our port.
                    strays += 1
                    continue
                datagrams.append(
                    Datagram(
                        data=data,
                        reply_ttl=_ttl_from_ancillary(ancdata),
                        elapsed=loop.time() - started,
                    )
                )
                quiet_until = None if settle is None else loop.time() + settle
            if not datagrams:
                raise DnsTimeout(str(spec), timeout)
            return Poll(datagrams=tuple(datagrams), strays=strays)
        finally:
            reader.close()
    finally:
        sock.close()


async def exchange(
    packet: bytes,
    resolver: ResolverSpec | str,
    *,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    hop_limit: int | None = None,
) -> Datagram:
    """Send ``packet`` over UDP and return the first datagram answering it."""
    poll = await listen(packet, resolver, timeout=timeout, settle=0.0, hop_limit=hop_limit)
    return poll.datagrams[0]


async def _tcp_exchange(packet: bytes, spec: ResolverSpec, *, timeout: float) -> bytes:
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(spec.address, spec.port)
            try:
                writer.write(struct.pack("!H", len(packet)) + packet)
                await writer.drain()
                length = struct.unpack("!H", await reader.readexactly(2))[0]
                return await reader.readexactly(length)
            finally:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()
    except TimeoutError:
        raise DnsTimeout(str(spec), timeout) from None
    except asyncio.IncompleteReadError as exc:
        raise MessageFormatError("TCP reply ended before the message did") from exc


def _check_reply(packet: bytes, message: Message, name: str, rtype: int) -> None:
    expected = int.from_bytes(packet[:2], "big")
    if message.id != expected:
        raise MessageFormatError(
            f"reply carries transaction id {message.id:#06x}, expected {expected:#06x}"
        )
    if not message.qr:
        raise MessageFormatError("reply is not marked as a response")
    if not message.questions:
        return
    question = message.questions[0]
    if question.rtype != rtype or _canonical(question.name) != _canonical(ascii_name(name)):
        raise MessageFormatError(
            f"reply question {question.name}/{question.type_name} does not match "
            f"{ascii_name(name)}/{type_name(rtype)}"
        )


def _addresses_of(message: Message, rtype: int, source: str | None = None) -> tuple[Address, ...]:
    """The addresses a reply carries for the question that was asked.

    A resolver that answers an AAAA question with A records is confused or
    lying; either way those records are not an answer to the question.
    """
    return tuple(
        Address(record.ip, record.ttl, source)
        for record in message.answers
        if record.rtype == rtype and record.ip is not None
    )


def _signature(message: Message) -> tuple[object, ...]:
    """What an answer says, ignoring TTLs and anything else that may drift."""
    return (
        message.rcode,
        tuple((record.name, record.rtype, record.ip, record.target) for record in message.answers),
    )


def _answer_set(message: Message) -> tuple[str, ...]:
    """An answer in one line, for a report: its addresses, or why it has none."""
    said = tuple(
        str(record.ip or record.target or record.name)
        for record in message.answers
        if record.ip is not None or record.target is not None
    )
    return said or (rcode_name(message.rcode),)


async def query(
    name: str,
    resolver: ResolverSpec | str,
    rtype: int = TYPE_A,
    *,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    settle: float | None = None,
    hop_limit: int | None = None,
) -> Exchange:
    """Ask one resolver one question, and listen for every answer it gets.

    Injected replies arrive first, and the real one still arrives after them, so
    the whole window is heard out and the *last* reply is the one to use.  What
    the others said, and how many of them there were, comes back in
    :attr:`Exchange.evidence`.  Truncated answers fall back to TCP.
    """
    spec = as_resolver(resolver)
    loop = asyncio.get_running_loop()
    started = loop.time()
    packet = build_query(name, rtype)

    poll = await listen(packet, spec, timeout=timeout, settle=settle, hop_limit=hop_limit)
    parsed: list[tuple[Message, Datagram]] = []
    mismatches = poll.mismatches
    first_error: Exception | None = None
    for datagram in poll.datagrams:
        try:
            message = parse_message(datagram.data)
            _check_reply(packet, message, name, rtype)
        except MessageFormatError as exc:
            # It carried our transaction id but was not an answer to our
            # question: that is worth counting, not worth failing over.
            mismatches += 1
            first_error = first_error or exc
            continue
        parsed.append((message, datagram))
    if not parsed:
        raise first_error if first_error is not None else MessageFormatError("no usable reply")

    message, datagram = parsed[-1]
    reply_ttl = datagram.reply_ttl
    used_tcp = False
    if message.truncated:
        message = parse_message(await _tcp_exchange(packet, spec, timeout=timeout))
        _check_reply(packet, message, name, rtype)
        used_tcp = True
        # A TCP connection has its own TTL; the UDP measurement no longer applies.
        reply_ttl = None

    chosen = _signature(message)
    alternatives: list[tuple[str, ...]] = []
    for other, _ in parsed:
        if _signature(other) == chosen:
            continue
        said = _answer_set(other)
        if said not in alternatives:
            alternatives.append(said)

    arrivals = tuple(
        Arrival(
            after=datagram.elapsed,
            addresses=_addresses_of(reply, rtype, str(spec)),
            rcode=reply.rcode,
            chosen=index == len(parsed) - 1,
            reply_ttl=datagram.reply_ttl,
        )
        for index, (reply, datagram) in enumerate(parsed)
    )
    return Exchange(
        message=message,
        reply_ttl=reply_ttl,
        elapsed=loop.time() - started,
        used_tcp=used_tcp,
        datagrams=poll.datagrams,
        evidence=Evidence(
            received=len(poll.datagrams),
            strays=poll.strays,
            mismatches=mismatches,
            alternatives=tuple(alternatives),
            arrivals=arrivals,
        ),
    )


async def responds_at(
    packet: bytes,
    resolver: ResolverSpec | str,
    hop_limit: int,
    *,
    timeout: float = DEFAULT_PROBE_TIMEOUT,
) -> bool:
    """True when anything at all answers a datagram with this hop limit."""
    try:
        await exchange(packet, resolver, timeout=timeout, hop_limit=hop_limit)
    except (DnsTimeout, OSError):
        return False
    return True


async def walk_hop_limits(
    packet: bytes,
    resolver: ResolverSpec | str,
    *,
    expected_hops: int,
    start: int,
    slack: int = DEFAULT_TTL_SLACK,
    depth: int | None = None,
    timeout: float = DEFAULT_PROBE_TIMEOUT,
) -> HopLadder:
    """Lower the hop limit from ``start`` until replies stop coming back.

    The walk stops at the first hop limit that gets no reply, which is the
    evidence the ladder is built on: at that limit, and below it, nothing on
    this path answers.  ``depth`` bounds the work (defaulting to just what
    ``slack`` needs) so that a responder which answers everything cannot keep
    the walk going down to one.
    """
    if not 1 <= start <= 255:
        raise ValueError(f"hop limit out of range: {start}")
    if slack < 1:
        raise ValueError(f"slack must be at least 1: {slack}")
    if depth is None:
        depth = max(1, slack - 1)
    spec = as_resolver(resolver)
    probed: list[int] = []
    answered: list[int] = []
    lowest = max(1, start - depth)
    current = start
    while True:
        probed.append(current)
        if not await responds_at(packet, spec, current, timeout=timeout):
            break
        answered.append(current)
        if current <= lowest:
            break
        current -= 1
    return HopLadder(
        expected_hops=expected_hops,
        slack=slack,
        probed=tuple(probed),
        answered=tuple(answered),
    )


async def _verify_reply(
    host: str,
    resolver: ResolverSpec,
    rtype: int,
    reply_ttl: int,
    timeout: float,
    *,
    slack: int,
) -> HopLadder | None:
    """Test one reply's TTL against the hop limit that really reaches the sender."""
    start = hop_budget(reply_ttl)
    if start is None:
        return None
    return await walk_hop_limits(
        build_query(host, rtype),
        resolver,
        expected_hops=hop_distance(reply_ttl),
        start=start,
        slack=slack,
        timeout=min(timeout, DEFAULT_PROBE_TIMEOUT),
    )


async def _question_reply(
    host: str,
    resolver: ResolverSpec,
    rtype: int,
    *,
    timeout: float,
    verify: bool,
    slack: int,
    settle: float | None,
) -> Reply:
    try:
        result = await query(host, resolver, rtype, timeout=timeout, settle=settle)
    except (OSError, DnsTimeout, MessageFormatError) as exc:
        return Reply(rtype=rtype, error=describe_error(exc))

    message = result.message
    evidence = result.evidence
    addresses = _addresses_of(message, rtype, str(resolver))
    cname = next((record.target for record in message.answers if record.rtype == TYPE_CNAME), None)
    reply = Reply(
        rtype=rtype,
        rcode=message.rcode,
        addresses=addresses,
        cname=cname,
        reply_ttl=result.reply_ttl,
        evidence=evidence,
    )
    if not verify:
        return reply

    injected = evidence.describe() if evidence is not None else None
    if injected is not None:
        # Several answers to one question is not something a resolver does.
        return dataclasses.replace(reply, verified=False, error=f"injected replies: {injected}")
    if reply.reply_ttl is None:
        return reply

    ladder = await _verify_reply(host, resolver, rtype, reply.reply_ttl, timeout, slack=slack)
    if ladder is None:
        return reply
    if not ladder.intercepted:
        return dataclasses.replace(reply, hop_limit=ladder.limit, verified=True)
    responder = ladder.responder_hops
    return dataclasses.replace(
        reply,
        hop_limit=responder,
        verified=False,
        error=(
            f"intercepted: something {responder} hop(s) away answered while the reply TTL "
            f"claims {ladder.expected_hops} hops"
        ),
    )


async def _query_resolver(
    host: str,
    resolver: ResolverSpec,
    *,
    timeout: float,
    types: tuple[int, ...],
    verify: bool,
    slack: int,
    settle: float | None,
) -> Answer:
    loop = asyncio.get_running_loop()
    started = loop.time()
    questions = asyncio.gather(
        *(
            _question_reply(
                host,
                resolver,
                rtype,
                timeout=timeout,
                verify=verify,
                slack=slack,
                settle=settle,
            )
            for rtype in types
        )
    )
    if not verify:
        return Answer(
            resolver=resolver,
            replies=tuple(await questions),
            elapsed=loop.time() - started,
        )

    invented, asked = await asyncio.gather(_impossible_answers(resolver, timeout), questions)
    replies = list(asked)
    if invented:
        # One fabricated answer is enough to distrust everything this resolver said.
        detail = ", ".join(invented[:3])
        replies = [
            dataclasses.replace(
                reply,
                verified=False,
                error=f"fabricated: an impossible name was answered with {detail}",
            )
            for reply in replies
        ]
    return Answer(
        resolver=resolver,
        replies=tuple(replies),
        elapsed=loop.time() - started,
        fabricated=bool(invented),
    )


def _record_types(types: Iterable[int]) -> tuple[int, ...]:
    record_types = tuple(types)
    if not record_types:
        raise ValueError("at least one record type is required")
    for rtype in record_types:
        if not 0 <= rtype <= 0xFFFF:
            raise ValueError(f"record type out of range: {rtype}")
    return record_types


async def resolve_stream(
    host: str,
    resolvers: Iterable[ResolverSpec | str] = DEFAULT_RESOLVERS,
    *,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    types: Iterable[int] = DEFAULT_RECORD_TYPES,
    verify: bool = False,
    slack: int = DEFAULT_TTL_SLACK,
    settle: float | None = None,
) -> AsyncGenerator[Answer, None]:
    """Yield one :class:`Answer` per resolver, in the order they reply.

    Queries start together.  Cancelling the consumer cancels every pending
    query, which is what the dialer does once a handshake has won.

    With ``verify=True`` every resolver is also checked, one check per reply:
    its reply TTL is compared with the hop limit that really reaches it
    (:func:`walk_hop_limits`), and the resolver is asked a name that cannot exist
    so that an invented answer gives it away.  Anything that fails is marked
    :attr:`Reply.intercepted` and left out of the address list.  Verification is
    opt-in: it costs a handful of extra queries per reply.
    """
    specs = normalize_resolvers(resolvers)
    record_types = _record_types(types)
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    tasks = [
        asyncio.create_task(
            _query_resolver(
                host,
                spec,
                timeout=timeout,
                types=record_types,
                verify=verify,
                slack=slack,
                settle=settle,
            ),
            name=f"resolve {spec}",
        )
        for spec in specs
    ]
    try:
        for completed in asyncio.as_completed(tasks):
            yield await completed
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def resolve(
    host: str,
    resolvers: Iterable[ResolverSpec | str] = DEFAULT_RESOLVERS,
    *,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    types: Iterable[int] = DEFAULT_RECORD_TYPES,
    verify: bool = False,
    slack: int = DEFAULT_TTL_SLACK,
    settle: float | None = None,
) -> Lookup:
    """Query every resolver and wait for all of them."""
    loop = asyncio.get_running_loop()
    started = loop.time()
    answers = [
        answer
        async for answer in resolve_stream(
            host,
            resolvers,
            timeout=timeout,
            types=types,
            verify=verify,
            slack=slack,
            settle=settle,
        )
    ]
    return Lookup(host=host, answers=tuple(answers), elapsed=loop.time() - started)


__all__ = [
    "DEFAULT_DNS_TIMEOUT",
    "DEFAULT_PROBE_TIMEOUT",
    "DEFAULT_RECORD_TYPES",
    "DEFAULT_RESOLVERS",
    "DEFAULT_SETTLE",
    "DEFAULT_TTL_SLACK",
    "INITIAL_TTLS",
    "Address",
    "Answer",
    "Arrival",
    "Datagram",
    "Evidence",
    "Exchange",
    "HopLadder",
    "Lookup",
    "Poll",
    "Reply",
    "ResolverSpec",
    "as_resolver",
    "exchange",
    "hop_budget",
    "hop_distance",
    "listen",
    "normalize_resolvers",
    "query",
    "random_invalid_name",
    "resolve",
    "resolve_stream",
    "responds_at",
    "walk_hop_limits",
]
