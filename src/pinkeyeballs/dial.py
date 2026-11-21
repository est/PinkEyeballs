"""TCP handshakes: racing them, or timing every one of them.

:func:`race` is the Happy-Eyeballs stage of the library — candidates stream in
from the resolvers, attempts start on a stagger, and the first handshake that
lands wins while the rest are cancelled.

:func:`measure` is the opposite trade: keep nothing, cancel nothing, and report
the handshake time of every address as it lands, for callers that would rather
sort the measurements themselves.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import ssl
import statistics
from collections import deque
from collections.abc import AsyncGenerator, AsyncIterable, AsyncIterator, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import TracebackType
from typing import Final, Literal

from .dns import (
    DEFAULT_DNS_TIMEOUT,
    DEFAULT_RECORD_TYPES,
    DEFAULT_RESOLVERS,
    DEFAULT_SETTLE,
    DEFAULT_TTL_SLACK,
    Address,
    Answer,
    Lookup,
    ResolverSpec,
    normalize_resolvers,
    resolve_stream,
)
from .dns import (
    resolve as resolve_host,
)
from .errors import DialFailed, DialTimeout, NoAddresses, describe_error

DEFAULT_ATTEMPT_DELAY = 0.25
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_CONCURRENCY = 8

FirstFamily = Literal["ipv6", "ipv4"]


@dataclass(frozen=True, slots=True)
class Endpoint:
    """A concrete ``(ip, port)`` candidate for a TCP connection."""

    ip: str
    port: int
    ttl: int | None = None
    source: str | None = None

    def __post_init__(self) -> None:
        try:
            ipaddress.ip_address(self.ip)
        except ValueError as exc:
            raise ValueError(f"invalid IP address {self.ip!r}") from exc
        if not 0 < self.port < 65536:
            raise ValueError(f"port out of range: {self.port}")

    @classmethod
    def from_address(cls, address: Address, port: int) -> Endpoint:
        """Build an endpoint from a resolved :class:`Address`."""
        return cls(ip=address.ip, port=port, ttl=address.ttl, source=address.source)

    @property
    def family(self) -> int:
        """Address family, ``4`` or ``6``."""
        return ipaddress.ip_address(self.ip).version

    @property
    def sockaddr(self) -> tuple[str, int]:
        """Tuple accepted by ``asyncio.open_connection``."""
        return self.ip, self.port

    def __str__(self) -> str:
        if self.family == 6:
            return f"[{self.ip}]:{self.port}"
        return f"{self.ip}:{self.port}"


class AttemptStatus(StrEnum):
    """How one scheduled handshake ended."""

    WON = "won"
    FAILED = "failed"
    DISCARDED = "discarded"
    ABORTED = "aborted"


@dataclass(slots=True)
class _Schedule:
    """Mutable bookkeeping shared by the producer, the scheduler and attempts."""

    in_flight: int = 0
    next_index: int = 0
    exhausted: bool = False
    favor_v6: bool = True


@dataclass(frozen=True, slots=True)
class Attempt:
    """One scheduled connection attempt.

    ``scheduled`` and ``started`` are offsets in seconds from the start of the
    race; ``latency`` is measured from the attempt's own start, so it is the
    actual TCP handshake time.
    """

    endpoint: Endpoint
    status: AttemptStatus
    scheduled: float = 0.0
    started: float | None = None
    latency: float | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class Certificate:
    """The peer certificate of a TLS handshake, as far as the standard library reads it."""

    subject: str
    issuer: str
    expires: str
    """ISO-8601 date, in UTC."""
    days_left: int | None = None

    def __str__(self) -> str:
        return f"{self.subject} (expires in {self.days_left}d)" if self.days_left else self.subject


@dataclass(frozen=True, slots=True)
class TLS:
    """How to make the TLS handshake, when one is wanted."""

    server_hostname: str | None = None
    """Name to verify and to send as SNI; defaults to the endpoint address."""
    verify: bool = True
    alpn: tuple[str, ...] = ("h2", "http/1.1")

    def context(self) -> ssl.SSLContext:
        if self.verify:
            context = ssl.create_default_context()
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        if self.alpn:
            context.set_alpn_protocols(list(self.alpn))
        return context


@dataclass(frozen=True, slots=True)
class Handshake:
    """One endpoint that was timed, whether it worked or not.

    One attempt fills in ``connect`` (and ``tls``), several fill in ``samples``
    as well: each sample is the time of the handshake the caller asked for, and
    :attr:`latency` is their median.  ``connect``, ``tls`` and the TLS details
    describe the fastest attempt overall, which is the one worth looking at.
    """

    endpoint: Endpoint
    elapsed: float = 0.0
    """Wall time from the start of the measurement until this endpoint was done."""
    started: float = 0.0
    """Offset at which the first attempt on this endpoint began."""
    samples: tuple[float, ...] = ()
    """One timing per attempt that connected."""
    failures: int = 0
    """Attempts that did not connect."""
    connect: float | None = None
    tls: float | None = None
    error: str | None = None
    tls_version: str | None = None
    cipher: str | None = None
    alpn: str | None = None
    certificate: Certificate | None = None

    @property
    def succeeded(self) -> bool:
        """True when at least one attempt connected."""
        return bool(self.samples)

    @property
    def failed(self) -> bool:
        """True when no attempt connected."""
        return not self.samples

    @property
    def latency(self) -> float | None:
        """The handshake time: the median sample, or how long the failure took."""
        if self.samples:
            return statistics.median(self.samples)
        return self.elapsed if self.error is not None else None

    @property
    def total(self) -> float | None:
        """TCP and TLS handshake together, from the fastest attempt."""
        if self.connect is None:
            return None
        return self.connect + (self.tls or 0.0)

    def spread(self) -> tuple[float, float] | None:
        """Fastest and slowest sample, when there was more than one."""
        return (min(self.samples), max(self.samples)) if self.samples else None


@dataclass(slots=True)
class Connection:
    """The winning connection plus the full attempt report."""

    endpoint: Endpoint
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    attempts: tuple[Attempt, ...] = ()
    elapsed: float = 0.0
    lookup: Lookup | None = None

    async def aclose(self) -> None:
        """Close the socket and wait for the transport to finish."""
        self.writer.close()
        with contextlib.suppress(OSError):
            await self.writer.wait_closed()

    async def __aenter__(self) -> Connection:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()


async def _iterate(
    candidates: AsyncIterable[Endpoint] | Iterable[Endpoint],
) -> AsyncIterator[Endpoint]:
    if isinstance(candidates, AsyncIterable):
        async for candidate in candidates:
            yield candidate
    else:
        for candidate in candidates:
            yield candidate


async def race(
    candidates: AsyncIterable[Endpoint] | Iterable[Endpoint],
    *,
    attempt_delay: float = DEFAULT_ATTEMPT_DELAY,
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
    deadline: float | None = None,
    first_family: FirstFamily = "ipv6",
) -> Connection:
    """Dial candidates as they arrive and keep the first handshake that lands.

    Candidates may stream in (typically from :func:`pinkeyeballs.resolve_stream`).
    Attempt ``n`` starts ``attempt_delay`` seconds after attempt ``n - 1``;
    because the schedule is driven by arrival order, a late DNS answer still
    gets a slot as long as its scheduled time has not passed.  The first
    completed handshake wins and everything else is cancelled.
    """
    if attempt_delay < 0:
        raise ValueError("attempt_delay must not be negative")
    if connect_timeout <= 0:
        raise ValueError("connect_timeout must be positive")
    if deadline is not None and deadline <= 0:
        raise ValueError("deadline must be positive")
    if first_family not in {"ipv6", "ipv4"}:
        raise ValueError(f"first_family must be 'ipv6' or 'ipv4', got {first_family!r}")

    loop = asyncio.get_running_loop()
    started_at = loop.time()
    queues: dict[int, deque[Endpoint]] = {6: deque(), 4: deque()}
    seen: set[tuple[str, int]] = set()
    wake = asyncio.Event()
    winner: asyncio.Future[tuple[Endpoint, asyncio.StreamReader, asyncio.StreamWriter]] = (
        loop.create_future()
    )
    attempts: dict[int, Attempt] = {}
    planned: dict[int, Endpoint] = {}
    running: set[asyncio.Task[None]] = set()
    schedule_state = _Schedule(favor_v6=first_family == "ipv6")

    def enqueue(endpoint: Endpoint) -> None:
        key = (endpoint.ip, endpoint.port)
        if key in seen:
            return
        seen.add(key)
        queues[endpoint.family].append(endpoint)
        wake.set()

    def take() -> Endpoint | None:
        preferred = 6 if schedule_state.favor_v6 else 4
        fallback = 4 if schedule_state.favor_v6 else 6
        if queues[preferred]:
            schedule_state.favor_v6 = not schedule_state.favor_v6
            return queues[preferred].popleft()
        if queues[fallback]:
            return queues[fallback].popleft()
        return None

    def available() -> bool:
        return bool(queues[6] or queues[4])

    def snapshot() -> tuple[Attempt, ...]:
        report: list[Attempt] = []
        for index in range(schedule_state.next_index):
            attempt = attempts.get(index)
            if attempt is None:
                report.append(
                    Attempt(
                        endpoint=planned[index],
                        status=AttemptStatus.ABORTED,
                        scheduled=index * attempt_delay,
                    )
                )
            else:
                report.append(attempt)
        return tuple(report)

    async def produce() -> None:
        try:
            async for candidate in _iterate(candidates):
                enqueue(candidate)
        finally:
            schedule_state.exhausted = True
            wake.set()

    async def attempt(index: int, endpoint: Endpoint) -> None:
        scheduled = index * attempt_delay
        started = loop.time() - started_at
        try:
            async with asyncio.timeout(connect_timeout):
                reader, writer = await asyncio.open_connection(*endpoint.sockaddr)
        except asyncio.CancelledError:
            raise
        except (OSError, TimeoutError) as exc:
            attempts[index] = Attempt(
                endpoint=endpoint,
                status=AttemptStatus.FAILED,
                scheduled=scheduled,
                started=started,
                latency=loop.time() - started_at - started,
                error=describe_error(exc),
            )
            return

        latency = loop.time() - started_at - started
        if winner.done():
            writer.close()
            attempts[index] = Attempt(
                endpoint=endpoint,
                status=AttemptStatus.DISCARDED,
                scheduled=scheduled,
                started=started,
                latency=latency,
            )
            return

        attempts[index] = Attempt(
            endpoint=endpoint,
            status=AttemptStatus.WON,
            scheduled=scheduled,
            started=started,
            latency=latency,
        )
        winner.set_result((endpoint, reader, writer))

    def finished(task: asyncio.Task[None]) -> None:
        running.discard(task)
        schedule_state.in_flight -= 1
        wake.set()

    async def schedule() -> None:
        while not winner.done():
            endpoint = take()
            if endpoint is None:
                if schedule_state.exhausted and schedule_state.in_flight == 0:
                    winner.set_exception(DialFailed(snapshot()))
                    return
                wake.clear()
                if available():
                    continue
                await wake.wait()
                continue

            target = started_at + schedule_state.next_index * attempt_delay
            delay = target - loop.time()
            if delay > 0:
                await asyncio.sleep(delay)

            index = schedule_state.next_index
            schedule_state.next_index += 1
            planned[index] = endpoint
            schedule_state.in_flight += 1
            task = asyncio.create_task(attempt(index, endpoint), name=f"dial {endpoint}")
            running.add(task)
            task.add_done_callback(finished)

    producer = asyncio.create_task(produce(), name="candidate producer")
    scheduler = asyncio.create_task(schedule(), name="dial scheduler")
    try:
        async with asyncio.timeout(deadline):
            endpoint, reader, writer = await winner
    except TimeoutError as exc:
        raise DialTimeout(deadline or 0.0, snapshot()) from exc
    finally:
        producer.cancel()
        scheduler.cancel()
        for task in list(running):
            task.cancel()
        await asyncio.gather(producer, scheduler, *running, return_exceptions=True)

    return Connection(
        endpoint=endpoint,
        reader=reader,
        writer=writer,
        attempts=snapshot(),
        elapsed=loop.time() - started_at,
    )


def _certificate(ssl_object: ssl.SSLObject | ssl.SSLSocket | None) -> Certificate | None:
    """Read whatever the parsed peer certificate has to say."""
    if ssl_object is None:
        return None
    try:
        peer = ssl_object.getpeercert()
    except (ValueError, OSError):  # pragma: no cover - no certificate at all
        return None
    if not peer:
        # An unverified connection hands over an empty dict.
        return None
    subject = _distinguished_name(peer.get("subject", ()))
    issuer = _distinguished_name(peer.get("issuer", ()))
    not_after = peer.get("notAfter")
    expires = ""
    days_left: int | None = None
    if isinstance(not_after, str):
        try:
            when = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        except ValueError:  # pragma: no cover - exotic date format
            expires = not_after
        else:
            expires = when.date().isoformat()
            days_left = (when - datetime.now(UTC)).days
    return Certificate(subject=subject, issuer=issuer, expires=expires, days_left=days_left)


_NAME_ABBREVIATIONS: Final = {
    "commonName": "CN",
    "organizationName": "O",
    "organizationalUnitName": "OU",
    "countryName": "C",
    "stateOrProvinceName": "ST",
    "localityName": "L",
}


def _distinguished_name(value: object) -> str:
    """Flatten the nested tuples ``getpeercert`` returns into ``CN=x, O=y``."""
    if not isinstance(value, (tuple, list)):
        return ""
    parts: list[str] = []
    for rdn in value:
        if not isinstance(rdn, (tuple, list)):
            continue
        for item in rdn:
            if isinstance(item, (tuple, list)) and len(item) == 2:
                key = _NAME_ABBREVIATIONS.get(str(item[0]), str(item[0]))
                parts.append(f"{key}={item[1]}")
    return ", ".join(parts)


async def _time_handshake(
    endpoint: Endpoint, timeout: float, started_at: float, tls: TLS | None
) -> Handshake:
    """One attempt: TCP, plus TLS when a :class:`TLS` is given."""
    loop = asyncio.get_running_loop()
    started = loop.time() - started_at
    connect: float | None = None
    writer: asyncio.StreamWriter | None = None
    tls_time: float | None = None
    try:
        async with asyncio.timeout(timeout):
            before = loop.time()
            _reader, writer = await asyncio.open_connection(*endpoint.sockaddr)
            connect = loop.time() - before
            if tls is not None:
                before_tls = loop.time()
                await writer.start_tls(
                    tls.context(), server_hostname=tls.server_hostname or endpoint.ip
                )
                tls_time = loop.time() - before_tls
    except asyncio.CancelledError:
        if writer is not None:
            writer.close()
        raise
    except (OSError, TimeoutError) as exc:
        if writer is not None:
            writer.close()
        return Handshake(
            endpoint=endpoint,
            elapsed=loop.time() - started_at - started,
            started=started,
            connect=connect,
            error=describe_error(exc),
        )

    details: dict[str, object] = {}
    if tls is not None:
        ssl_object = writer.get_extra_info("ssl_object")
        details = {
            "tls_version": getattr(ssl_object, "version", lambda: None)(),
            "cipher": (getattr(ssl_object, "cipher", lambda: None)() or (None,))[0],
            "alpn": getattr(ssl_object, "selected_alpn_protocol", lambda: None)(),
            "certificate": _certificate(ssl_object),
        }
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()
    latency = tls_time if tls_time is not None else connect
    assert latency is not None  # a connection without a timing would be a bug
    return Handshake(
        endpoint=endpoint,
        elapsed=loop.time() - started_at - started,
        started=started,
        samples=(latency,),
        connect=connect,
        tls=tls_time,
        **details,  # type: ignore[arg-type]
    )


def _merge_attempts(endpoint: Endpoint, attempts: Sequence[Handshake]) -> Handshake:
    """Turn the samples of one endpoint into a single result."""
    good = [attempt for attempt in attempts if attempt.samples]
    failures = len(attempts) - len(good)
    if not good:
        return Handshake(
            endpoint=endpoint,
            elapsed=attempts[-1].elapsed,
            started=attempts[0].started,
            failures=failures,
            connect=attempts[-1].connect,
            error=attempts[0].error,
        )
    # The fastest attempt overall is the one whose details are worth showing.
    best = min(good, key=lambda attempt: attempt.total or 0.0)
    return Handshake(
        endpoint=endpoint,
        elapsed=attempts[-1].elapsed,
        started=attempts[0].started,
        samples=tuple(attempt.samples[0] for attempt in good),
        failures=failures,
        connect=best.connect,
        tls=best.tls,
        tls_version=best.tls_version,
        cipher=best.cipher,
        alpn=best.alpn,
        certificate=best.certificate,
    )


async def measure(
    candidates: AsyncIterable[Endpoint] | Iterable[Endpoint],
    *,
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    samples: int = 1,
    tls: TLS | None = None,
) -> AsyncGenerator[Handshake, None]:
    """Time a handshake for every candidate, yielding results as they land.

    Nothing is cancelled: every address gets its turn, at most ``concurrency``
    of them at once, and the results arrive in completion order.  Duplicate
    addresses are dialed once, each handshake is closed again as soon as it has
    been timed, and with ``samples`` above one the attempts of an address are
    run one after another so that they do not queue behind each other.

    Passing a :class:`TLS` times the TLS handshake too, which then becomes the
    number in :attr:`Handshake.latency`.
    """
    if connect_timeout <= 0:
        raise ValueError("connect_timeout must be positive")
    if concurrency < 1:
        raise ValueError(f"concurrency must be at least 1: {concurrency}")
    if samples < 1:
        raise ValueError(f"samples must be at least 1: {samples}")

    loop = asyncio.get_running_loop()
    started_at = loop.time()
    seen: set[tuple[str, int]] = set()
    work: asyncio.Queue[Endpoint | None] = asyncio.Queue(maxsize=concurrency)
    results: asyncio.Queue[Handshake | None] = asyncio.Queue()

    async def produce() -> None:
        try:
            async for candidate in _iterate(candidates):
                key = (candidate.ip, candidate.port)
                if key in seen:
                    continue
                seen.add(key)
                await work.put(candidate)
        finally:
            for _ in range(concurrency):
                await work.put(None)

    async def worker() -> None:
        while True:
            endpoint = await work.get()
            if endpoint is None:
                await results.put(None)
                return
            attempts = [
                await _time_handshake(endpoint, connect_timeout, started_at, tls)
                for _ in range(samples)
            ]
            await results.put(_merge_attempts(endpoint, attempts))

    tasks = [asyncio.create_task(produce(), name="candidate producer")]
    tasks += [
        asyncio.create_task(worker(), name=f"measure worker {index}")
        for index in range(concurrency)
    ]
    try:
        done = 0
        while done < concurrency:
            result = await results.get()
            if result is None:
                done += 1
                continue
            yield result
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@dataclass(frozen=True, slots=True)
class Dialer:
    """Configuration for :meth:`dial`."""

    resolvers: Iterable[ResolverSpec | str] = DEFAULT_RESOLVERS
    resolve_timeout: float = DEFAULT_DNS_TIMEOUT
    attempt_delay: float = DEFAULT_ATTEMPT_DELAY
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
    deadline: float | None = None
    first_family: FirstFamily = "ipv6"
    record_types: Iterable[int] = DEFAULT_RECORD_TYPES
    verify: bool = False
    slack: int = DEFAULT_TTL_SLACK
    settle: float | None = DEFAULT_SETTLE
    """How long to keep listening for late DNS replies; dialing cannot wait the
    whole query window, so this only hears out the first quarter second."""

    def __post_init__(self) -> None:
        object.__setattr__(self, "resolvers", normalize_resolvers(self.resolvers))
        object.__setattr__(self, "record_types", tuple(self.record_types))
        if self.resolve_timeout <= 0:
            raise ValueError("resolve_timeout must be positive")
        if self.attempt_delay < 0:
            raise ValueError("attempt_delay must not be negative")
        if self.connect_timeout <= 0:
            raise ValueError("connect_timeout must be positive")
        if self.deadline is not None and self.deadline <= 0:
            raise ValueError("deadline must be positive")
        if self.first_family not in {"ipv6", "ipv4"}:
            raise ValueError(f"first_family must be 'ipv6' or 'ipv4', got {self.first_family!r}")
        if self.slack < 1:
            raise ValueError(f"slack must be at least 1: {self.slack}")

    async def lookup(self, host: str) -> Lookup:
        """Resolve ``host`` through every resolver, without dialing."""
        return await resolve_host(
            host,
            self.resolvers,
            timeout=self.resolve_timeout,
            types=self.record_types,
            verify=self.verify,
            slack=self.slack,
            settle=self.settle,
        )

    async def dial(self, host: str, port: int) -> Connection:
        """Resolve and dial ``host:port``, keeping the fastest handshake."""
        loop = asyncio.get_running_loop()
        started = loop.time()
        answers: list[Answer] = []
        complete = False

        async def candidates() -> AsyncIterator[Endpoint]:
            nonlocal complete
            async for answer in resolve_stream(
                host,
                self.resolvers,
                timeout=self.resolve_timeout,
                types=self.record_types,
                verify=self.verify,
                slack=self.slack,
                settle=self.settle,
            ):
                answers.append(answer)
                for address in answer.addresses:
                    yield Endpoint.from_address(address, port)
            complete = True

        try:
            connection = await race(
                candidates(),
                attempt_delay=self.attempt_delay,
                connect_timeout=self.connect_timeout,
                deadline=self.deadline,
                first_family=self.first_family,
            )
        except DialFailed as exc:
            if not any(answer.addresses for answer in answers):
                raise NoAddresses(host, answers) from exc
            raise

        connection.lookup = Lookup(
            host=host,
            answers=tuple(answers),
            elapsed=loop.time() - started,
            complete=complete,
        )
        return connection


async def dial(
    host: str,
    port: int,
    *,
    resolvers: Iterable[ResolverSpec | str] = DEFAULT_RESOLVERS,
    resolve_timeout: float = DEFAULT_DNS_TIMEOUT,
    attempt_delay: float = DEFAULT_ATTEMPT_DELAY,
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
    deadline: float | None = None,
    first_family: FirstFamily = "ipv6",
    record_types: Iterable[int] = DEFAULT_RECORD_TYPES,
    verify: bool = False,
    slack: int = DEFAULT_TTL_SLACK,
    settle: float | None = DEFAULT_SETTLE,
) -> Connection:
    """Convenience wrapper around :meth:`Dialer.dial`."""
    return await Dialer(
        resolvers=resolvers,
        resolve_timeout=resolve_timeout,
        attempt_delay=attempt_delay,
        connect_timeout=connect_timeout,
        deadline=deadline,
        first_family=first_family,
        record_types=record_types,
        verify=verify,
        slack=slack,
        settle=settle,
    ).dial(host, port)


__all__ = [
    "DEFAULT_ATTEMPT_DELAY",
    "DEFAULT_CONCURRENCY",
    "DEFAULT_CONNECT_TIMEOUT",
    "TLS",
    "Attempt",
    "AttemptStatus",
    "Certificate",
    "Connection",
    "Dialer",
    "Endpoint",
    "FirstFamily",
    "Handshake",
    "dial",
    "measure",
    "race",
]
