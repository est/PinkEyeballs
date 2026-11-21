"""Checks for DNS answers that did not come from where they claim.

Two independent tests, both cheap:

* a **canary**: a random name under the reserved ``.invalid`` zone cannot exist,
  so any address that comes back was invented — the classic NXDOMAIN hijack, and
  the one thing a middlebox cannot hide;
* a **hop ladder**: a reply's IP TTL says how far away the sender is
  (``initial - hops``), and lowering the hop limit until replies stop measures
  how far away it really is.  A TTL that claims a much longer path than the
  packet could have travelled was not written by the sender it names.

Neither test proves anything about an honest middlebox that answers with its own
TTL; comparing resolvers with :func:`pinkeyeballs.consensus.compare` is the tool
for that.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final, Literal

from .dns import (
    DEFAULT_PROBE_TIMEOUT,
    DEFAULT_RESOLVERS,
    DEFAULT_SETTLE,
    DEFAULT_TTL_SLACK,
    ResolverSpec,
    as_resolver,
    exchange,
    hop_budget,
    hop_distance,
    normalize_resolvers,
    query,
    random_invalid_name,
    walk_hop_limits,
)
from .errors import DnsTimeout, MessageFormatError, describe_error
from .wire import TYPE_A, build_query, parse_message, rcode_name

#: What a check concluded: a verdict, never a guess.
Verdict = Literal["intercepted", "clean", "inconclusive", "error"]

CANARY_TIMEOUT: Final = DEFAULT_PROBE_TIMEOUT


@dataclass(frozen=True, slots=True)
class Canary:
    """A name that cannot exist, asked on purpose.

    An address in the reply means something answered for a name that has no
    answer to give, so neither the resolver nor the path to it can be trusted.
    """

    resolver: ResolverSpec
    name: str
    rcode: int | None = None
    addresses: tuple[str, ...] = ()
    reply_ttl: int | None = None
    elapsed: float = 0.0
    error: str | None = None

    @property
    def fabricated(self) -> bool:
        """True when the impossible name came back with an address."""
        return bool(self.addresses)

    @property
    def verdict(self) -> Verdict:
        if self.fabricated:
            return "intercepted"
        if self.error is not None:
            return "error"
        return "clean"

    @property
    def rcode_name(self) -> str | None:
        return None if self.rcode is None else rcode_name(self.rcode)


@dataclass(frozen=True, slots=True)
class Probe:
    """Outcome of one hop-limited probe.

    In auto mode the resolver is first asked an impossible name: that reply
    gives both ``reply_ttl``/``hops`` and the canary verdict, and ``probed`` /
    ``answered`` are the ladder walked down from ``hops - 1``.  ``hop_limit`` is
    the rung the verdict rests on: the highest limit that got nothing when the
    answer looks honest, the lowest limit that still got a reply when it does
    not.  ``responder_hops`` is how far away the ladder says the answer is.

    With an explicit ``hop_limit`` no measurement is done: the ladder is that one
    probe, and any reply means something answered where the caller made it
    impossible.
    """

    resolver: ResolverSpec
    name: str
    verdict: Verdict = "inconclusive"
    hop_limit: int | None = None
    probed: tuple[int, ...] = ()
    answered: tuple[int, ...] = ()
    reply_ttl: int | None = None
    hops: int | None = None
    responder_hops: int | None = None
    slack: int = DEFAULT_TTL_SLACK
    fabricated: bool = False
    rcode: int | None = None
    addresses: tuple[str, ...] = ()
    elapsed: float = 0.0
    error: str | None = None

    @property
    def intercepted(self) -> bool:
        """True when the probe found something to disbelieve."""
        return self.verdict == "intercepted"

    @property
    def rcode_name(self) -> str | None:
        return None if self.rcode is None else rcode_name(self.rcode)


async def _ask(
    packet: bytes,
    spec: ResolverSpec,
    hop_limit: int,
    timeout: float,
) -> tuple[bool, int | None, tuple[str, ...], str | None]:
    """Send one hop-limited query and report what, if anything, came back."""
    try:
        datagram = await exchange(packet, spec, timeout=timeout, hop_limit=hop_limit)
    except (DnsTimeout, OSError):
        return False, None, (), None
    try:
        message = parse_message(datagram.data)
    except MessageFormatError as exc:
        return True, None, (), f"unparseable reply: {exc}"
    if message.id != int.from_bytes(packet[:2], "big"):
        return True, message.rcode, (), f"unexpected transaction id {message.id:#06x}"
    addresses = tuple(record.ip for record in message.answers if record.ip is not None)
    return True, message.rcode, addresses, None


async def canary(
    resolver: ResolverSpec | str,
    name: str | None = None,
    *,
    timeout: float = CANARY_TIMEOUT,
    settle: float | None = DEFAULT_SETTLE,
) -> Canary:
    """Ask ``resolver`` for a name that cannot exist.

    One query, and the cheapest way to catch NXDOMAIN hijacking.  Pass ``name``
    to ask something else; the check only means anything for names that are
    guaranteed to have no answer.
    """
    spec = as_resolver(resolver)
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    target = name or random_invalid_name()
    try:
        result = await query(target, spec, TYPE_A, timeout=timeout, settle=settle)
    except (OSError, DnsTimeout, MessageFormatError) as exc:
        return Canary(resolver=spec, name=target, error=describe_error(exc))
    return Canary(
        resolver=spec,
        name=target,
        rcode=result.rcode,
        addresses=result.hosts,
        reply_ttl=result.reply_ttl,
        elapsed=result.elapsed,
    )


async def canary_all(
    resolvers: Iterable[ResolverSpec | str] = DEFAULT_RESOLVERS,
    name: str | None = None,
    *,
    timeout: float = CANARY_TIMEOUT,
) -> tuple[Canary, ...]:
    """Canary every resolver in parallel."""
    specs = normalize_resolvers(resolvers)
    return tuple(await asyncio.gather(*(canary(spec, name, timeout=timeout) for spec in specs)))


async def probe(
    resolver: ResolverSpec | str,
    name: str | None = None,
    *,
    hop_limit: int | None = None,
    timeout: float = DEFAULT_PROBE_TIMEOUT,
    slack: int = DEFAULT_TTL_SLACK,
    settle: float | None = None,
    rtype: int = TYPE_A,
) -> Probe:
    """Ask ``resolver`` a question that a remote server should not receive.

    With ``hop_limit=None`` the resolver is asked an impossible name first; its
    TTL says how far away the sender claims to be, and the hop limit is walked
    down from one less than that until replies stop.  Passing ``hop_limit``
    yourself skips both and sends exactly one probe.
    """
    spec = as_resolver(resolver)
    if hop_limit is not None and not 1 <= hop_limit <= 255:
        raise ValueError(f"hop limit out of range: {hop_limit}")
    if slack < 1:
        raise ValueError(f"slack must be at least 1: {slack}")
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    own_name = name is None
    target = name or random_invalid_name()
    loop = asyncio.get_running_loop()
    started = loop.time()
    packet = build_query(target, rtype)
    rcode: int | None = None
    addresses: tuple[str, ...] = ()
    error: str | None = None

    if hop_limit is not None:
        responded, rcode, addresses, error = await _ask(packet, spec, hop_limit, timeout)
        return Probe(
            resolver=spec,
            name=target,
            verdict="intercepted" if responded else "clean",
            hop_limit=hop_limit,
            probed=(hop_limit,),
            answered=(hop_limit,) if responded else (),
            fabricated=own_name and bool(addresses),
            rcode=rcode,
            addresses=addresses,
            elapsed=loop.time() - started,
            error=error,
        )

    try:
        measured = await query(target, spec, rtype, timeout=timeout, settle=settle)
    except DnsTimeout:
        return Probe(
            resolver=spec,
            name=target,
            verdict="error",
            elapsed=loop.time() - started,
            error="no reply to an ordinary query",
        )
    except (OSError, MessageFormatError) as exc:
        return Probe(
            resolver=spec,
            name=target,
            verdict="error",
            elapsed=loop.time() - started,
            error=describe_error(exc),
        )

    reply_ttl = measured.reply_ttl
    hops = None if reply_ttl is None else hop_distance(reply_ttl)
    start = None if reply_ttl is None else hop_budget(reply_ttl)
    if own_name and measured.hosts:
        # Nothing left to measure: the answer to an impossible name is a lie.
        return Probe(
            resolver=spec,
            name=target,
            verdict="intercepted",
            reply_ttl=reply_ttl,
            hops=hops,
            fabricated=True,
            rcode=measured.rcode,
            addresses=measured.hosts,
            elapsed=loop.time() - started,
            error=f"an impossible name was answered with {', '.join(measured.hosts[:3])}",
        )
    if reply_ttl is None:
        return Probe(
            resolver=spec,
            name=target,
            elapsed=loop.time() - started,
            error="the platform did not report the reply TTL",
        )
    assert hops is not None
    if start is None:
        return Probe(
            resolver=spec,
            name=target,
            reply_ttl=reply_ttl,
            hops=hops,
            rcode=measured.rcode,
            elapsed=loop.time() - started,
            error=f"the resolver is {hops} hop(s) away, too close to tell apart from a proxy",
        )

    ladder = await walk_hop_limits(
        packet,
        spec,
        expected_hops=hops,
        start=start,
        slack=slack,
        timeout=min(timeout, DEFAULT_PROBE_TIMEOUT),
    )

    rcode = measured.rcode
    addresses = measured.hosts
    decisive = ladder.responder_hops if ladder.intercepted else ladder.limit
    if ladder.intercepted and ladder.answered:
        # One extra query at the decisive rung, purely to report what came back.
        _responded, rcode, addresses, error = await _ask(
            packet,
            spec,
            decisive if decisive is not None else min(ladder.answered),
            timeout,
        )

    return Probe(
        resolver=spec,
        name=target,
        verdict="intercepted" if ladder.intercepted else "clean",
        hop_limit=decisive,
        probed=ladder.probed,
        answered=ladder.answered,
        reply_ttl=reply_ttl,
        hops=hops,
        responder_hops=ladder.responder_hops,
        slack=slack,
        rcode=rcode,
        addresses=addresses,
        elapsed=loop.time() - started,
        error=error,
    )


async def probe_all(
    resolvers: Iterable[ResolverSpec | str] = DEFAULT_RESOLVERS,
    name: str | None = None,
    *,
    hop_limit: int | None = None,
    timeout: float = DEFAULT_PROBE_TIMEOUT,
    slack: int = DEFAULT_TTL_SLACK,
    rtype: int = TYPE_A,
) -> tuple[Probe, ...]:
    """Probe every resolver in parallel."""
    specs = normalize_resolvers(resolvers)
    return tuple(
        await asyncio.gather(
            *(
                probe(
                    spec,
                    name,
                    hop_limit=hop_limit,
                    timeout=timeout,
                    slack=slack,
                    rtype=rtype,
                )
                for spec in specs
            )
        )
    )


__all__ = [
    "CANARY_TIMEOUT",
    "Canary",
    "Probe",
    "Verdict",
    "canary",
    "canary_all",
    "probe",
    "probe_all",
]
