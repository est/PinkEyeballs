"""Command line interface: one target, then the resolvers to ask.

    pinkeyeballs HOST[:PORT] [RESOLVER ...]

Without a port the answers are printed, one address per line.  With a port every
address gets a TCP handshake — and, with ``--tls``, a TLS one — and its time is
printed instead.  Results stream to stdout as they arrive, so they can be piped
into ``sort`` or ``grep``; anything about the *resolvers* (timeouts, NXDOMAIN,
injected replies) goes to stderr.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import json
import os
import re
import sys
import unicodedata
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from typing import Final

from . import __version__
from .dial import (
    DEFAULT_CONCURRENCY,
    DEFAULT_CONNECT_TIMEOUT,
    TLS,
    Certificate,
    Endpoint,
    Handshake,
    measure,
)
from .dns import (
    DEFAULT_DNS_TIMEOUT,
    DEFAULT_RECORD_TYPES,
    DEFAULT_RESOLVERS,
    DEFAULT_SETTLE,
    Address,
    Answer,
    Arrival,
    Evidence,
    Reply,
    ResolverSpec,
    hop_distance,
    resolve_stream,
)
from .errors import PinkEyeballsError
from .wire import TYPE_A, TYPE_AAAA, rcode_name

#: The markdown tables.  Every reply is a row of its own, in arrival order: a
#: second answer to one question is the thing worth seeing, so nothing is
#: merged away.  The widths come from what the run already knows — see
#: :func:`_table_widths`.
ADDRESS_COLUMNS: Final = ("address", "type", "ttl", "resolver", "ip ttl", "time", "note")

#: What the usual failures are called in a column, where there is no room for a
#: paragraph.  The full text stays in ``--json`` and in the ``-v`` notes.
ERROR_LABELS: Final = {
    "TimeoutError": "timeout",
    "ConnectionRefusedError": "refused",
    "ConnectionResetError": "reset",
    "ConnectionAbortedError": "aborted",
    "BrokenPipeError": "broken pipe",
    "SSLCertVerificationError": "certificate",
    "SSLError": "tls",
    "DnsTimeout": "no reply",
    "MessageFormatError": "malformed",
    "PlatformError": "no libresolv",
    "gaierror": "unresolved",
}

#: Widest note a row can carry, so the column is sized for the worst label
#: rather than for a paragraph.
NOTE_WIDTH: Final = max(
    len(label)
    for label in ("injected", "duplicate", "no reply", "no addresses", *ERROR_LABELS.values())
)

#: ``[Errno N]`` codes that mean the same thing on either platform.
ERRNO_LABELS: Final = {
    51: "unreachable",
    60: "timeout",
    61: "refused",
    65: "unreachable",
    101: "unreachable",
    104: "reset",
    110: "timeout",
    111: "refused",
    113: "unreachable",
}

EXAMPLES = """\
examples:
  pinkeyeballs example.com                    every address, one per line
  pinkeyeballs example.com 1.1.1.1 8.8.8.8    ... as these resolvers see it
  pinkeyeballs example.com:443 1.1.1.1        handshake time for every address
  pinkeyeballs example.com:443 --tls          ... and the TLS handshake
  pinkeyeballs example.com --markdown         one row per reply, in arrival order
  pinkeyeballs example.com:443 --markdown -v
  pinkeyeballs example.com:443 --verify       vet the answers before dialing
  pinkeyeballs -6 example.com                 only IPv6
  pinkeyeballs 1.1.1.1:443                    time a literal address, no DNS

stdout gets the results, one per line, as they arrive; stderr gets the resolver
diagnostics, always for failures and with -v for the rest (-q silences them).
--json prints one JSON object per line, --markdown one table.

exit codes: 0 something answered, 1 nothing did, 2 bad arguments
"""


def _port(text: str) -> int:
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid port: {text!r}") from exc
    if not 0 < value < 65536:
        raise argparse.ArgumentTypeError(f"port out of range: {value}")
    return value


def _positive(text: str) -> float:
    try:
        value = float(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid duration: {text!r}") from exc
    if value <= 0:
        raise argparse.ArgumentTypeError("duration must be positive")
    return value


def _non_negative(text: str) -> float:
    try:
        value = float(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid duration: {text!r}") from exc
    if value < 0:
        raise argparse.ArgumentTypeError("duration must not be negative")
    return value


def _count(text: str) -> int:
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid count: {text!r}") from exc
    if value < 1:
        raise argparse.ArgumentTypeError("count must be at least 1")
    return value


def _slack(text: str) -> int:
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid hop slack: {text!r}") from exc
    if value < 1:
        raise argparse.ArgumentTypeError("hop slack must be at least 1")
    return value


@dataclass(frozen=True, slots=True)
class Target:
    """A name or an IP literal, with the port to time if there is one."""

    host: str
    port: int | None = None

    @property
    def literal(self) -> bool:
        """True when the host is an IP address and no lookup is needed."""
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            return False
        return True

    def __str__(self) -> str:
        if self.port is None:
            return self.host
        return f"[{self.host}]:{self.port}" if ":" in self.host else f"{self.host}:{self.port}"


def _target(host: str, port: str | None = None) -> Target:
    if not host:
        raise argparse.ArgumentTypeError("a host is required")
    return Target(host) if port is None else Target(host, _port(port))


def parse_target(text: str) -> Target:
    """Parse ``HOST``, ``HOST:PORT``, ``[IPv6]:PORT`` or a bare IPv6 literal."""
    if text.startswith("["):
        host, separator, tail = text[1:].partition("]")
        if not separator:
            raise argparse.ArgumentTypeError(f"missing ']' in {text!r}")
        if not tail:
            return _target(host)
        if not tail.startswith(":"):
            raise argparse.ArgumentTypeError(f"expected ':PORT' after {host!r}, found {tail!r}")
        return _target(host, tail[1:])
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        return _target(host, port)
    # Either no port at all, or an IPv6 literal with nothing to split off.
    return _target(text)


def parse_resolver(text: str) -> ResolverSpec:
    """Parse ``ADDR`` and ``ADDR#PORT`` (``#`` so IPv6 needs no brackets)."""
    address, separator, port = text.rpartition("#")
    if not separator:
        address = text
    if address.startswith("[") and address.endswith("]"):
        address = address[1:-1]
    try:
        return ResolverSpec(address, _port(port) if separator else 53)
    except ValueError as exc:
        hint = " (to time a port, write the target as example.com:443)" if text.isdigit() else ""
        raise argparse.ArgumentTypeError(f"{exc}{hint}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pinkeyeballs",
        description="Resolve a name through several DNS servers at once, or time a "
        "handshake to every address they return.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("target", type=parse_target, help="HOST, or HOST:PORT to time handshakes")
    parser.add_argument(
        "resolvers",
        nargs="*",
        type=parse_resolver,
        metavar="RESOLVER",
        help="DNS servers to ask (default: 1.1.1.1, 8.8.8.8, 9.9.9.9)",
    )
    parser.add_argument(
        "-r",
        "--resolver",
        action="append",
        type=parse_resolver,
        metavar="ADDR[#PORT]",
        help="DNS server, repeatable; the same as listing them after the target",
    )
    parser.add_argument(
        "--resolve-timeout",
        type=_positive,
        default=DEFAULT_DNS_TIMEOUT,
        metavar="SECONDS",
        help=f"timeout per DNS question (default: {DEFAULT_DNS_TIMEOUT})",
    )
    parser.add_argument(
        "--settle",
        type=_non_negative,
        default=DEFAULT_SETTLE,
        metavar="SECONDS",
        help=f"keep listening this long after a reply, for replies that arrive late "
        f"behind an injected one (default: {DEFAULT_SETTLE})",
    )
    parser.add_argument(
        "--connect-timeout",
        type=_positive,
        default=DEFAULT_CONNECT_TIMEOUT,
        metavar="SECONDS",
        help=f"timeout per handshake (default: {DEFAULT_CONNECT_TIMEOUT})",
    )
    parser.add_argument(
        "--concurrency",
        type=_count,
        default=DEFAULT_CONCURRENCY,
        metavar="N",
        help=f"handshakes in flight (default: {DEFAULT_CONCURRENCY})",
    )
    parser.add_argument(
        "--samples",
        type=_count,
        default=1,
        metavar="N",
        help="handshakes per address, reported as their median (default: 1)",
    )
    parser.add_argument(
        "--tls",
        action="store_true",
        help="also make the TLS handshake, and report that time instead",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="with --tls, do not verify the certificate (and do not read it either)",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="canary and hop-limit check every answer before using it",
    )
    parser.add_argument(
        "--slack",
        type=_slack,
        default=6,
        metavar="HOPS",
        help="hops a reply TTL may overstate before it counts as injected (default: 6)",
    )
    family = parser.add_mutually_exclusive_group()
    family.add_argument("-4", dest="ipv4", action="store_true", help="ask for IPv4 addresses only")
    family.add_argument("-6", dest="ipv6", action="store_true", help="ask for IPv6 addresses only")
    parser.add_argument("-v", "--verbose", action="store_true", help="more columns, more stderr")
    parser.add_argument("-q", "--quiet", action="store_true", help="keep stderr to fatal errors")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="one JSON object per line")
    output.add_argument(
        "--markdown", action="store_true", help="one markdown table, as it comes in"
    )
    return parser


def _validate(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Reject option combinations argparse cannot express on its own."""
    target: Target = args.target
    if args.samples > 1 and target.port is None:
        parser.error("--samples needs a port: write the target as HOST:PORT")
    if args.tls and target.port is None:
        parser.error("--tls needs a port: write the target as HOST:PORT")
    if args.insecure and not args.tls:
        parser.error("--insecure only means something together with --tls")
    wanted = 4 if args.ipv4 else 6 if args.ipv6 else None
    if wanted is not None and target.literal:
        found = ipaddress.ip_address(target.host).version
        if found != wanted:
            parser.error(f"{target.host} is IPv{found}, but IPv{wanted} was asked for")


def _resolvers(args: argparse.Namespace) -> tuple[ResolverSpec, ...]:
    given = list(args.resolver or []) + list(args.resolvers)
    return tuple(given) if given else tuple(ResolverSpec(spec) for spec in DEFAULT_RESOLVERS)


def _family(args: argparse.Namespace) -> int | None:
    """The one address family that was asked for, if any."""
    return 4 if args.ipv4 else 6 if args.ipv6 else None


def _timing_table(args: argparse.Namespace) -> tuple[str, ...]:
    """The columns of a timing table, so that none of them is always empty."""
    columns = ["endpoint", "handshake"]
    if args.samples > 1:
        columns.append("samples")
    if args.tls:
        columns.extend(["tcp", "tls", "alpn"])
        if not args.insecure:
            columns.append("certificate")
    columns.extend(["resolver", "dns ttl", "ip ttl", "note"])
    return tuple(columns)


def _table_widths(
    columns: Sequence[str],
    *,
    resolvers: Sequence[ResolverSpec],
    args: argparse.Namespace,
    family: int | None,
) -> list[int]:
    """How wide each column has to be, from what the run already knows.

    The resolver addresses came from the command line, the timeouts bound every
    number in a cell, and the family bounds the addresses.  Only the DNS answers
    are open, and they are all IPv4 or all IPv6 by then.
    """
    ipv6 = family in (None, 6)
    address = 32 if ipv6 else 15
    port = len(str(args.target.port or 443))
    slowest = _milliseconds(args.connect_timeout)
    known = {
        "address": address,
        "endpoint": address + (5 if ipv6 else 4) + port,
        "resolver": max((_display_width(str(spec)) for spec in resolvers), default=0),
        "time": _display_width(_milliseconds(args.resolve_timeout)),
        "handshake": _display_width(slowest),
        "tcp": _display_width(slowest),
        "samples": _display_width(f"{args.samples}/{args.samples} ({slowest}-{slowest})"),
        "type": len("AAAA"),
        "ttl": 7,
        "dns ttl": 7,
        "ip ttl": len("255-255"),
        "note": NOTE_WIDTH,
        "tls": len("TLSv1.3"),
        "alpn": len("http/1.1"),
        "certificate": 22,
    }
    return [max(_display_width(column), known.get(column, 0)) for column in columns]


def _record_types(args: argparse.Namespace) -> tuple[int, ...]:
    if args.ipv4:
        return (TYPE_A,)
    if args.ipv6:
        return (TYPE_AAAA,)
    return tuple(DEFAULT_RECORD_TYPES)


def _ms(seconds: float | None) -> float | None:
    return None if seconds is None else round(seconds * 1000, 3)


def _milliseconds(seconds: float | None) -> str:
    return "-" if seconds is None else f"{seconds * 1000:.1f}ms"


def _short_error(error: str) -> str:
    """One or two words for a failure, for a column that is already narrow."""
    name, _, detail = error.partition(": ")
    name = name.split(" ", 1)[0]
    label = ERROR_LABELS.get(name)
    if label is None:
        found = re.search(r"\[Errno (\d+)\]", detail)
        label = ERRNO_LABELS.get(int(found.group(1))) if found else None
    if label is None:
        label = name.removesuffix("Error").lower() or "failed"
    return label


def _ttl_cell(reply_ttl: int | None) -> str:
    """The IP TTL as ``initial-hops``, which is what the hop ladder reads."""
    if reply_ttl is None:
        return ""
    hops = hop_distance(reply_ttl)
    return f"{reply_ttl + hops}-{hops}"


def _reply_ttl_note(reply_ttl: int | None) -> str | None:
    """The IP TTL of a reply, written as the initial value minus the hops it lost."""
    return None if reply_ttl is None else f"IP TTL {_ttl_cell(reply_ttl)}"


def _samples_cell(handshake: Handshake) -> str:
    total = len(handshake.samples) + handshake.failures
    if total <= 1:
        return ""
    spread = handshake.spread()
    cell = f"{len(handshake.samples)}/{total}"
    if spread is not None and len(handshake.samples) > 1:
        cell += f" ({spread[0] * 1000:.1f}-{spread[1] * 1000:.1f}ms)"
    return cell


def _display_width(text: str) -> int:
    """Columns a string takes on a terminal, counting wide characters twice."""
    width = 0
    for character in text:
        if unicodedata.combining(character):
            continue
        width += 2 if unicodedata.east_asian_width(character) in {"W", "F"} else 1
    return width


def _pad(text: str, width: int) -> str:
    """Pad to ``width`` columns, which keeps the pipes of a table in line."""
    return text + " " * max(0, width - _display_width(text))


def _clip(text: str, width: int) -> str:
    """Shorten to ``width`` columns, for values that have no natural bound."""
    if _display_width(text) <= width:
        return text
    kept = ""
    for character in text:
        if _display_width(kept + character) > width - 1:
            break
        kept += character
    return kept + "…"


def _reply_for(answer: Answer | None, family: int) -> Reply | None:
    """The reply an address of this family came from."""
    if answer is None:
        return None
    wanted = TYPE_A if family == 4 else TYPE_AAAA
    return next((reply for reply in answer.replies if reply.rtype == wanted), None)


def _reply_note_text(reply: Reply) -> str:
    """Why a question produced nothing worth putting in an address row."""
    if reply.error is not None:
        return _short_error(reply.error)
    return reply.rcode_name or "no addresses"


def _arrival_note(arrival: Arrival, evidence: Evidence) -> str:
    """What to say about one reply: nothing when it is the one we kept."""
    if arrival.chosen:
        if arrival.addresses:
            return ""
        return "no addresses" if arrival.rcode == 0 else rcode_name(arrival.rcode)
    return "injected" if evidence.contested else "duplicate"


def _evidence_short(evidence: Evidence) -> str:
    parts: list[str] = []
    if evidence.contested:
        parts.append("injected")
    elif evidence.received > 1:
        parts.append("duplicate")
    if evidence.strays:
        parts.append(f"{evidence.strays} wrong ids")
    if evidence.mismatches:
        parts.append(f"{evidence.mismatches} mismatched")
    return " · ".join(parts)


def _verification_note(reply: Reply) -> str | None:
    if reply.verified is False:
        return f"{reply.type_name} intercepted at hop limit {reply.hop_limit}"
    if reply.verified is True:
        return f"{reply.type_name} clean at hop limit {reply.hop_limit}"
    return None


def _certificate_cell(certificate: Certificate) -> str:
    """The certificate in a table cell: its name and how long it has left."""
    days = "" if certificate.days_left is None else f" ({certificate.days_left}d)"
    return f"{certificate.subject}{days}"


def _certificate_note(certificate: Certificate) -> str:
    parts = [str(certificate)]
    if certificate.issuer:
        parts.append(f"via {certificate.issuer}")
    return " ".join(parts)


def _evidence_note(answer: Answer) -> str | None:
    """What the wire showed, when it showed something a resolver does not do."""
    parts = [
        f"{reply.type_name}: {described}"
        for reply in answer.replies
        if reply.evidence is not None and (described := reply.evidence.describe()) is not None
    ]
    return "injected replies: " + "; ".join(parts) if parts else None


def _resolver_line(answer: Answer, *, verbose: bool) -> str:
    """One resolver's answer, in as few words as it takes."""
    parts: list[str] = []
    if answer.rcode not in (None, 0):
        parts.append(answer.rcode_name or f"rcode {answer.rcode}")
    cnames = sorted({reply.cname for reply in answer.replies if reply.cname})
    if cnames:
        parts.append("cname " + ", ".join(cnames))
    if answer.addresses:
        parts.append(", ".join(str(address) for address in answer.addresses))
    elif not parts:
        parts.append("no addresses")
    if verbose:
        note = _reply_ttl_note(answer.reply_ttl)
        if note is not None:
            parts.append(note)
        parts.extend(
            item
            for item in (_verification_note(reply) for reply in answer.replies)
            if item is not None
        )
    parts.append(_milliseconds(answer.latency))
    return f"{answer.resolver}: {', '.join(parts)}"


def _dns_columns(address: Address, answer: Answer) -> list[str]:
    """What DNS said about one address, for the -v columns."""
    return [
        str(address.source or "-"),
        "ttl unknown" if address.ttl is None else f"dns ttl {address.ttl}",
        _reply_ttl_note(answer.reply_ttl) or "IP TTL unknown",
    ]


def _timing_columns(
    handshake: Handshake, answer: Answer | None, address: Address | None
) -> list[str]:
    """The -v columns of one timed endpoint, prettiest first."""
    columns: list[str] = []
    samples = _samples_cell(handshake)
    if samples:
        columns.append(f"n={samples}")
    if address is None or answer is None:
        columns.append("literal address, no DNS")
    else:
        columns.extend(_dns_columns(address, answer))
    if handshake.connect is not None and (handshake.tls is not None or handshake.error is not None):
        columns.append(f"tcp {_ms(handshake.connect):.1f}ms")
    if handshake.tls is not None:
        version = handshake.tls_version or "tls"
        ciphers = " ".join(part for part in (handshake.cipher, handshake.alpn) if part is not None)
        columns.append(f"tls {version} {ciphers}".rstrip())
    if handshake.certificate is not None:
        columns.append(f"cert {_certificate_note(handshake.certificate)}")
    return columns


def _evidence_payload(evidence: Evidence | None) -> dict[str, object] | None:
    if evidence is None:
        return None
    return {
        "received": evidence.received,
        "contested": evidence.contested,
        "alternatives": [list(said) for said in evidence.alternatives],
        "strays": evidence.strays,
        "mismatches": evidence.mismatches,
        "first_ms": round(evidence.first * 1000, 3),
        "last_ms": round(evidence.last * 1000, 3),
    }


def _address_payload(address: Address, answer: Answer | None) -> dict[str, object]:
    reply = _reply_for(answer, address.family)
    return {
        "ip": address.ip,
        "family": address.family,
        "ttl": address.ttl,
        "source": address.source,
        "reply_ttl": None if answer is None else answer.reply_ttl,
        "rcode": None if reply is None else reply.rcode,
        "evidence": _evidence_payload(None if reply is None else reply.evidence),
    }


def _handshake_payload(handshake: Handshake, answer: Answer | None = None) -> dict[str, object]:
    endpoint = handshake.endpoint
    reply = _reply_for(answer, endpoint.family)
    certificate = handshake.certificate
    return {
        "ip": endpoint.ip,
        "family": endpoint.family,
        "port": endpoint.port,
        "source": endpoint.source,
        "started_ms": round(handshake.started * 1000, 3),
        "latency_ms": _ms(handshake.latency),
        "connect_ms": _ms(handshake.connect),
        "tls_ms": _ms(handshake.tls),
        "samples_ms": [_ms(sample) for sample in handshake.samples],
        "failures": handshake.failures,
        "rcode": None if reply is None else reply.rcode,
        "evidence": _evidence_payload(None if reply is None else reply.evidence),
        "tls_version": handshake.tls_version,
        "cipher": handshake.cipher,
        "alpn": handshake.alpn,
        "certificate": None
        if certificate is None
        else {
            "subject": certificate.subject,
            "issuer": certificate.issuer,
            "expires": certificate.expires,
            "days_left": certificate.days_left,
        },
        "error": handshake.error,
    }


class _Writer:
    """Results in one of three shapes, written as they come in.

    Text and JSON lines go out immediately.  A markdown table is printed row by
    row too — the header first, padded to fixed widths — so a run against a slow
    resolver still shows what it already has.
    """

    def __init__(
        self,
        *,
        json_mode: bool,
        markdown: bool,
        verbose: bool,
        quiet: bool,
        family: int | None = None,
    ) -> None:
        self.json = json_mode
        self.markdown = markdown
        self.verbose = verbose
        self.quiet = quiet
        self.family = family
        self.kind = ""
        self.columns: Sequence[str] = ()
        self.widths: list[int] = []
        self.seen: set[str] = set()
        self.notes: list[str] = []
        self.printed = 0

    # ------------------------------------------------------------------ table
    def table(self, kind: str, columns: Sequence[str], widths: Sequence[int]) -> None:
        """Start a table: its columns, and how wide each one is padded."""
        self.kind = kind
        self.columns = columns
        self.widths = list(widths)
        if not self.markdown:
            return
        self._print_row(columns)
        print("| " + " | ".join("-" * width for width in self.widths) + " |", flush=True)

    def _print_row(self, cells: Sequence[str]) -> None:
        padded = (_pad(cell, width) for cell, width in zip(cells, self.widths, strict=True))
        print("| " + " | ".join(padded) + " |", flush=True)

    def _width(self, column: str) -> int:
        columns = list(self.columns)
        if column not in columns:
            return len(column)
        index = columns.index(column)
        return self.widths[index] if index < len(self.widths) else len(column)

    def _row(self, values: dict[str, str]) -> None:
        self._print_row([values.get(column, "") for column in self.columns])

    # ---------------------------------------------------------------- results
    def literal(self, address: Address) -> None:
        """A target that is already an address: no DNS, no resolver."""
        self.printed += 1
        if self.markdown:
            self._row({"address": str(address)})
            return
        self._emit([str(address)], _address_payload(address, None))

    def answer(self, answer: Answer) -> None:
        """One resolver's answer: a row per reply, or a line per address."""
        if self.markdown:
            if self.kind == "address":
                self._timeline_rows(answer)
            return
        self.report(answer)
        for address in self._wanted(answer.addresses):
            if address.ip in self.seen:
                continue
            self.seen.add(address.ip)
            self.printed += 1
            text = [str(address)]
            if self.verbose:
                text.extend(_dns_columns(address, answer))
            self._emit(text, _address_payload(address, answer))

    def _timeline_rows(self, answer: Answer) -> None:
        resolver = str(answer.resolver)
        for reply in answer.replies:
            evidence = reply.evidence
            if evidence is None or not evidence.arrivals:
                self._row(
                    {"type": reply.type_name, "resolver": resolver, "note": _reply_note_text(reply)}
                )
                continue
            for arrival in evidence.arrivals:
                note = _arrival_note(arrival, evidence)
                addresses = self._wanted(arrival.addresses)
                if not addresses:
                    self._row(
                        {
                            "type": reply.type_name,
                            "resolver": resolver,
                            "time": _milliseconds(arrival.after),
                            "note": note,
                        }
                    )
                    continue
                for address in addresses:
                    self.printed += 1
                    self._row(
                        {
                            "address": str(address),
                            "type": reply.type_name,
                            "ttl": "" if address.ttl is None else str(address.ttl),
                            "resolver": resolver,
                            "ip ttl": _ttl_cell(arrival.reply_ttl),
                            "time": _milliseconds(arrival.after),
                            "note": note,
                        }
                    )

    def handshake(
        self, handshake: Handshake, answer: Answer | None, address: Address | None
    ) -> None:
        endpoint = handshake.endpoint
        reply = _reply_for(answer, endpoint.family)
        if handshake.error is None:
            self.printed += 1
        if self.markdown:
            self._row(
                {
                    "endpoint": str(endpoint),
                    "handshake": ""
                    if handshake.error is not None
                    else _milliseconds(handshake.latency),
                    "samples": _samples_cell(handshake),
                    "tcp": ""
                    if handshake.connect is None
                    or (handshake.tls is None and handshake.error is None)
                    else f"{_ms(handshake.connect):.1f}ms",
                    "tls": handshake.tls_version or "",
                    "cipher": handshake.cipher or "",
                    "alpn": handshake.alpn or "",
                    "certificate": ""
                    if handshake.certificate is None
                    else _clip(
                        _certificate_cell(handshake.certificate), self._width("certificate")
                    ),
                    "resolver": "" if address is None else str(address.source or ""),
                    "dns ttl": "" if address is None or address.ttl is None else str(address.ttl),
                    "ip ttl": "" if reply is None else _ttl_cell(reply.reply_ttl),
                    "note": "" if handshake.error is None else _short_error(handshake.error),
                }
            )
            return
        text = [
            str(endpoint),
            "" if handshake.latency is None else _milliseconds(handshake.latency),
        ]
        if handshake.error is not None:
            text[1] = "-"
            text.append(_short_error(handshake.error))
        if self.verbose:
            text.extend(_timing_columns(handshake, answer, address))
        self._emit(text, _handshake_payload(handshake, answer))
        if handshake.error is not None and self.verbose:
            self.note(f"{endpoint}: {handshake.error}")

    def report(self, answer: Answer) -> None:
        """What a resolver did, on stderr: always when it went wrong, else with -v."""
        if answer.error is not None:
            self.note(f"{answer.resolver}: {answer.error}")
            return
        injected = _evidence_note(answer)
        if injected is not None:
            self.note(f"{answer.resolver}: {injected}")
        if self.verbose or not answer.addresses:
            self.note(_resolver_line(answer, verbose=self.verbose))

    def dns_rows(self, answer: Answer) -> None:
        """The DNS side of a timing run, for the questions that became no endpoint."""
        if self.markdown and self.kind == "endpoint":
            for reply in answer.replies:
                evidence = reply.evidence
                if reply.addresses:
                    if evidence is not None and evidence.poisoned:
                        self._row(
                            {"resolver": str(answer.resolver), "note": _evidence_short(evidence)}
                        )
                    continue
                self._row({"resolver": str(answer.resolver), "note": _reply_note_text(reply)})
            return
        self.report(answer)

    # ----------------------------------------------------------------- output
    def note(self, message: str) -> None:
        if self.quiet:
            return
        if self.markdown:
            self.notes.append(message)
        else:
            print(message, file=sys.stderr, flush=True)

    def finish(self) -> None:
        if self.markdown and self.notes:
            print("", flush=True)
            for note in self.notes:
                print(f"- {note}", flush=True)

    def _emit(self, text: Sequence[str], payload: dict[str, object]) -> None:
        if self.json:
            print(json.dumps(payload), flush=True)
        else:
            print("\t".join(text), flush=True)

    def _wanted(self, addresses: Sequence[Address]) -> list[Address]:
        if self.family is None:
            return list(addresses)
        return [address for address in addresses if address.family == self.family]


def _literal_notes(target: Target, args: argparse.Namespace, writer: _Writer) -> None:
    if not writer.verbose:
        return
    writer.note(f"{target.host} is an IP literal, no resolver is asked")
    if args.verify:
        writer.note(f"{target}: there is nothing to verify for a literal address")


async def _addresses(
    target: Target, resolvers: tuple[ResolverSpec, ...], args: argparse.Namespace, writer: _Writer
) -> int:
    if target.literal:
        _literal_notes(target, args, writer)
        writer.literal(Address(target.host))
        return 0

    async for answer in resolve_stream(
        target.host,
        resolvers,
        timeout=args.resolve_timeout,
        types=_record_types(args),
        verify=args.verify,
        slack=args.slack,
        settle=args.settle,
    ):
        writer.answer(answer)
    return 0 if writer.printed else 1


async def _handshakes(
    target: Target, resolvers: tuple[ResolverSpec, ...], args: argparse.Namespace, writer: _Writer
) -> int:
    port = target.port
    assert port is not None  # the caller only gets here with a port
    seen: dict[tuple[str, int], tuple[Address, Answer | None]] = {}

    async def candidates() -> AsyncIterator[Endpoint]:
        if target.literal:
            _literal_notes(target, args, writer)
            yield Endpoint(target.host, port)
            return
        async for answer in resolve_stream(
            target.host,
            resolvers,
            timeout=args.resolve_timeout,
            types=_record_types(args),
            verify=args.verify,
            slack=args.slack,
            settle=args.settle,
        ):
            writer.dns_rows(answer)
            for address in writer._wanted(answer.addresses):
                seen.setdefault((address.ip, port), (address, answer))
                yield Endpoint.from_address(address, port)

    tls = None if not args.tls else TLS(server_hostname=target.host, verify=not args.insecure)
    async for handshake in measure(
        candidates(),
        connect_timeout=args.connect_timeout,
        concurrency=args.concurrency,
        samples=args.samples,
        tls=tls,
    ):
        endpoint = handshake.endpoint
        address, answer = seen.get((endpoint.ip, endpoint.port), (None, None))
        writer.handshake(handshake, answer, address)
    return 0 if writer.printed else 1


async def _run(args: argparse.Namespace) -> int:
    writer = _Writer(
        json_mode=args.json,
        markdown=args.markdown,
        verbose=args.verbose,
        quiet=args.quiet,
        family=_family(args),
    )
    target: Target = args.target
    resolvers = _resolvers(args)
    columns = ADDRESS_COLUMNS if target.port is None else _timing_table(args)
    widths = _table_widths(columns, resolvers=resolvers, args=args, family=_family(args))
    try:
        writer.table("address" if target.port is None else "endpoint", columns, widths)
        if target.port is None:
            return await _addresses(target, resolvers, args, writer)
        return await _handshakes(target, resolvers, args, writer)
    finally:
        writer.finish()


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``pinkeyeballs`` and ``python -m pinkeyeballs``."""
    parser = build_parser()
    args = parser.parse_args(argv)
    _validate(parser, args)
    try:
        return asyncio.run(_run(args))
    except BrokenPipeError:
        # Whatever was reading stdout went away, like `head` does.
        with contextlib.suppress(OSError):
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 141
    except (PinkEyeballsError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
