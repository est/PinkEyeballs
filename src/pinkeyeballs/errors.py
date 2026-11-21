"""Exceptions raised by PinkEyeballs."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .dial import Attempt
    from .dns import Answer


class PinkEyeballsError(Exception):
    """Base class for every error this library raises on purpose."""


class PlatformError(PinkEyeballsError):
    """The C library on this platform lacks a DNS helper we need."""


class QueryBuildError(PinkEyeballsError):
    """A DNS query could not be built."""


class MessageFormatError(PinkEyeballsError):
    """A DNS message on the wire is malformed."""


class DnsTimeout(PinkEyeballsError):
    """A resolver did not answer in time."""

    def __init__(self, resolver: str, timeout: float) -> None:
        self.resolver = resolver
        self.timeout = timeout
        super().__init__(f"no reply from {resolver} within {timeout:.2f}s")


class NoAddresses(PinkEyeballsError):
    """Resolution finished without a single usable address."""

    def __init__(self, host: str, answers: Iterable[Answer] = ()) -> None:
        self.host = host
        self.answers = tuple(answers)
        details = "; ".join(
            f"{answer.resolver}: {answer.error or 'no addresses'}" for answer in self.answers
        )
        super().__init__(f"could not resolve {host!r}" + (f" ({details})" if details else ""))


class DialFailed(PinkEyeballsError):
    """Every scheduled handshake failed."""

    def __init__(self, attempts: Iterable[Attempt] = ()) -> None:
        self.attempts = tuple(attempts)
        failures = [
            f"{attempt.endpoint}: {attempt.error}"
            for attempt in self.attempts
            if attempt.error is not None
        ]
        message = "every connection attempt failed"
        super().__init__(message + (f": {'; '.join(failures)}" if failures else ""))


class DialTimeout(PinkEyeballsError):
    """The overall deadline expired before any handshake completed."""

    def __init__(self, timeout: float, attempts: Iterable[Attempt] = ()) -> None:
        self.timeout = timeout
        self.attempts = tuple(attempts)
        super().__init__(f"no connection succeeded within {timeout:.3f}s")


def describe_error(exc: BaseException) -> str:
    """Render an exception as ``Type: message`` for reports."""
    message = str(exc).strip()
    return f"{type(exc).__name__}: {message}" if message else type(exc).__name__
