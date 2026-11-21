"""Tests for racing TCP handshakes."""

from __future__ import annotations

import asyncio
import ssl
import statistics
from collections.abc import AsyncIterator

import pytest

from pinkeyeballs import (
    TLS,
    Address,
    AttemptStatus,
    Certificate,
    Connection,
    Dialer,
    Endpoint,
    NoAddresses,
    dial,
    measure,
    race,
)
from pinkeyeballs.dial import DEFAULT_ATTEMPT_DELAY
from pinkeyeballs.errors import DialFailed, DialTimeout
from pinkeyeballs.wire import TYPE_A
from tests.conftest import MakeResolver, rr_a


def test_endpoint_helpers() -> None:
    endpoint = Endpoint("127.0.0.1", 443)
    assert str(endpoint) == "127.0.0.1:443"
    assert endpoint.family == 4
    assert endpoint.sockaddr == ("127.0.0.1", 443)
    assert str(Endpoint("2606:2800::1", 443)) == "[2606:2800::1]:443"
    assert Endpoint.from_address(Address("1.2.3.4", 60, "1.1.1.1"), 80) == Endpoint(
        "1.2.3.4", 80, 60, "1.1.1.1"
    )
    with pytest.raises(ValueError):
        Endpoint("nope", 443)
    with pytest.raises(ValueError):
        Endpoint("1.2.3.4", 0)


async def test_race_keeps_the_first_handshake(
    echo_server: tuple[str, int], closed_port: int
) -> None:
    host, port = echo_server
    candidates = [Endpoint(host, closed_port), Endpoint(host, port)]
    async with await race(candidates, attempt_delay=0.01) as connection:
        assert connection.endpoint.port == port
        assert connection.endpoint.source is None
        assert connection.elapsed > 0
        statuses = {attempt.endpoint.port: attempt.status for attempt in connection.attempts}
        assert statuses[port] is AttemptStatus.WON
        assert statuses[closed_port] is AttemptStatus.FAILED
        failed = next(item for item in connection.attempts if item.status is AttemptStatus.FAILED)
        assert "ConnectionRefused" in (failed.error or "")
        assert failed.latency is not None
        assert failed.started is not None


async def test_race_schedules_attempts_on_a_stagger(
    echo_server: tuple[str, int], closed_port: int
) -> None:
    host, port = echo_server
    candidates = [Endpoint(host, closed_port), Endpoint(host, port)]
    connection = await race(candidates, attempt_delay=0.05)
    try:
        assert [attempt.scheduled for attempt in connection.attempts] == [0.0, 0.05]
    finally:
        await connection.aclose()


async def test_race_discards_a_handshake_that_loses(
    echo_server: tuple[str, int], second_echo_server: tuple[str, int]
) -> None:
    # Both attempt at once, so the loser has to be closed again.
    _host, first_port = echo_server
    _second, second_port = second_echo_server
    candidates = [Endpoint("127.0.0.1", first_port), Endpoint("127.0.0.1", second_port)]
    connection = await race(candidates, attempt_delay=0.0)
    try:
        statuses = [attempt.status for attempt in connection.attempts]
        assert len(statuses) == 2
        assert statuses.count(AttemptStatus.WON) == 1
        # The loser either landed too late or was cancelled while dialing.
        loser = next(status for status in statuses if status is not AttemptStatus.WON)
        assert loser in {AttemptStatus.DISCARDED, AttemptStatus.ABORTED}
    finally:
        await connection.aclose()


async def test_race_deduplicates_addresses(echo_server: tuple[str, int], closed_port: int) -> None:
    host, port = echo_server
    candidates = [Endpoint(host, closed_port), Endpoint(host, closed_port), Endpoint(host, port)]
    connection = await race(candidates, attempt_delay=0.0)
    try:
        assert len(connection.attempts) == 2
    finally:
        await connection.aclose()


async def test_race_fails_when_every_attempt_fails(closed_port: int) -> None:
    with pytest.raises(DialFailed) as info:
        await race([Endpoint("127.0.0.1", closed_port)], attempt_delay=0.0)
    attempts = info.value.attempts
    assert [attempt.status for attempt in attempts] == [AttemptStatus.FAILED]
    assert attempts[0].error is not None
    assert "127.0.0.1" in str(info.value)


async def test_race_on_an_empty_candidate_list() -> None:
    with pytest.raises(DialFailed) as info:
        await race([], attempt_delay=0.0)
    assert info.value.attempts == ()


async def test_race_times_out_on_a_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    async def never_connects(*args: object, **kwargs: object) -> None:
        await asyncio.sleep(30)

    # 127.0.0.2 is not an assigned address here, so a real connect would hang.

    monkeypatch.setattr("asyncio.open_connection", never_connects)
    with pytest.raises(DialTimeout) as info:
        await race(
            [Endpoint("127.0.0.1", 9), Endpoint("127.0.0.2", 9)],
            attempt_delay=0.0,
            deadline=0.05,
        )
    assert info.value.timeout == 0.05
    assert len(info.value.attempts) >= 1
    assert "no connection succeeded within" in str(info.value)


@pytest.mark.parametrize(
    ("first_family", "expected"),
    [
        ("ipv6", ["::1", "127.0.0.1", "127.0.0.2", "127.0.0.3"]),
        ("ipv4", ["127.0.0.1", "::1", "127.0.0.2", "127.0.0.3"]),
    ],
)
async def test_race_interleaves_families(
    closed_port: int, monkeypatch: pytest.MonkeyPatch, first_family: str, expected: list[str]
) -> None:
    async def refused(*args: object, **kwargs: object) -> None:
        raise ConnectionRefusedError(61, "Connect call failed")

    monkeypatch.setattr("asyncio.open_connection", refused)
    candidates = [
        Endpoint("127.0.0.1", closed_port),
        Endpoint("127.0.0.2", closed_port),
        Endpoint("127.0.0.3", closed_port),
        Endpoint("::1", closed_port),
    ]
    with pytest.raises(DialFailed) as info:
        await race(
            candidates,
            attempt_delay=0.0,
            deadline=5.0,
            first_family=first_family,  # type: ignore[arg-type]
        )
    assert [attempt.endpoint.ip for attempt in info.value.attempts] == expected


async def test_race_validates_arguments() -> None:
    with pytest.raises(ValueError):
        await race([], attempt_delay=-1)
    with pytest.raises(ValueError):
        await race([], connect_timeout=0)
    with pytest.raises(ValueError):
        await race([], deadline=0)
    with pytest.raises(ValueError):
        await race([], first_family="ipv5")  # type: ignore[arg-type]


async def test_dialer_defaults_and_validation() -> None:
    dialer = Dialer()
    assert dialer.attempt_delay == DEFAULT_ATTEMPT_DELAY
    assert dialer.verify is False
    assert dialer.first_family == "ipv6"
    assert dialer.slack == 6
    with pytest.raises(ValueError):
        Dialer(connect_timeout=0)
    with pytest.raises(ValueError):
        Dialer(attempt_delay=-0.1)
    with pytest.raises(ValueError):
        Dialer(deadline=-1)
    with pytest.raises(ValueError):
        Dialer(resolve_timeout=0)
    with pytest.raises(ValueError):
        Dialer(first_family="either")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        Dialer(resolvers=[])


async def test_dial_resolves_then_connects(
    make_resolver: MakeResolver, echo_server: tuple[str, int]
) -> None:
    _host, port = echo_server
    resolver = await make_resolver(answers=[rr_a("example.com", "127.0.0.1", 30)])
    connection = await dial(
        "example.com",
        port,
        resolvers=[resolver.spec],
        attempt_delay=0.0,
        record_types=[TYPE_A],
    )
    try:
        assert connection.endpoint == Endpoint("127.0.0.1", port, 30, resolver.address)
        assert connection.lookup is not None
        assert connection.lookup.complete is True
        assert connection.lookup.elapsed > 0
        assert [address.ip for address in connection.lookup.addresses] == ["127.0.0.1"]
    finally:
        await connection.aclose()


async def test_dialer_lookup_does_not_connect(make_resolver: MakeResolver) -> None:
    resolver = await make_resolver(answers=[rr_a("example.com", "127.0.0.1")])
    lookup = await Dialer(resolvers=[resolver.spec], record_types=[TYPE_A]).lookup("example.com")
    assert [address.ip for address in lookup.addresses] == ["127.0.0.1"]


async def test_dial_raises_no_addresses_when_dns_fails(make_resolver: MakeResolver) -> None:
    resolver = await make_resolver(drop=True)
    with pytest.raises(NoAddresses) as info:
        await dial(
            "example.com",
            9,
            resolvers=[resolver.spec],
            resolve_timeout=0.2,
            attempt_delay=0.0,
            record_types=[TYPE_A],
        )
    assert info.value.host == "example.com"


async def test_dial_ignores_addresses_from_an_intercepted_resolver(
    make_resolver: MakeResolver, requires_ttl: None
) -> None:
    resolver = await make_resolver(
        answers=[rr_a("example.com", "6.6.6.6")], min_ttl=3, reply_ttl=48
    )
    with pytest.raises(NoAddresses) as info:
        await dial(
            "example.com",
            9,
            resolvers=[resolver.spec],
            attempt_delay=0.0,
            record_types=[TYPE_A],
            verify=True,
        )
    assert "could not resolve" in str(info.value)
    assert "intercepted" in str(info.value)


async def test_connection_stays_usable_after_the_race(echo_server: tuple[str, int]) -> None:
    host, port = echo_server
    connection: Connection = await race([Endpoint(host, port)], attempt_delay=0.0)
    try:
        assert await connection.reader.read() == b""
    finally:
        await connection.aclose()


async def test_measure_times_every_candidate(
    echo_server: tuple[str, int], second_echo_server: tuple[str, int]
) -> None:
    # Two endpoints that both accept; measure() keeps neither back.
    _host, first_port = echo_server
    _second, second_port = second_echo_server
    candidates = [Endpoint("127.0.0.1", first_port), Endpoint("127.0.0.1", second_port)]
    results = [item async for item in measure(candidates)]
    assert len(results) == 2
    assert all(result.succeeded for result in results)
    assert all(result.latency is not None and result.latency >= 0 for result in results)
    assert all(result.started >= 0 for result in results)
    assert {result.endpoint.port for result in results} == {first_port, second_port}


async def test_measure_reports_a_refused_handshake(closed_port: int) -> None:
    results = [item async for item in measure([Endpoint("127.0.0.1", closed_port)])]
    assert len(results) == 1
    handshake = results[0]
    assert handshake.failed is True
    assert handshake.succeeded is False
    assert "ConnectionRefused" in (handshake.error or "")
    assert handshake.latency is not None


async def test_measure_keeps_going_after_a_failure(
    echo_server: tuple[str, int], closed_port: int
) -> None:
    _host, port = echo_server
    candidates = [Endpoint("127.0.0.1", closed_port), Endpoint("127.0.0.1", port)]
    results = [item async for item in measure(candidates, concurrency=1)]
    assert [result.succeeded for result in results] == [False, True]


async def test_measure_deduplicates_and_takes_async_candidates(
    echo_server: tuple[str, int], closed_port: int
) -> None:
    _host, port = echo_server

    async def candidates() -> AsyncIterator[Endpoint]:
        yield Endpoint("127.0.0.1", port)
        yield Endpoint("127.0.0.1", port)
        yield Endpoint("127.0.0.1", closed_port)

    results = [item async for item in measure(candidates())]
    assert len(results) == 2
    assert [result.succeeded for result in results].count(True) == 1


async def test_measure_validates_arguments() -> None:
    with pytest.raises(ValueError):
        [item async for item in measure([], connect_timeout=0)]
    with pytest.raises(ValueError):
        [item async for item in measure([], concurrency=0)]


async def test_measure_on_an_empty_candidate_list() -> None:
    assert [item async for item in measure([])] == []


async def test_measure_stops_cleanly_when_the_caller_stops(echo_server: tuple[str, int]) -> None:
    _host, port = echo_server
    stream = measure([Endpoint("127.0.0.1", port)])
    first = await anext(stream)
    assert first.succeeded is True
    await stream.aclose()
    leftovers = [task for task in asyncio.all_tasks() if task.get_name().startswith("measure ")]
    assert leftovers == []


async def test_measure_is_a_plain_iterator_over_endpoints(echo_server: tuple[str, int]) -> None:
    host, port = echo_server
    results = [item async for item in measure([Endpoint(host, port)], concurrency=4)]
    assert results[0].endpoint == Endpoint(host, port)
    assert results[0].started == 0.0 or results[0].started > 0


async def test_measure_takes_samples_and_reports_the_median(
    echo_server: tuple[str, int], closed_port: int
) -> None:
    _host, port = echo_server
    results = [item async for item in measure([Endpoint("127.0.0.1", port)], samples=3)]
    handshake = results[0]
    assert len(handshake.samples) == 3
    assert handshake.failures == 0
    assert handshake.latency == statistics.median(handshake.samples)
    assert handshake.spread() is not None
    assert handshake.total is not None


async def test_measure_counts_the_samples_it_could_not_make(closed_port: int) -> None:
    handshake = await anext(measure([Endpoint("127.0.0.1", closed_port)], samples=2))
    assert handshake.samples == ()
    assert handshake.failures == 2
    assert handshake.failed is True
    assert handshake.latency is not None  # how long the failure took
    assert handshake.spread() is None


async def test_measure_times_a_tls_handshake(tls_server: tuple[str, int]) -> None:
    host, port = tls_server
    results = [
        item
        async for item in measure(
            [Endpoint(host, port)], tls=TLS(server_hostname="localhost", verify=False)
        )
    ]
    handshake = results[0]
    assert handshake.succeeded is True
    assert handshake.connect is not None
    assert handshake.tls is not None
    assert handshake.latency == handshake.tls  # TLS is the headline when asked for
    assert handshake.total is not None and handshake.total >= handshake.connect
    assert handshake.tls_version is not None
    assert handshake.alpn in {None, "http/1.1"}  # nothing on the other end speaks h2
    # An unverified connection is not decoded, so there is no certificate to read.
    assert handshake.certificate is None


async def test_measure_reports_a_certificate_it_could_not_verify(
    tls_server: tuple[str, int],
) -> None:
    host, port = tls_server
    handshake = await anext(measure([Endpoint(host, port)], tls=TLS(server_hostname="localhost")))
    assert handshake.failed is True
    assert "CERTIFICATE_VERIFY_FAILED" in (handshake.error or "")
    assert handshake.connect is not None  # TCP worked, the TLS handshake did not
    assert handshake.tls is None
    assert handshake.latency is not None


async def test_tls_details() -> None:
    context = TLS().context()
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.minimum_version <= ssl.TLSVersion.TLSv1_2
    loose = TLS(verify=False, alpn=()).context()
    assert loose.check_hostname is False
    assert loose.verify_mode == ssl.CERT_NONE


def test_certificate_rendering() -> None:
    certificate = Certificate(
        subject="CN=example.com", issuer="CN=Someone", expires="2026-12-25", days_left=39
    )
    assert str(certificate) == "CN=example.com (expires in 39d)"
    assert Certificate("CN=x", "CN=y", "", None).days_left is None


async def test_measure_validates_the_sample_count(echo_server: tuple[str, int]) -> None:
    _host, port = echo_server
    with pytest.raises(ValueError):
        [item async for item in measure([Endpoint("127.0.0.1", port)], samples=0)]
