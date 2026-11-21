"""Tests for resolving through one or more servers."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Iterable

import pytest

from pinkeyeballs import (
    Address,
    Answer,
    HopLadder,
    Lookup,
    Reply,
    ResolverSpec,
    exchange,
    hop_budget,
    hop_distance,
    resolve,
    resolve_stream,
    responds_at,
    walk_hop_limits,
)
from pinkeyeballs.dns import DEFAULT_RECORD_TYPES, DEFAULT_TTL_SLACK, Exchange, query
from pinkeyeballs.errors import DnsTimeout, MessageFormatError
from pinkeyeballs.wire import TYPE_A, TYPE_AAAA, TYPE_CNAME, build_query
from tests.conftest import (
    FakeResolver,
    MakeResolver,
    build_reply,
    question_name,
    rr_a,
    rr_aaaa,
    rr_cname,
)


def resolve_stream_now(
    host: str,
    resolvers: Iterable[ResolverSpec | str],
    **kwargs: object,
) -> AsyncGenerator[Answer, None]:
    """``resolve_stream`` without waiting for late replies."""
    return resolve_stream(host, resolvers, settle=0.0, **kwargs)  # type: ignore[arg-type]


async def query_now(
    name: str,
    resolver: ResolverSpec | str,
    rtype: int = TYPE_A,
    *,
    timeout: float = 2.0,
    hop_limit: int | None = None,
) -> Exchange:
    """``query`` without waiting for late replies; the window is tested on its own."""
    return await query(name, resolver, rtype, timeout=timeout, hop_limit=hop_limit, settle=0.0)


async def resolve_now(
    host: str,
    resolvers: Iterable[ResolverSpec | str] = ("1.1.1.1",),
    *,
    timeout: float = 2.0,
    types: Iterable[int] = DEFAULT_RECORD_TYPES,
    verify: bool = False,
    slack: int = 6,
    settle: float | None = 0.0,
) -> Lookup:
    """``resolve`` without waiting for late replies, unless a window is given."""
    return await resolve(
        host,
        resolvers,
        timeout=timeout,
        types=types,
        verify=verify,
        slack=slack,
        settle=settle,
    )


def test_hop_distance_uses_initial_ttl_candidates() -> None:
    assert hop_distance(64) == 0
    assert hop_distance(63) == 1
    assert hop_distance(48) == 16
    assert hop_distance(107) == 21
    assert hop_distance(128) == 0
    assert hop_distance(192) == 63
    with pytest.raises(ValueError):
        hop_distance(0)
    with pytest.raises(ValueError):
        hop_distance(256)


def test_hop_budget_is_one_hop_short() -> None:
    assert hop_budget(48) == 15
    assert hop_budget(107) == 20
    # A resolver on the local segment cannot be told apart from a proxy.
    assert hop_budget(64) is None
    assert hop_budget(63) is None


def test_hop_ladder_verdicts() -> None:
    # Nothing answers below the estimate: the reply looks honest.
    assert HopLadder(expected_hops=16, probed=(15,), answered=()).intercepted is False
    assert HopLadder(expected_hops=16, probed=(15,), answered=()).limit == 15
    # Replies come from much closer than the TTL claims.
    rungs = (19, 18, 17, 16, 15, 14)
    deep = HopLadder(expected_hops=20, slack=6, probed=rungs, answered=rungs)
    assert deep.responder_hops == 13
    assert deep.limit is None
    assert deep.intercepted is True
    # Six hops of drift is within slack, seven is not.
    assert HopLadder(expected_hops=16, probed=(15, 10), answered=(15, 11)).intercepted is False
    assert HopLadder(expected_hops=16, probed=(15, 9), answered=(15, 10, 9)).intercepted is True
    assert HopLadder(expected_hops=16, probed=(15, 10), answered=(15, 10)).intercepted is True


def test_resolver_spec_validation() -> None:
    assert str(ResolverSpec("1.1.1.1")) == "1.1.1.1"
    assert str(ResolverSpec("::1")) == "::1"
    assert str(ResolverSpec("1.1.1.1", 5353)) == "1.1.1.1#5353"
    assert ResolverSpec("::1").family == 6
    with pytest.raises(ValueError):
        ResolverSpec("not-an-ip")


def test_address_validation() -> None:
    assert Address("2001:db8::1").family == 6
    with pytest.raises(ValueError):
        Address("390.1.1.1")


def test_reply_invalidation_helpers() -> None:
    reply = Reply(
        rtype=TYPE_A,
        rcode=0,
        addresses=(Address("1.2.3.4"),),
        reply_ttl=48,
        hop_limit=13,
        verified=False,
        error="intercepted",
    )
    assert reply.intercepted is True
    assert reply.accepted is False
    assert reply.ok is False
    assert reply.type_name == "A"
    assert Reply(rtype=TYPE_CNAME).accepted is True
    assert Reply(rtype=TYPE_CNAME).verified is None


async def test_query_returns_addresses(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(
        answers=[rr_a("example.com", "93.184.216.34", 42), rr_aaaa("example.com", "2606:2800::1")]
    )
    result = await query_now("example.com", fake.spec, TYPE_A)
    assert result.rcode == 0
    assert result.hosts == ("93.184.216.34", "2606:2800::1")
    assert result.used_tcp is False
    assert result.elapsed > 0
    assert result.message.answers[0].ttl == 42


async def test_query_falls_back_to_tcp_when_truncated(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(
        answers=[rr_a("example.com", "93.184.216.34")], truncated=True, tcp=True
    )
    result = await query_now("example.com", fake.spec, TYPE_A)
    assert result.used_tcp is True
    assert result.hosts == ("93.184.216.34",)
    assert len(fake.queries) == 2


async def test_query_times_out_on_a_silent_resolver(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(drop=True)
    with pytest.raises(DnsTimeout):
        await query_now("example.com", fake.spec, TYPE_A, timeout=0.2)


async def test_exchange_returns_a_datagram(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "93.184.216.34")])
    datagram = await exchange(build_query("example.com", TYPE_A), fake.spec, timeout=1.0)
    assert datagram.reply_ttl is None or 1 <= datagram.reply_ttl <= 255
    assert datagram.elapsed > 0


async def test_reply_with_wrong_id_is_ignored(make_resolver: MakeResolver) -> None:
    def wrong_id(query_bytes: bytes) -> bytes:
        qid = int.from_bytes(query_bytes[:2], "big") ^ 0xFFFF
        return build_reply(query_bytes, answers=[rr_a("example.com", "1.2.3.4")], reply_id=qid)

    fake = await make_resolver(reply_builder=wrong_id)
    with pytest.raises(DnsTimeout):
        await query_now("example.com", fake.spec, TYPE_A, timeout=0.2)


async def test_reply_for_another_question_is_rejected(make_resolver: MakeResolver) -> None:
    def other_question(query_bytes: bytes) -> bytes:
        qid = int.from_bytes(query_bytes[:2], "big")
        question = build_query("other.example.com", TYPE_A, qid=qid)
        return build_reply(question, answers=[rr_a("other.example.com", "1.2.3.4")])

    fake = await make_resolver(reply_builder=other_question)
    with pytest.raises(MessageFormatError):
        await query_now("example.com", fake.spec, TYPE_A, timeout=0.5)


async def test_query_argument_validation(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.2.3.4")])
    with pytest.raises(ValueError):
        await query_now("example.com", fake.spec, TYPE_A, timeout=0)
    with pytest.raises(ValueError):
        await query_now("example.com", fake.spec, TYPE_A, hop_limit=0)


async def test_exchange_rejects_short_packets(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(answers=[])
    with pytest.raises(ValueError):
        await exchange(b"\x00", fake.spec)


async def test_resolve_stream_reports_every_resolver(make_resolver: MakeResolver) -> None:
    quick = await make_resolver(answers=[rr_a("example.com", "1.1.1.1")])
    slow = await make_resolver(answers=[rr_a("example.com", "2.2.2.2")])
    answers = [
        answer async for answer in resolve_stream_now("example.com", [quick.spec, slow.spec])
    ]
    assert {str(answer.resolver) for answer in answers} == {quick.address, slow.address}
    assert all(answer.replies[0].rcode == 0 for answer in answers)
    assert all(len(answer.replies) == 2 for answer in answers)  # A and AAAA


async def test_resolve_keeps_sources_and_ttls(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.1.1.1", 60)])
    lookup = await resolve_now("example.com", [fake.spec], types=[TYPE_A])
    assert [address.ip for address in lookup.addresses] == ["1.1.1.1"]
    assert lookup.addresses[0].source == fake.address
    assert lookup.addresses[0].ttl == 60
    assert lookup.addresses[0].family == 4
    assert lookup.responders == 1
    assert lookup.complete is True
    assert lookup.intercepted == ()
    assert lookup.errors == ()


async def test_resolve_merges_addresses_from_every_resolver(make_resolver: MakeResolver) -> None:
    first = await make_resolver(answers=[rr_a("example.com", "1.1.1.1")])
    second = await make_resolver(answers=[rr_a("example.com", "2.2.2.2")])
    lookup = await resolve_now("example.com", [first.spec, second.spec], types=[TYPE_A])
    assert {address.ip for address in lookup.addresses} == {"1.1.1.1", "2.2.2.2"}
    assert lookup.responders == 2


async def test_resolve_reports_nxdomain_and_timeouts(make_resolver: MakeResolver) -> None:
    empty = await make_resolver(rcode=3)
    silent = await make_resolver(drop=True)
    lookup = await resolve_now("example.com", [empty.spec, silent.spec], timeout=0.2)
    assert lookup.addresses == ()
    assert lookup.answers[0].rcode == 3
    assert "DnsTimeout" in (lookup.answers[1].error or "")
    assert lookup.errors


async def test_resolve_follows_cnames(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(
        answers=[
            rr_cname("www.example.com", "example.com", 3600),
            rr_a("example.com", "93.184.216.34", 60),
        ]
    )
    lookup = await resolve_now("www.example.com", [fake.spec], types=[TYPE_A])
    reply = lookup.answers[0].replies[0]
    assert reply.cname == "example.com"
    assert [address.ip for address in reply.addresses] == ["93.184.216.34"]


async def test_reply_ttl_is_captured(make_resolver: MakeResolver, requires_ttl: None) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.2.3.4")], reply_ttl=48)
    result = await query_now("example.com", fake.spec, TYPE_A, timeout=1.0)
    assert result.reply_ttl == 48
    lookup = await resolve_now("example.com", [fake.spec], types=[TYPE_A])
    assert lookup.answers[0].reply_ttl == 48
    # Capture alone decides nothing.
    assert lookup.answers[0].replies[0].verified is None
    assert lookup.answers[0].replies[0].hop_limit is None


async def test_verify_accepts_a_reply_whose_ttl_matches_the_distance(
    make_resolver: MakeResolver, requires_ttl: None
) -> None:
    # 13 hops away, claiming 16: within slack, so the reply is believed.
    fake = await make_resolver(answers=[rr_a("example.com", "1.2.3.4")], min_ttl=14, reply_ttl=48)
    lookup = await resolve_now("example.com", [fake.spec], types=[TYPE_A], verify=True)
    reply = lookup.answers[0].replies[0]
    assert reply.verified is True
    assert reply.hop_limit == 13
    assert reply.intercepted is False
    assert reply.accepted is True
    assert [address.ip for address in reply.addresses] == ["1.2.3.4"]


async def test_verify_rejects_a_reply_that_lies_about_its_distance(
    make_resolver: MakeResolver, requires_ttl: None
) -> None:
    # Two hops away but claiming 16 hops: no honest router can do that.
    fake = await make_resolver(answers=[rr_a("example.com", "6.6.6.6")], min_ttl=3, reply_ttl=48)
    lookup = await resolve_now("example.com", [fake.spec], types=[TYPE_A], verify=True)
    reply = lookup.answers[0].replies[0]
    assert reply.intercepted is True
    assert reply.verified is False
    assert reply.rcode == 0  # the sender still claimed success
    assert "intercepted" in (reply.error or "")
    # The address is kept for the report, but nothing downstream may dial it.
    assert [address.ip for address in reply.addresses] == ["6.6.6.6"]
    assert reply.accepted is False
    assert lookup.answers[0].addresses == ()
    assert lookup.intercepted == (fake.spec,)
    assert lookup.addresses == ()
    assert lookup.responders == 0


async def test_verify_can_be_relaxed_with_slack(
    make_resolver: MakeResolver, requires_ttl: None
) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.2.3.4")], min_ttl=8, reply_ttl=48)
    strict = await resolve_now("example.com", [fake.spec], types=[TYPE_A], verify=True, slack=6)
    assert strict.answers[0].replies[0].intercepted is True
    loose = await resolve_now("example.com", [fake.spec], types=[TYPE_A], verify=True, slack=20)
    assert loose.answers[0].replies[0].verified is True


async def test_verify_needs_a_ttl_to_start_from(
    make_resolver: MakeResolver, requires_ttl: None
) -> None:
    # A resolver on the local segment reports a TTL of 64: no verdict either way.
    fake = await make_resolver(answers=[rr_a("example.com", "1.2.3.4")], reply_ttl=64)
    lookup = await resolve_now("example.com", [fake.spec], types=[TYPE_A], verify=True)
    reply = lookup.answers[0].replies[0]
    assert reply.reply_ttl == 64
    assert reply.verified is None
    assert reply.hop_limit is None
    assert [address.ip for address in reply.addresses] == ["1.2.3.4"]


async def test_walk_hop_limits_finds_the_floor(
    make_resolver: MakeResolver, requires_ttl: None
) -> None:
    # A responder ten hops away, claiming sixteen.
    fake = await make_resolver(answers=[rr_a("example.com", "1.2.3.4")], min_ttl=11)
    ladder = await walk_hop_limits(
        build_query("example.com", TYPE_A), fake.spec, expected_hops=16, start=15, timeout=0.5
    )
    assert ladder.probed == (15, 14, 13, 12, 11, 10)
    assert ladder.answered == (15, 14, 13, 12, 11)
    assert ladder.limit == 10
    assert ladder.responder_hops == 10
    assert ladder.intercepted is False  # exactly at the slack


async def test_walk_hop_limits_stops_at_the_first_silence(
    make_resolver: MakeResolver, requires_ttl: None
) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.2.3.4")], min_ttl=15)
    ladder = await walk_hop_limits(
        build_query("example.com", TYPE_A), fake.spec, expected_hops=16, start=15, timeout=0.5
    )
    assert ladder.probed == (15, 14)
    assert ladder.answered == (15,)
    assert ladder.limit == 14
    assert ladder.responder_hops == 14
    assert ladder.slack == DEFAULT_TTL_SLACK
    assert ladder.intercepted is False


async def test_walk_hop_limits_argument_validation(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(answers=[])
    packet = build_query("example.com", TYPE_A)
    with pytest.raises(ValueError):
        await walk_hop_limits(packet, fake.spec, expected_hops=4, start=0)
    with pytest.raises(ValueError):
        await walk_hop_limits(packet, fake.spec, expected_hops=4, start=3, slack=0)


async def test_responds_at_reports_silence(make_resolver: MakeResolver, closed_port: int) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.2.3.4")])
    packet = build_query("example.com", TYPE_A)
    assert await responds_at(packet, fake.spec, 64, timeout=1.0) is True
    assert (
        await responds_at(packet, ResolverSpec("127.0.0.1", closed_port), 64, timeout=0.5) is False
    )


async def test_resolve_validates_arguments(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(answers=[])
    with pytest.raises(ValueError):
        await resolve_now("example.com", [fake.spec], types=[])
    with pytest.raises(ValueError):
        await resolve_now("example.com", [fake.spec], timeout=0)
    with pytest.raises(ValueError):
        await resolve_now("example.com", [])


async def test_cancelling_a_stream_cancels_pending_queries(make_resolver: MakeResolver) -> None:
    quick = await make_resolver(answers=[rr_a("example.com", "1.2.3.4")])
    silent = await make_resolver(drop=True)
    stream = resolve_stream("example.com", [quick.spec, silent.spec], timeout=30.0, settle=0.0)
    first = await anext(stream)
    assert first.resolver == quick.spec
    await stream.aclose()
    leftovers = [task for task in asyncio.all_tasks() if task.get_name().startswith("resolve ")]
    assert leftovers == []


async def test_fake_resolver_emulates_distance(
    make_resolver: MakeResolver, requires_ttl: None
) -> None:
    fake: FakeResolver = await make_resolver(answers=[rr_a("example.com", "1.2.3.4")], min_ttl=9)
    packet = build_query("example.com", TYPE_A)
    assert await responds_at(packet, fake.spec, 9, timeout=0.5) is True
    assert await responds_at(packet, fake.spec, 8, timeout=0.5) is False
    assert fake.saw_ttl is True


async def test_verify_catches_a_fabricated_answer(make_resolver: MakeResolver) -> None:
    # A resolver that answers even for a name that cannot exist.
    fake = await make_resolver(answers=[rr_a("example.com", "6.6.6.6")], unknown="answers")
    lookup = await resolve_now("example.com", [fake.spec], types=[TYPE_A], verify=True)
    answer = lookup.answers[0]
    assert answer.fabricated is True
    assert answer.intercepted is True
    assert "fabricated" in (answer.error or "")
    assert [address.ip for address in answer.replies[0].addresses] == ["6.6.6.6"]
    assert answer.addresses == ()
    assert lookup.intercepted == (fake.spec,)
    assert lookup.addresses == ()


async def test_the_canary_only_runs_when_verifying(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.2.3.4")])
    await resolve_now("example.com", [fake.spec], types=[TYPE_A])
    assert {question_name(query) for query, _ in fake.queries} == {"example.com"}
    assert fake.queries and all(query for query, _ in fake.queries)

    fake.queries.clear()
    await resolve_now("example.com", [fake.spec], types=[TYPE_A], verify=True)
    asked = {question_name(query) for query, _ in fake.queries}
    assert "example.com" in asked
    assert any(name.endswith(".invalid") for name in asked)


async def test_a_failure_is_reported_once_per_reason(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(drop=True)
    lookup = await resolve_now("example.com", [fake.spec], timeout=0.2)
    assert lookup.answers[0].error == f"DnsTimeout: no reply from {fake.address} within 0.20s"
    assert len(lookup.errors) == 1


async def test_a_forged_reply_and_the_real_one_are_both_heard(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(
        answers=[rr_a("example.com", "1.1.1.1")],
        forgery=lambda query: build_reply(query, answers=[rr_a("example.com", "6.6.6.6")]),
        lag=0.05,
    )
    result = await query("example.com", fake.spec, TYPE_A, timeout=2.0, settle=0.5)
    evidence = result.evidence
    assert evidence is not None
    assert evidence.received == 2
    assert evidence.contested is True
    assert evidence.alternatives == (("6.6.6.6",),)
    assert evidence.first < evidence.last
    assert evidence.last >= 0.05
    # The injected reply is the early one, so the real answer is the last one.
    assert result.hosts == ("1.1.1.1",)
    assert [datagram.elapsed for datagram in result.datagrams] == sorted(
        datagram.elapsed for datagram in result.datagrams
    )


async def test_the_window_closes_once_the_replies_stop(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.1.1.1")])
    started = asyncio.get_running_loop().time()
    result = await query("example.com", fake.spec, TYPE_A, timeout=5.0, settle=0.05)
    elapsed = asyncio.get_running_loop().time() - started
    assert result.evidence is not None
    assert result.evidence.received == 1
    assert elapsed < 1.0  # nowhere near the five second window


async def test_the_whole_window_is_heard_when_no_settle_is_given(
    make_resolver: MakeResolver,
) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.1.1.1")])
    started = asyncio.get_running_loop().time()
    await query("example.com", fake.spec, TYPE_A, timeout=0.3, settle=None)
    assert asyncio.get_running_loop().time() - started >= 0.3


async def test_wrong_transaction_ids_are_counted(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.1.1.1")], strays=3)
    result = await query("example.com", fake.spec, TYPE_A, timeout=2.0, settle=0.2)
    assert result.evidence is not None
    assert result.evidence.strays == 3
    assert result.evidence.poisoned is True
    assert result.hosts == ("1.1.1.1",)  # the stray guesses are ignored, not used


async def test_a_duplicate_reply_is_reported_but_not_a_contest(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.1.1.1")], duplicate=2)
    result = await query("example.com", fake.spec, TYPE_A, timeout=2.0, settle=0.2)
    assert result.evidence is not None
    assert result.evidence.received == 2
    assert result.evidence.contested is False
    assert result.evidence.poisoned is True


async def test_verify_rejects_an_answer_that_was_contested(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(
        answers=[rr_a("example.com", "1.1.1.1")],
        forgery=lambda query: build_reply(query, answers=[rr_a("example.com", "6.6.6.6")]),
        lag=0.05,
    )
    lookup = await resolve_now(
        "example.com", [fake.spec], types=[TYPE_A], verify=True, timeout=2.0, settle=0.5
    )
    reply = lookup.answers[0].replies[0]
    assert reply.contested is True
    assert reply.verified is False
    assert "injected replies" in (reply.error or "")
    # Kept for the report, but nothing downstream may use it.
    assert reply.accepted is False
    assert lookup.answers[0].addresses == ()
    assert lookup.poisoned == (fake.spec,)
    assert lookup.intercepted == (fake.spec,)


async def test_without_verify_a_contested_answer_is_used_but_reported(
    make_resolver: MakeResolver,
) -> None:
    fake = await make_resolver(
        answers=[rr_a("example.com", "1.1.1.1")],
        forgery=lambda query: build_reply(query, answers=[rr_a("example.com", "6.6.6.6")]),
        lag=0.05,
    )
    lookup = await resolve_now("example.com", [fake.spec], types=[TYPE_A], timeout=2.0, settle=0.5)
    reply = lookup.answers[0].replies[0]
    assert reply.contested is True
    assert reply.accepted is True
    assert [address.ip for address in reply.addresses] == ["1.1.1.1"]
    assert lookup.poisoned == (fake.spec,)


async def test_a_reply_only_answers_with_the_type_that_was_asked(
    make_resolver: MakeResolver,
) -> None:
    # The fake hands every question both records; each reply may only use its own.
    fake = await make_resolver(
        answers=[rr_a("example.com", "1.1.1.1"), rr_aaaa("example.com", "2001:db8::1")]
    )
    lookup = await resolve_now("example.com", [fake.spec], timeout=1.0)
    address, aaaa = lookup.answers[0].replies
    assert address.rtype == TYPE_A
    assert [item.ip for item in address.addresses] == ["1.1.1.1"]
    assert aaaa.rtype == TYPE_AAAA
    assert [item.ip for item in aaaa.addresses] == ["2001:db8::1"]
    assert [item.family for item in lookup.addresses] == [4, 6]
