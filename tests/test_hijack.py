"""Tests for the hop-limited interception probe."""

from __future__ import annotations

import pytest

from pinkeyeballs import (
    Probe,
    ResolverSpec,
    canary,
    canary_all,
    probe,
    probe_all,
    random_invalid_name,
)
from tests.conftest import MakeResolver, rr_a


def test_random_invalid_name_is_random_and_reserved() -> None:
    names = {random_invalid_name() for _ in range(5)}
    assert len(names) == 5
    assert all(name.endswith(".invalid") for name in names)


async def test_probe_with_an_explicit_hop_limit_finds_a_reply(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.2.3.4")])
    result = await probe(fake.spec, "example.com", hop_limit=64, timeout=1.0)
    assert result.verdict == "intercepted"
    assert result.intercepted is True
    assert result.answered == (64,)
    assert result.probed == (64,)
    assert result.hops is None
    assert result.rcode_name == "NOERROR"
    assert result.addresses == ("1.2.3.4",)


async def test_probe_with_an_explicit_hop_limit_stays_silent(
    make_resolver: MakeResolver, requires_ttl: None
) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.2.3.4")], min_ttl=14)
    result = await probe(fake.spec, "example.com", hop_limit=13, timeout=0.5)
    assert result.verdict == "clean"
    assert result.intercepted is False
    assert result.answered == ()
    assert result.hop_limit == 13
    assert result.error is None


async def test_probe_measures_then_walks_the_ladder(
    make_resolver: MakeResolver, requires_ttl: None
) -> None:
    # Thirteen hops away, claiming sixteen: honest enough.
    fake = await make_resolver(answers=[rr_a("example.com", "1.2.3.4")], min_ttl=14, reply_ttl=48)
    result = await probe(fake.spec, "example.com", timeout=0.5)
    assert result.verdict == "clean"
    assert result.reply_ttl == 48
    assert result.hops == 16
    assert result.responder_hops == 13
    assert result.probed == (15, 14, 13)
    assert result.answered == (15, 14)
    assert result.hop_limit == 13
    assert result.slack == 6
    assert result.rcode_name == "NOERROR"


async def test_probe_catches_a_reply_that_lies_about_its_distance(
    make_resolver: MakeResolver, requires_ttl: None
) -> None:
    fake = await make_resolver(
        answers=[rr_a("example.com", "6.6.6.6")], min_ttl=3, reply_ttl=48, tcp=True
    )
    result = await probe(fake.spec, "example.com", timeout=0.5)
    assert result.verdict == "intercepted"
    assert result.intercepted is True
    assert result.responder_hops == 9
    assert result.hop_limit == 9
    assert result.answered == (15, 14, 13, 12, 11, 10)
    assert result.addresses == ("6.6.6.6",)
    assert result.rcode_name == "NOERROR"


async def test_probe_reports_a_resolver_too_close_to_judge(
    make_resolver: MakeResolver, requires_ttl: None
) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.2.3.4")], reply_ttl=64)
    result = await probe(fake.spec, "example.com", timeout=0.5)
    assert result.verdict == "inconclusive"
    assert result.intercepted is False
    assert result.hop_limit is None
    assert result.reply_ttl == 64
    assert result.hops == 0
    assert "too close" in (result.error or "")


async def test_probe_reports_a_silent_resolver(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(drop=True)
    result = await probe(fake.spec, "example.com", timeout=0.2)
    assert result.verdict == "error"
    assert result.error == "no reply to an ordinary query"
    assert result.probed == ()


async def test_probe_reports_an_unparseable_reply(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(
        answers=[rr_a("example.com", "1.2.3.4")], reply_builder=lambda _q: b"!"
    )
    result = await probe(fake.spec, "example.com", hop_limit=64, timeout=1.0)
    assert result.verdict == "intercepted"  # something answered, whatever it said
    assert "unparseable" in (result.error or "")


async def test_probe_uses_a_random_name_by_default(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(answers=[])
    result = await probe(fake.spec, timeout=1.0, hop_limit=64)
    assert result.name.startswith("probe-")
    assert result.name.endswith(".invalid")
    assert fake.queries[0][0][12:].startswith(b"\x12probe-")


async def test_probe_all_runs_every_resolver(make_resolver: MakeResolver) -> None:
    first = await make_resolver(answers=[rr_a("example.com", "1.1.1.1")], min_ttl=3, reply_ttl=48)
    second = await make_resolver(answers=[rr_a("example.com", "2.2.2.2")], drop=True)
    results = await probe_all([first.spec, second.spec], "example.com", timeout=0.2)
    assert [result.resolver for result in results] == [first.spec, second.spec]
    assert results[0].intercepted is True
    assert results[1].verdict == "error"


async def test_probe_argument_validation(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(answers=[])
    with pytest.raises(ValueError):
        await probe(fake.spec, hop_limit=0)
    with pytest.raises(ValueError):
        await probe(fake.spec, hop_limit=256)
    with pytest.raises(ValueError):
        await probe(fake.spec, slack=0)
    with pytest.raises(ValueError):
        await probe(fake.spec, timeout=0)
    with pytest.raises(ValueError):
        await probe("bogus-address")


def test_probe_verdict_helper() -> None:
    fresh = Probe(resolver=ResolverSpec("1.1.1.1"), name="x.invalid")
    assert fresh.verdict == "inconclusive"
    assert fresh.intercepted is False
    assert fresh.rcode_name is None
    dirty = Probe(resolver=ResolverSpec("1.1.1.1"), name="x.invalid", verdict="intercepted")
    assert dirty.intercepted is True


async def test_canary_is_clean_for_an_honest_resolver(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.2.3.4")])
    result = await canary(fake.spec)
    assert result.fabricated is False
    assert result.verdict == "clean"
    assert result.rcode == 3
    assert result.addresses == ()
    assert result.rcode_name == "NXDOMAIN"


async def test_canary_catches_an_invented_answer(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "6.6.6.6")], unknown="answers")
    result = await canary(fake.spec)
    assert result.fabricated is True
    assert result.verdict == "intercepted"
    assert result.addresses == ("6.6.6.6",)
    assert result.rcode == 0


async def test_canary_reports_a_silent_resolver(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(drop=True)
    result = await canary(fake.spec, timeout=0.2)
    assert result.verdict == "error"
    assert "DnsTimeout" in (result.error or "")


async def test_canary_all_runs_every_resolver(make_resolver: MakeResolver) -> None:
    honest = await make_resolver(answers=[rr_a("example.com", "1.2.3.4")])
    liar = await make_resolver(answers=[rr_a("example.com", "6.6.6.6")], unknown="answers")
    results = await canary_all([honest.spec, liar.spec])
    assert [result.resolver for result in results] == [honest.spec, liar.spec]
    assert results[0].verdict == "clean"
    assert results[1].fabricated is True


async def test_canary_validates_arguments(make_resolver: MakeResolver) -> None:
    fake = await make_resolver(answers=[])
    with pytest.raises(ValueError):
        await canary(fake.spec, timeout=0)


async def test_probe_reports_a_fabricated_answer(make_resolver: MakeResolver) -> None:
    # A resolver that answers anything is caught before any hop counting.
    fake = await make_resolver(answers=[rr_a("example.com", "6.6.6.6")], unknown="answers")
    result = await probe(fake.spec)
    assert result.verdict == "intercepted"
    assert result.fabricated is True
    assert result.addresses == ("6.6.6.6",)
    assert result.answered == ()
    assert result.probed == ()
    assert "impossible name" in (result.error or "")
