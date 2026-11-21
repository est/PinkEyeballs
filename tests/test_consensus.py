"""Tests for comparing resolvers against each other."""

from __future__ import annotations

from pinkeyeballs import (
    Address,
    Agreement,
    Answer,
    Lookup,
    Opinion,
    Reply,
    ResolverSpec,
    Split,
    Stance,
    compare,
)
from pinkeyeballs.wire import TYPE_A, TYPE_AAAA


def answer(
    resolver: str,
    *addresses: str,
    rtype: int = TYPE_A,
    rcode: int | None = 0,
    error: str | None = None,
) -> Answer:
    """One resolver's reply: the addresses it returned for the question."""
    spec = ResolverSpec(resolver)
    if rcode is None:
        return Answer(resolver=spec, replies=(Reply(rtype=rtype, error=error),))
    resolved = tuple(Address(ip) for ip in addresses)
    return Answer(resolver=spec, replies=(Reply(rtype=rtype, rcode=rcode, addresses=resolved),))


def lookup(*answers: Answer) -> Lookup:
    return Lookup(host="example.com", answers=answers)


def test_two_resolvers_that_agree() -> None:
    agreement = compare(lookup(answer("1.1.1.1", "9.9.9.9"), answer("8.8.8.8", "9.9.9.9")))
    assert agreement.comparable is True
    assert agreement.unanimous is True
    assert agreement.undecided is False
    assert agreement.outliers == ()
    split = agreement.for_rtype(TYPE_A)
    assert split is not None
    assert split.voices == 2
    assert split.unanimous is True
    assert [opinion.stance for opinion in split.majority] == [Stance.AGREE, Stance.AGREE]
    assert [str(opinion.resolver) for opinion in split.majority] == ["1.1.1.1", "8.8.8.8"]


def test_an_answer_nobody_else_gave_is_an_outlier() -> None:
    agreement = compare(
        lookup(
            answer("1.1.1.1", "9.9.9.9"),
            answer("8.8.8.8", "9.9.9.9"),
            answer("9.9.9.9", "6.6.6.6"),
        )
    )
    assert agreement.unanimous is False
    assert agreement.undecided is False
    outliers = agreement.outliers
    assert [str(opinion.resolver) for opinion in outliers] == ["9.9.9.9"]
    assert outliers[0].stance is Stance.OUTLIER
    assert outliers[0].addresses == ("6.6.6.6",)
    assert outliers[0].type_name == "A"
    split = agreement.for_rtype(TYPE_A)
    assert split is not None
    assert split.decided is True
    assert [str(opinion.resolver) for opinion in split.majority] == ["1.1.1.1", "8.8.8.8"]


def test_a_partial_match_still_counts_as_agreement() -> None:
    # Rotating CDN addresses: one resolver knows a third address, nobody lies.
    agreement = compare(
        lookup(answer("1.1.1.1", "9.9.9.9", "7.7.7.7"), answer("8.8.8.8", "9.9.9.9"))
    )
    assert agreement.unanimous is True
    split = agreement.for_rtype(TYPE_A)
    assert split is not None
    assert [opinion.stance for opinion in split.majority] == [Stance.OVERLAP, Stance.OVERLAP]


def test_two_resolvers_that_disagree_have_no_majority() -> None:
    agreement = compare(lookup(answer("1.1.1.1", "9.9.9.9"), answer("8.8.8.8", "6.6.6.6")))
    assert agreement.comparable is True
    assert agreement.unanimous is False
    assert agreement.undecided is True
    assert agreement.outliers == ()
    split = agreement.for_rtype(TYPE_A)
    assert split is not None
    assert split.decided is False
    assert len(split.groups) == 2


def test_an_answer_where_the_others_said_there_is_none() -> None:
    # The classic hijack: one resolver invents an address for a name that does not exist.
    agreement = compare(
        lookup(
            answer("1.1.1.1", rcode=3),
            answer("8.8.8.8", rcode=3),
            answer("9.9.9.9", "6.6.6.6"),
        )
    )
    outliers = agreement.outliers
    assert [str(opinion.resolver) for opinion in outliers] == ["9.9.9.9"]
    assert outliers[0].stance is Stance.DISAGREED
    assert outliers[0].rcode == 0
    assert outliers[0].addresses == ("6.6.6.6",)


def test_silence_is_not_an_opinion() -> None:
    agreement = compare(
        lookup(
            answer("1.1.1.1", "9.9.9.9"),
            answer("8.8.8.8", "9.9.9.9"),
            answer("9.9.9.9", rcode=None, error="DnsTimeout: no reply"),
        )
    )
    split = agreement.for_rtype(TYPE_A)
    assert split is not None
    assert split.voices == 2
    assert split.unanimous is True
    assert [str(opinion.resolver) for opinion in split.silent] == ["9.9.9.9"]
    assert agreement.outliers == ()
    assert agreement.unanimous is True


def test_a_lone_resolver_has_nothing_to_compare() -> None:
    agreement = compare(lookup(answer("1.1.1.1", "9.9.9.9")))
    assert agreement.comparable is False
    assert agreement.unanimous is False
    assert agreement.undecided is False
    assert agreement.outliers == ()


def test_every_question_is_compared_separately() -> None:
    agreement = compare(
        Lookup(
            host="example.com",
            answers=(
                Answer(
                    resolver=ResolverSpec("1.1.1.1"),
                    replies=(
                        Reply(rtype=TYPE_A, rcode=0, addresses=(Address("9.9.9.9"),)),
                        Reply(rtype=TYPE_AAAA, rcode=0, addresses=(Address("2001:db8::1"),)),
                    ),
                ),
                Answer(
                    resolver=ResolverSpec("8.8.8.8"),
                    replies=(
                        Reply(rtype=TYPE_A, rcode=0, addresses=(Address("9.9.9.9"),)),
                        Reply(rtype=TYPE_AAAA, rcode=3),
                    ),
                ),
            ),
        )
    )
    assert [split.rtype for split in agreement.splits] == [TYPE_A, TYPE_AAAA]
    assert agreement.for_rtype(TYPE_A) is not None
    assert agreement.for_rtype(TYPE_A).unanimous is True  # type: ignore[union-attr]
    aaaa = agreement.for_rtype(TYPE_AAAA)
    assert aaaa is not None
    assert aaaa.decided is False  # one against one is no majority
    assert [opinion.stance for opinion in aaaa.groups[1]] == [Stance.DISAGREED]
    assert agreement.for_rtype(16) is None
    # Nothing is decided while the two resolvers contradict each other.
    assert agreement.undecided is True
    assert agreement.outliers == ()
    assert len(agreement.opinions) == 4


def test_empty_lookup() -> None:
    agreement = compare(Lookup(host="example.com"))
    assert agreement.splits == ()
    assert agreement.comparable is False
    assert agreement.outliers == ()
    assert agreement.opinions == ()


def test_helper_types() -> None:
    opinion = Opinion(resolver=ResolverSpec("1.1.1.1"), rtype=TYPE_A, stance=Stance.AGREE)
    assert opinion.type_name == "A"
    assert Split(rtype=TYPE_A, groups=((opinion,),), decided=False).majority == (opinion,)
    assert Split(rtype=TYPE_A).all == ()
    assert Agreement(host="example.com").for_rtype(TYPE_A) is None
    assert Agreement(host="example.com").unanimous is False
