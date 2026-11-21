"""Comparing what each resolver said about the same name.

Every resolver is asked the same question, so their answers can be lined up.
Resolvers whose answers are compatible with each other form a group; a group
that nobody else joined is an outlier — a broken server, a censoring one, or a
middlebox with a different idea of what the name means.

This is the check that still works when a middlebox answers honestly about its
own distance, which is exactly where the TTL forensics of
:mod:`pinkeyeballs.hijack` run out of road.  It reports, it does not judge:
content delivery networks hand out different addresses to different resolvers on
purpose, so a lone group means "these disagree", not "this one is lying".
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .dns import Answer, Lookup, Reply, ResolverSpec
from .wire import type_name


class Stance(StrEnum):
    """How one resolver's answer compares with the rest."""

    AGREE = "agree"
    OVERLAP = "overlap"
    OUTLIER = "outlier"
    DISAGREED = "disagreed"
    SILENT = "silent"


@dataclass(frozen=True, slots=True)
class Opinion:
    """One resolver's answer to one question."""

    resolver: ResolverSpec
    rtype: int
    stance: Stance
    rcode: int | None = None
    addresses: tuple[str, ...] = ()

    @property
    def type_name(self) -> str:
        return type_name(self.rtype)


@dataclass(frozen=True, slots=True)
class Split:
    """The answer groups of one record type, the biggest first.

    ``decided`` is set when one group is strictly bigger than the next, which is
    what makes it fair to point at the rest as the outliers.
    """

    rtype: int
    groups: tuple[tuple[Opinion, ...], ...] = ()
    silent: tuple[Opinion, ...] = ()
    decided: bool = False

    @property
    def voices(self) -> int:
        """How many resolvers said anything at all about this question."""
        return sum(len(group) for group in self.groups)

    @property
    def unanimous(self) -> bool:
        return len(self.groups) < 2

    @property
    def majority(self) -> tuple[Opinion, ...]:
        return self.groups[0] if self.groups else ()

    @property
    def outliers(self) -> tuple[Opinion, ...]:
        """The minority groups, once a majority is clear."""
        return (
            tuple(opinion for group in self.groups[1:] for opinion in group) if self.decided else ()
        )

    @property
    def all(self) -> tuple[Opinion, ...]:
        return tuple(opinion for group in self.groups for opinion in group) + self.silent


@dataclass(frozen=True, slots=True)
class Agreement:
    """What every resolver said, question by question."""

    host: str
    splits: tuple[Split, ...] = ()

    def for_rtype(self, rtype: int) -> Split | None:
        return next((split for split in self.splits if split.rtype == rtype), None)

    @property
    def comparable(self) -> bool:
        """True when at least two resolvers answered at least one question."""
        return any(split.voices > 1 for split in self.splits)

    @property
    def unanimous(self) -> bool:
        """True when no two resolvers disagreed anywhere."""
        return self.comparable and all(split.unanimous for split in self.splits if split.voices > 1)

    @property
    def undecided(self) -> bool:
        """True when resolvers disagree but no side is bigger than the other."""
        return any(
            split.voices > 1 and not (split.unanimous or split.decided) for split in self.splits
        )

    @property
    def outliers(self) -> tuple[Opinion, ...]:
        """Answers that no other resolver agreed with, when a majority is clear."""
        return tuple(opinion for split in self.splits for opinion in split.outliers)

    @property
    def opinions(self) -> tuple[Opinion, ...]:
        return tuple(opinion for split in self.splits for opinion in split.all)


@dataclass(frozen=True, slots=True)
class _Vote:
    """One resolver's answer to one question, ready to be grouped."""

    resolver: ResolverSpec
    rcode: int
    addresses: frozenset[str]

    @property
    def speaks_of_addresses(self) -> bool:
        return bool(self.addresses)


def _vote(addresses: tuple[str, ...], reply: Reply, resolver: ResolverSpec) -> _Vote:
    return _Vote(
        resolver=resolver,
        rcode=reply.rcode if reply.rcode is not None else 0,
        addresses=frozenset(addresses),
    )


def _compatible(left: _Vote, right: _Vote) -> bool:
    """Two answers fit together if they share an address or agree on nothing."""
    if left.speaks_of_addresses and right.speaks_of_addresses:
        return bool(left.addresses & right.addresses)
    if left.speaks_of_addresses or right.speaks_of_addresses:
        return False
    return left.rcode == right.rcode


def _group(votes: list[_Vote]) -> list[list[_Vote]]:
    """Split votes into groups that are mutually compatible."""
    remaining = list(votes)
    groups: list[list[_Vote]] = []
    while remaining:
        group = [remaining.pop(0)]
        while True:
            joined = [
                vote for vote in remaining if any(_compatible(vote, member) for member in group)
            ]
            if not joined:
                break
            for vote in joined:
                remaining.remove(vote)
            group.extend(joined)
        groups.append(group)
    groups.sort(key=lambda group: -len(group))
    return groups


def _opinions(rtype: int, groups: list[list[_Vote]], decided: bool) -> list[list[Opinion]]:
    """Label every group: agree, overlap, or the odd one out."""
    majority_says_addresses = bool(groups) and any(vote.speaks_of_addresses for vote in groups[0])
    labelled: list[list[Opinion]] = []
    for index, group in enumerate(groups):
        said_addresses = any(vote.speaks_of_addresses for vote in group)
        if index == 0:
            identical = len({vote.addresses for vote in group}) == 1
            stance = Stance.AGREE if identical else Stance.OVERLAP
        elif said_addresses != majority_says_addresses:
            # A different kind of answer: addresses where the rest said none, or worse.
            stance = Stance.DISAGREED
        else:
            stance = Stance.OUTLIER
        labelled.append(
            [
                Opinion(
                    resolver=vote.resolver,
                    rtype=rtype,
                    stance=stance,
                    rcode=vote.rcode,
                    addresses=tuple(sorted(vote.addresses)),
                )
                for vote in group
            ]
        )
    return labelled


def _split(rtype: int, answers: tuple[Answer, ...]) -> Split:
    votes: list[_Vote] = []
    silent: list[Opinion] = []
    for answer in answers:
        reply = next((item for item in answer.replies if item.rtype == rtype), None)
        if reply is None or reply.rcode is None:
            silent.append(Opinion(resolver=answer.resolver, rtype=rtype, stance=Stance.SILENT))
            continue
        addresses = tuple(address.ip for address in reply.addresses)
        votes.append(_vote(addresses, reply, answer.resolver))

    groups = _group(votes)
    decided = len(groups) > 1 and len(groups[0]) > len(groups[1])
    return Split(
        rtype=rtype,
        groups=tuple(tuple(group) for group in _opinions(rtype, groups, decided)),
        silent=tuple(silent),
        decided=decided,
    )


def compare(lookup: Lookup) -> Agreement:
    """Line up every resolver's answer, question by question."""
    rtypes = sorted({reply.rtype for answer in lookup.answers for reply in answer.replies})
    return Agreement(
        host=lookup.host,
        splits=tuple(_split(rtype, lookup.answers) for rtype in rtypes),
    )


__all__ = [
    "Agreement",
    "Opinion",
    "Split",
    "Stance",
    "compare",
]
