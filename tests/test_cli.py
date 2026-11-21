"""Tests for the command line interface."""

from __future__ import annotations

import argparse
import json

import pytest

from pinkeyeballs import (
    Address,
    Answer,
    Arrival,
    Certificate,
    Endpoint,
    Evidence,
    Handshake,
    Probe,
    Reply,
    ResolverSpec,
)
from pinkeyeballs.cli import (
    ADDRESS_COLUMNS,
    Target,
    _arrival_note,
    _evidence_short,
    _handshake_payload,
    _run,
    _short_error,
    _table_widths,
    _timing_columns,
    _timing_table,
    _Writer,
    build_parser,
    main,
    parse_resolver,
    parse_target,
)
from pinkeyeballs.wire import TYPE_A, TYPE_AAAA
from tests.conftest import MakeResolver, build_reply, rr_a, rr_aaaa


def test_parse_target_without_a_port() -> None:
    target = parse_target("example.com")
    assert target == Target("example.com")
    assert target.port is None
    assert target.literal is False
    assert str(target) == "example.com"


def test_parse_target_with_a_port() -> None:
    target = parse_target("example.com:8443")
    assert (target.host, target.port) == ("example.com", 8443)
    assert str(target) == "example.com:8443"


def test_parse_target_with_an_ip_literal() -> None:
    assert parse_target("1.1.1.1").literal is True
    assert parse_target("1.1.1.1:443").literal is True
    assert str(parse_target("[2001:db8::1]:443")) == "[2001:db8::1]:443"
    assert str(parse_target("[2001:db8::1]")) == "2001:db8::1"
    # A bare IPv6 literal has no port to find, brackets or not.
    assert (parse_target("2001:db8::1").host, parse_target("2001:db8::1").port) == (
        "2001:db8::1",
        None,
    )


@pytest.mark.parametrize("text", ["", ":443", "example.com:", "example.com:0", "example.com:99999"])
def test_bad_targets_are_rejected(text: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        parse_target(text)


@pytest.mark.parametrize("text", ["[2001:db8::1", "[2001:db8::1]x", "example.com:port"])
def test_malformed_targets_are_rejected(text: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        parse_target(text)


def test_parse_resolver() -> None:
    assert parse_resolver("1.1.1.1") == ResolverSpec("1.1.1.1")
    assert parse_resolver("1.1.1.1#5353") == ResolverSpec("1.1.1.1", 5353)
    assert parse_resolver("[::1]#5353") == ResolverSpec("::1", 5353)


def test_a_bare_port_points_at_the_target_syntax() -> None:
    with pytest.raises(argparse.ArgumentTypeError) as info:
        parse_resolver("443")
    assert "example.com:443" in str(info.value)
    with pytest.raises(argparse.ArgumentTypeError):
        parse_resolver("1.1.1.1#0")
    with pytest.raises(argparse.ArgumentTypeError):
        parse_resolver("dns.example.com")


def cells(line: str) -> list[str]:
    """The cells of a markdown table row, whatever padding they carry."""
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def run_args(argv: list[str]) -> argparse.Namespace:
    """Parse arguments with the reply window closed, so the tests stay fast."""
    return build_parser().parse_args([*argv, "--settle", "0"])


def test_parser_defaults() -> None:
    args = build_parser().parse_args(["example.com"])
    assert args.target == Target("example.com")
    assert args.resolvers == []
    assert args.resolver is None
    assert args.resolve_timeout == 2.0
    assert args.connect_timeout == 5.0
    assert args.concurrency == 8
    assert args.verify is False
    assert args.slack == 6
    assert args.samples == 1
    assert args.tls is False
    assert args.insecure is False
    assert args.quiet is False
    assert (args.ipv4, args.ipv6) == (False, False)
    assert args.verbose is False
    assert args.json is False


def test_parser_collects_resolvers_from_both_places() -> None:
    args = build_parser().parse_args(
        [
            "example.com:443",
            "1.1.1.1",
            "-r",
            "8.8.8.8#5353",
            "--verify",
            "--slack",
            "3",
            "--concurrency",
            "2",
            "--connect-timeout",
            "1.5",
            "--resolve-timeout",
            "0.5",
            "-v",
            "--json",
        ]
    )
    assert [str(spec) for spec in args.resolvers] == ["1.1.1.1"]
    assert [str(spec) for spec in args.resolver] == ["8.8.8.8#5353"]
    assert (args.verify, args.slack, args.concurrency) == (True, 3, 2)
    assert (args.connect_timeout, args.resolve_timeout) == (1.5, 0.5)
    assert (args.verbose, args.json) == (True, True)


def test_parser_accepts_the_measurement_flags() -> None:
    args = build_parser().parse_args(["example.com:443", "--tls", "--insecure", "--samples", "3"])
    assert (args.tls, args.insecure, args.samples) == (True, True, 3)
    assert build_parser().parse_args(["example.com", "-4"]).ipv4 is True
    assert build_parser().parse_args(["example.com", "-6"]).ipv6 is True
    assert build_parser().parse_args(["example.com", "-q"]).quiet is True


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["example.com", "nope"],
        ["example.com", "--slack", "0"],
        ["example.com", "--concurrency", "0"],
        ["example.com", "--resolve-timeout", "0"],
        ["example.com", "--connect-timeout", "-1"],
        ["example.com", "--samples", "0"],
    ],
)
def test_bad_arguments_exit_with_a_usage_error(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as info:
        build_parser().parse_args(argv)
    assert info.value.code == 2


@pytest.mark.parametrize(
    "argv",
    [
        ["example.com", "-4", "-6"],
        ["example.com", "--tls"],
        ["example.com", "--samples", "3"],
        ["example.com", "--insecure"],
        ["1.1.1.1", "-6"],
    ],
)
def test_option_combinations_are_checked_before_anything_runs(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as info:
        main(argv)
    assert info.value.code == 2
    assert "error" in capsys.readouterr().err


def test_version_exits_cleanly() -> None:
    with pytest.raises(SystemExit) as info:
        main(["--version"])
    assert info.value.code == 0


def test_a_literal_target_needs_no_network(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["1.1.1.1"]) == 0
    assert capsys.readouterr().out == "1.1.1.1\n"


def test_a_literal_target_as_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--json", "1.1.1.1"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "ip": "1.1.1.1",
        "family": 4,
        "ttl": None,
        "source": None,
        "reply_ttl": None,
        "rcode": None,
        "evidence": None,
    }


def test_a_closed_port_exits_nonzero(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--connect-timeout", "1", "127.0.0.1:1"]) == 1
    columns = capsys.readouterr().out.split("\t")
    assert columns[0] == "127.0.0.1:1"
    assert columns[1] == "-"
    assert columns[2] == "refused\n"


def test_writer_writes_text_lines_and_notes(capsys: pytest.CaptureFixture[str]) -> None:
    writer = _Writer(json_mode=False, markdown=False, verbose=False, quiet=False)
    writer.table("address", ADDRESS_COLUMNS, [8] * len(ADDRESS_COLUMNS))
    writer.literal(Address("1.2.3.4"))
    writer.note("a resolver had a bad day")
    captured = capsys.readouterr()
    assert captured.out == "1.2.3.4\n"
    assert captured.err == "a resolver had a bad day\n"


def test_writer_streams_the_markdown_table(capsys: pytest.CaptureFixture[str]) -> None:
    writer = _Writer(json_mode=False, markdown=True, verbose=False, quiet=False)
    widths = [26, 4, 6, 10, 7, 8, 10]
    writer.table("address", ADDRESS_COLUMNS, widths)
    header = capsys.readouterr().out.splitlines()
    assert cells(header[0]) == list(ADDRESS_COLUMNS)
    assert all(set(cell) == {"-"} for cell in cells(header[1]))

    writer.answer(
        Answer(
            resolver=ResolverSpec("1.1.1.1"),
            replies=(
                Reply(
                    rtype=TYPE_A,
                    rcode=0,
                    addresses=(Address("2001:db8::11", 60, "1.1.1.1"),),
                    evidence=Evidence(
                        arrivals=(
                            Arrival(
                                0.0123,
                                (Address("2001:db8::11", 60, "1.1.1.1"),),
                                0,
                                True,
                                48,
                            ),
                        )
                    ),
                ),
            ),
        )
    )
    row = cells(capsys.readouterr().out.splitlines()[0])
    assert row[0] == "2001:db8::11"
    assert row[1] == "A"
    assert row[2] == "60"
    assert row[3] == "1.1.1.1"
    assert row[4] == "64-16"
    assert row[5] == "12.3ms"

    writer.note("careful")
    writer.finish()
    assert capsys.readouterr().out.splitlines() == ["", "- careful"]


def test_writer_resolver_report(capsys: pytest.CaptureFixture[str]) -> None:
    writer = _Writer(json_mode=False, markdown=False, verbose=False, quiet=False)
    resolver = ResolverSpec("1.1.1.1")
    writer.report(Answer(resolver=resolver, replies=(Reply(rtype=TYPE_A, rcode=3),)))
    writer.report(
        Answer(resolver=resolver, replies=(Reply(rtype=TYPE_A, error="DnsTimeout: nope"),))
    )
    writer.report(
        Answer(
            resolver=resolver,
            replies=(Reply(rtype=TYPE_A, rcode=0, addresses=(Address("1.2.3.4"),)),),
        )
    )
    captured = capsys.readouterr()
    assert captured.err.splitlines() == ["1.1.1.1: NXDOMAIN, 0.0ms", "1.1.1.1: DnsTimeout: nope"]
    assert captured.out == ""


def test_writer_is_quiet_about_success_unless_verbose(capsys: pytest.CaptureFixture[str]) -> None:
    answer = Answer(
        resolver=ResolverSpec("1.1.1.1"),
        replies=(Reply(rtype=TYPE_A, rcode=0, addresses=(Address("1.2.3.4"),)),),
        elapsed=0.01,
    )
    _Writer(json_mode=False, markdown=False, verbose=True, quiet=False).report(answer)
    assert capsys.readouterr().err == "1.1.1.1: 1.2.3.4, 10.0ms\n"


def test_handshake_payload() -> None:
    payload = _handshake_payload(
        Handshake(
            endpoint=Endpoint("1.2.3.4", 443, 60, "1.1.1.1"),
            elapsed=0.3,
            started=0.25,
            samples=(0.0123, 0.0201),
            connect=0.005,
            tls=0.0123,
            tls_version="TLSv1.3",
            cipher="TLS_AES_128_GCM_SHA256",
            alpn="h2",
            certificate=Certificate("CN=example.com", "CN=Someone", "2026-12-25", 39),
        )
    )
    assert payload["ip"] == "1.2.3.4"
    assert payload["source"] == "1.1.1.1"
    assert payload["latency_ms"] == 16.2  # the median of 12.3 and 20.1
    assert payload["connect_ms"] == 5.0
    assert payload["tls_ms"] == 12.3
    assert payload["samples_ms"] == [12.3, 20.1]
    assert payload["tls_version"] == "TLSv1.3"
    assert payload["alpn"] == "h2"
    assert payload["certificate"] == {
        "subject": "CN=example.com",
        "issuer": "CN=Someone",
        "expires": "2026-12-25",
        "days_left": 39,
    }
    assert json.dumps(payload)


def test_timing_columns_spell_out_what_was_measured() -> None:
    answer = Answer(
        resolver=ResolverSpec("1.1.1.1"),
        replies=(
            Reply(
                rtype=TYPE_A,
                rcode=0,
                addresses=(Address("1.2.3.4", 300, "1.1.1.1"),),
                reply_ttl=48,
            ),
        ),
    )
    address = answer.replies[0].addresses[0]
    handshake = Handshake(
        endpoint=Endpoint("1.2.3.4", 443, 300, "1.1.1.1"),
        samples=(0.2, 0.3, 0.4),
        failures=1,
        connect=0.05,
        tls=0.2,
        tls_version="TLSv1.3",
        cipher="TLS_AES_128_GCM_SHA256",
        alpn="h2",
        certificate=Certificate("CN=example.com", "CN=Someone", "2026-12-25", 39),
    )
    columns = _timing_columns(handshake, answer, address)
    assert columns[0] == "n=3/4 (200.0-400.0ms)"
    assert columns[1:4] == ["1.1.1.1", "dns ttl 300", "IP TTL 64-16"]
    assert columns[4] == "tcp 50.0ms"
    assert columns[5] == "tls TLSv1.3 TLS_AES_128_GCM_SHA256 h2"
    assert columns[6] == "cert CN=example.com (expires in 39d) via CN=Someone"


def test_timing_columns_for_a_literal_without_tls() -> None:
    handshake = Handshake(endpoint=Endpoint("1.2.3.4", 443), samples=(0.05,), connect=0.05)
    columns = _timing_columns(handshake, None, None)
    assert columns == ["literal address, no DNS"]


async def test_address_command_asks_only_for_the_family_it_was_told(
    make_resolver: MakeResolver, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = await make_resolver(
        answers=[rr_a("example.com", "1.1.1.1"), rr_aaaa("example.com", "2001:db8::1")]
    )
    assert await _run(run_args(["example.com", fake.address, "-4"])) == 0
    assert capsys.readouterr().out.splitlines() == ["1.1.1.1"]

    fake.queries.clear()
    assert await _run(run_args(["example.com", fake.address, "-6"])) == 0
    assert capsys.readouterr().out.splitlines() == ["2001:db8::1"]
    assert [question_type(query) for query, _ in fake.queries] == [TYPE_AAAA]


async def test_quiet_keeps_stderr_for_fatal_errors_only(
    make_resolver: MakeResolver, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = await make_resolver(drop=True)
    args = run_args(["example.com", fake.address, "--resolve-timeout", "0.2", "-q"])
    assert await _run(args) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


async def test_tls_handshake_is_timed_and_described(
    make_resolver: MakeResolver, tls_server: tuple[str, int], capsys: pytest.CaptureFixture[str]
) -> None:
    host, port = tls_server
    fake = await make_resolver(answers=[rr_a("example.com", host, 30)])
    args = run_args([f"example.com:{port}", fake.address, "--tls", "--insecure", "-v"])
    assert await _run(args) == 0
    columns = capsys.readouterr().out.splitlines()[0].split("\t")
    assert columns[0] == f"{host}:{port}"
    assert columns[1].endswith("ms")
    assert any(column.startswith("tcp ") for column in columns)
    assert any(column.startswith("tls TLS") for column in columns)


async def test_tls_without_insecure_reports_the_certificate_problem(
    make_resolver: MakeResolver, tls_server: tuple[str, int], capsys: pytest.CaptureFixture[str]
) -> None:
    host, port = tls_server
    fake = await make_resolver(answers=[rr_a("example.com", host, 30)])
    args = run_args([f"example.com:{port}", fake.address, "--tls", "-v"])
    assert await _run(args) == 1
    captured = capsys.readouterr()
    columns = captured.out.splitlines()[0].split("\t")
    assert columns[1] == "-"
    assert columns[2] == "certificate"
    assert "CERTIFICATE_VERIFY_FAILED" in captured.err


async def test_samples_are_reported_as_a_median(
    make_resolver: MakeResolver, echo_server: tuple[str, int], capsys: pytest.CaptureFixture[str]
) -> None:
    host, port = echo_server
    fake = await make_resolver(answers=[rr_a("example.com", host, 30)])
    args = run_args([f"example.com:{port}", fake.address, "--samples", "3", "-v"])
    assert await _run(args) == 0
    columns = capsys.readouterr().out.splitlines()[0].split("\t")
    assert columns[1].endswith("ms")
    assert columns[2].startswith("n=3/3 (")


async def test_address_command_prints_one_address_per_line(
    make_resolver: MakeResolver, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = await make_resolver(
        answers=[rr_a("example.com", "1.1.1.1", 60), rr_aaaa("example.com", "2001:db8::1", 60)]
    )
    args = run_args(["example.com", fake.address, "--resolve-timeout", "1"])
    assert await _run(args) == 0
    captured = capsys.readouterr()
    assert captured.out.splitlines() == ["1.1.1.1", "2001:db8::1"]
    assert captured.err == ""


async def test_address_command_verbose_adds_columns(
    make_resolver: MakeResolver, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.1.1.1", 60)])
    args = run_args(["example.com", fake.address, "-v"])
    assert await _run(args) == 0
    captured = capsys.readouterr()
    columns = captured.out.splitlines()[0].split("\t")
    assert columns[0] == "1.1.1.1"
    assert columns[1] == fake.address
    assert columns[2] == "dns ttl 60"
    assert columns[3].startswith("IP TTL")
    assert captured.err.startswith(f"{fake.address}: 1.1.1.1, IP TTL")


async def test_address_command_deduplicates_resolvers(
    make_resolver: MakeResolver, capsys: pytest.CaptureFixture[str]
) -> None:
    first = await make_resolver(answers=[rr_a("example.com", "1.1.1.1")])
    second = await make_resolver(answers=[rr_a("example.com", "1.1.1.1")])
    args = run_args(["example.com", first.address, second.address])
    assert await _run(args) == 0
    assert capsys.readouterr().out.splitlines() == ["1.1.1.1"]


async def test_address_command_explains_a_failure_on_stderr(
    make_resolver: MakeResolver, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = await make_resolver(drop=True)
    args = run_args(["example.com", fake.address, "--resolve-timeout", "0.2"])
    assert await _run(args) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "DnsTimeout" in captured.err


async def test_verify_drops_fabricated_answers(
    make_resolver: MakeResolver, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "6.6.6.6")], unknown="answers")
    args = run_args(["example.com", fake.address, "--verify"])
    assert await _run(args) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "fabricated" in captured.err


async def test_address_command_as_json(
    make_resolver: MakeResolver, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.1.1.1", 60)])
    args = run_args(["example.com", fake.address, "--json"])
    assert await _run(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ip"] == "1.1.1.1"
    assert payload["ttl"] == 60
    assert payload["source"] == fake.address


async def test_measure_command_times_every_address(
    make_resolver: MakeResolver, echo_server: tuple[str, int], capsys: pytest.CaptureFixture[str]
) -> None:
    host, port = echo_server
    fake = await make_resolver(answers=[rr_a("example.com", host, 30)])
    args = run_args([f"example.com:{port}", fake.address])
    assert await _run(args) == 0
    columns = capsys.readouterr().out.splitlines()[0].split("\t")
    assert columns[0] == f"{host}:{port}"
    assert columns[1].endswith("ms")


async def test_measure_command_reports_a_refused_handshake(
    make_resolver: MakeResolver, closed_port: int, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "127.0.0.1", 30)])
    args = run_args(
        [f"example.com:{closed_port}", fake.address, "--connect-timeout", "1", "--json"]
    )
    assert await _run(args) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["port"] == closed_port
    assert payload["latency_ms"] is not None  # how long it took to be refused
    assert "ConnectionRefused" in str(payload["error"])


async def test_measure_command_without_any_address(
    make_resolver: MakeResolver, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.1.1.1")], drop=True)
    args = run_args(["example.com:443", fake.address, "--resolve-timeout", "0.2"])
    assert await _run(args) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "DnsTimeout" in captured.err


def question_type(query: bytes) -> int:
    """The record type a query asks for."""
    offset = 12
    while query[offset]:
        offset += query[offset] + 1
    return int.from_bytes(query[offset + 1 : offset + 3], "big")


async def test_probe_type_still_importable() -> None:
    assert Probe(resolver=ResolverSpec("1.1.1.1"), name="x.invalid").verdict == "inconclusive"


async def test_injected_replies_are_reported_on_stderr(
    make_resolver: MakeResolver, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = await make_resolver(
        answers=[rr_a("example.com", "1.1.1.1")],
        forgery=lambda query: build_reply(query, answers=[rr_a("example.com", "6.6.6.6")]),
        lag=0.05,
    )
    args = build_parser().parse_args(["example.com", fake.address, "--settle", "0.5"])
    assert await _run(args) == 0
    captured = capsys.readouterr()
    # The real answer is used, and the injected one is named on stderr.
    assert captured.out.splitlines() == ["1.1.1.1"]
    assert "injected replies" in captured.err
    assert "not 6.6.6.6" in captured.err


async def test_wrong_transaction_ids_are_reported_on_stderr(
    make_resolver: MakeResolver, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.1.1.1")], strays=2)
    args = build_parser().parse_args(["example.com", fake.address, "--settle", "0.2"])
    assert await _run(args) == 0
    captured = capsys.readouterr()
    assert captured.out.splitlines() == ["1.1.1.1"]
    assert "2 datagrams with a wrong transaction id" in captured.err


async def test_evidence_is_in_the_json_report(
    make_resolver: MakeResolver, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = await make_resolver(
        answers=[rr_a("example.com", "1.1.1.1")],
        forgery=lambda query: build_reply(query, answers=[rr_a("example.com", "6.6.6.6")]),
        lag=0.05,
    )
    args = build_parser().parse_args(["example.com", fake.address, "--json", "--settle", "0.5"])
    assert await _run(args) == 0
    payload = json.loads(capsys.readouterr().out)
    evidence = payload["evidence"]
    assert evidence["received"] == 2
    assert evidence["contested"] is True
    assert evidence["alternatives"] == [["6.6.6.6"]]
    assert evidence["last_ms"] > evidence["first_ms"]


async def test_markdown_table_for_addresses(
    make_resolver: MakeResolver, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.1.1.1", 60)])
    args = build_parser().parse_args(["example.com", fake.address, "--markdown", "--settle", "0.2"])
    assert await _run(args) == 0
    lines = capsys.readouterr().out.splitlines()
    assert cells(lines[0]) == list(ADDRESS_COLUMNS)
    assert all(set(cell) == {"-"} for cell in cells(lines[1]))
    row = cells(lines[2])
    assert row[0] == "1.1.1.1"
    assert row[1] == "A"
    assert row[2] == "60"
    assert row[3] == fake.address
    assert row[5].endswith("ms")  # when the reply arrived


async def test_markdown_table_is_one_row_per_reply(
    make_resolver: MakeResolver, capsys: pytest.CaptureFixture[str]
) -> None:
    # No aggregation: the same address from two resolvers is two rows.
    first = await make_resolver(answers=[rr_a("example.com", "1.1.1.1")])
    second = await make_resolver(answers=[rr_a("example.com", "1.1.1.1")])
    args = build_parser().parse_args(
        ["example.com", first.address, second.address, "--markdown", "--settle", "0.2"]
    )
    assert await _run(args) == 0
    rows = [cells(line) for line in capsys.readouterr().out.splitlines()[2:]]
    # Both resolvers answered, and nothing was merged into a single row.
    assert {row[3] for row in rows} == {first.address, second.address}
    assert sum(1 for row in rows if row[0] == "1.1.1.1") == 2


async def test_markdown_table_for_handshakes(
    make_resolver: MakeResolver, tls_server: tuple[str, int], capsys: pytest.CaptureFixture[str]
) -> None:
    host, port = tls_server
    fake = await make_resolver(answers=[rr_a("example.com", host, 30)])
    args = build_parser().parse_args(
        [f"example.com:{port}", fake.address, "--markdown", "--tls", "--insecure"]
    )
    assert await _run(args) == 0
    lines = capsys.readouterr().out.splitlines()
    header = cells(lines[0])
    assert header == list(_timing_table(args))
    row = next(cells(line) for line in lines[2:] if cells(line)[0] == f"{host}:{port}")
    assert row[header.index("handshake")].endswith("ms")
    assert row[header.index("resolver")] == fake.address
    assert row[header.index("tls")] == "TLSv1.3"


async def test_markdown_puts_the_injection_in_the_table(
    make_resolver: MakeResolver, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = await make_resolver(
        answers=[rr_a("example.com", "1.1.1.1")],
        forgery=lambda query: build_reply(query, answers=[rr_a("example.com", "6.6.6.6")]),
        lag=0.05,
    )
    args = build_parser().parse_args(["example.com", fake.address, "--markdown", "--settle", "0.5"])
    assert await _run(args) == 0
    captured = capsys.readouterr()
    rows = [cells(line) for line in captured.out.splitlines()[2:]]
    # Every reply is a row, in arrival order: the forged ones are marked, the
    # last one is the answer that was used.
    assert {row[0] for row in rows} >= {"6.6.6.6", "1.1.1.1"}
    assert rows[0][6] == "injected"
    assert float(rows[-1][5].removesuffix("ms")) > float(rows[0][5].removesuffix("ms"))
    assert captured.err == ""


async def test_markdown_of_a_literal_target(capsys: pytest.CaptureFixture[str]) -> None:
    assert await _run(build_parser().parse_args(["1.1.1.1", "--markdown"])) == 0
    lines = capsys.readouterr().out.splitlines()
    assert cells(lines[0]) == list(ADDRESS_COLUMNS)
    assert cells(lines[2])[0] == "1.1.1.1"


def test_json_and_markdown_do_not_mix() -> None:
    with pytest.raises(SystemExit) as info:
        build_parser().parse_args(["example.com", "--json", "--markdown"])
    assert info.value.code == 2


def test_short_error_labels() -> None:
    assert (
        _short_error("TimeoutError: [Errno 60] Connect call failed ('1.2.3.4', 443)") == "timeout"
    )
    assert (
        _short_error("ConnectionRefusedError: [Errno 61] Connect call failed ('127.0.0.1', 1)")
        == "refused"
    )
    assert _short_error("SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] ...") == (
        "certificate"
    )
    assert _short_error("DnsTimeout: no reply from 1.1.1.1 within 2.00s") == "no reply"
    assert _short_error("OSError: [Errno 65] No route to host") == "unreachable"
    assert _short_error("MessageFormatError: nonsense") == "malformed"
    assert _short_error("WeirdError without detail") == "weird"


def test_arrival_notes() -> None:
    forged = Arrival(0.0008, (Address("6.6.6.6"),), 0, False, 48)
    real = Arrival(0.0514, (Address("1.1.1.1"),), 0, True, 48)
    contested = Evidence(received=2, alternatives=(("6.6.6.6",),), arrivals=(forged, real))
    assert _arrival_note(forged, contested) == "injected"
    assert _arrival_note(real, contested) == ""
    duplicate = Evidence(received=2, arrivals=(forged, real))
    assert _arrival_note(forged, duplicate) == "duplicate"
    refused = Arrival(0.02, (), 5, True, 48)
    assert _arrival_note(refused, Evidence(arrivals=(refused,))) == "REFUSED"
    empty = Arrival(0.02, (), 0, True, 48)
    assert _arrival_note(empty, Evidence(arrivals=(empty,))) == "no addresses"


def test_short_evidence_note() -> None:
    evidence = Evidence(received=3, strays=12, mismatches=1, alternatives=(("6.6.6.6",),))
    assert _evidence_short(evidence) == "injected · 12 wrong ids · 1 mismatched"
    assert _evidence_short(Evidence(received=2)) == "duplicate"
    assert _evidence_short(Evidence()) == ""


async def test_markdown_table_lists_a_resolver_that_gave_nothing(
    make_resolver: MakeResolver, capsys: pytest.CaptureFixture[str]
) -> None:
    good = await make_resolver(answers=[rr_a("example.com", "1.1.1.1")])
    silent = await make_resolver(drop=True)
    args = build_parser().parse_args(
        ["example.com", good.address, silent.address, "--markdown", "--resolve-timeout", "0.3"]
    )
    assert await _run(args) == 0
    lines = capsys.readouterr().out.splitlines()
    rows = [cells(line) for line in lines[2:]]
    silent_row = next(row for row in rows if row[3] == silent.address)
    assert silent_row[0] == ""  # no address to show
    assert silent_row[6] == "no reply"


def test_markdown_widths_come_from_the_arguments() -> None:
    # The resolver addresses are on the command line, so their column is sized
    # for them; the timeouts bound the numbers, and -4 bounds the addresses.
    args = build_parser().parse_args(
        ["example.com:443", "2001:db8::53#53", "-4", "--connect-timeout", "2"]
    )
    resolvers = (ResolverSpec("2001:db8::53", 53),)
    timing = dict(
        zip(
            _timing_table(args),
            _table_widths(_timing_table(args), resolvers=resolvers, args=args, family=4),
            strict=True,
        )
    )
    assert timing["resolver"] == len("2001:db8::53")
    assert timing["handshake"] == max(len("handshake"), len("2000.0ms"))
    assert timing["note"] >= len("injected")

    addresses = dict(
        zip(
            ADDRESS_COLUMNS,
            _table_widths(ADDRESS_COLUMNS, resolvers=resolvers, args=args, family=4),
            strict=True,
        )
    )
    assert addresses["address"] == 15  # IPv4 only
    assert addresses["time"] == len("2000.0ms")


async def test_markdown_lines_are_all_the_same_width(
    make_resolver: MakeResolver, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = await make_resolver(answers=[rr_a("example.com", "1.1.1.1")])
    args = build_parser().parse_args(["example.com", fake.address, "--markdown", "--settle", "0.2"])
    assert await _run(args) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len({len(line) for line in lines}) == 1
