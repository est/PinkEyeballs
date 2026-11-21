<p align="center">
  <img src="assets/logo.png" alt="" width="150">
</p>

# PinkEyeballs

Ask several DNS servers the same question at once, then either take the answers
or time a TCP handshake to every one of them.

```console
$ pinkeyeballs example.com 1.1.1.1 8.8.8.8
203.0.113.10
203.0.113.11
2001:db8::10
2001:db8::11

$ pinkeyeballs example.com:443 1.1.1.1 8.8.8.8
203.0.113.10:443	24.1ms
[2001:db8::11]:443	26.4ms
[2001:db8::10]:443	27.0ms
203.0.113.11:443	41.2ms
```

## Install

Python 3.11+ on a POSIX system with libresolv: Linux (glibc), macOS, the BSDs.
There are no runtime dependencies — queries are built by libc's `res_mkquery`
and replies are walked by `ns_initparse` / `ns_parserr` / `ns_name_uncompress`
through `ctypes`.

```bash
python -m pip install -e ".[dev]"   # not on PyPI yet
```

## CLI

```
pinkeyeballs HOST[:PORT] [RESOLVER ...]
```

Just a host: print every address the resolvers return.  Host and port: time a
handshake to every address instead, and print that.  Results go to stdout as
they arrive, one per line, so the sorting is yours to choose:

```bash
pinkeyeballs example.com | sort -u
pinkeyeballs example.com:443 1.1.1.1 | sort -k2 -n | head -1     # fastest first
pinkeyeballs example.com:443 1.1.1.1 | awk -F'\t' '$2 != "-"'    # only reachable
```

`RESOLVER` is `ADDR` or `ADDR#PORT` (`#` so IPv6 needs no brackets); `-r` does
the same.  With none given the defaults are 1.1.1.1, 8.8.8.8 and 9.9.9.9.  An IP
literal needs no resolver at all:

```bash
pinkeyeballs 1.1.1.1:443          # time one address, no DNS
pinkeyeballs [2001:db8::53]:443
```

What is on stdout is results; what is on stderr is about the *resolvers* —
timeouts, NXDOMAIN, a fabrication caught by `--verify`.  Failures show up on
stderr even when results exist, so nothing is swallowed.

| option                      | meaning                                                                  |
| --------------------------- | ------------------------------------------------------------------------ |
| `--tls`                     | time the TLS handshake too, and report that instead of TCP               |
| `--insecure`                | with `--tls`, skip certificate verification                              |
| `--samples N`               | handshakes per address, reported as their median (1)                     |
| `--concurrency N`           | handshakes in flight (8)                                                 |
| `--connect-timeout SECONDS` | timeout per handshake (5.0)                                              |
| `--resolve-timeout SECONDS` | timeout per DNS question (2.0)                                           |
| `--verify`                  | canary and hop-limit check every answer before using it                  |
| `--slack HOPS`              | drift allowed before a reply counts as injected (6)                      |
| `-4` / `-6`                 | only IPv4 or only IPv6                                                   |
| `--settle SECONDS`          | keep listening this long after a reply, for one that arrives late (0.25) |
| `-v`, `--verbose`           | extra columns, and a line per resolver on stderr                         |
| `-q`, `--quiet`             | keep stderr for fatal errors only                                        |
| `--json`                    | one JSON object per line instead of columns                              |
| `--markdown`                | one markdown table, a row per reply, printed as it arrives               |

One handshake is measured by default, which is noisy on a real network;
`--samples 3` dials an address three times and reports the median (the spread
shows up under `-v`).  `--tls` adds the TLS handshake — the time reported becomes
that one — and `-v` spells out what came back:

```console
$ pinkeyeballs example.com:443 1.1.1.1 -v --tls --samples 3
1.1.1.1: 203.0.113.10, 203.0.113.11, IP TTL 64-12, 21.5ms
203.0.113.10:443	24.8ms	n=3 23.7-26.4ms	1.1.1.1	dns ttl 300	IP TTL 64-12	tcp 21.4ms	tls TLSv1.3 TLS_AES_256_GCM_SHA384 h2	cert CN=example.com (74d)
```

The resolver lines on stderr say what each resolver answered — the addresses
themselves, the CNAME it followed, the IP TTL of its reply in the form the hop
ladder reads it (`initial - hops`), the verdict of `--verify` and how long it
took.  The columns after the time are the sample spread, the resolver that
handed the address over, its DNS TTL, that reply's IP TTL, the TCP and TLS
handshake times, the negotiated protocol and, when the certificate was verified,
its name, its remaining life and its issuer.  `--json` carries all of it too:

```console
$ pinkeyeballs example.com:443 8.8.8.8 --tls --json
{"ip": "203.0.113.10", "family": 4, "port": 443, "source": "8.8.8.8", "started_ms": 12.4, "latency_ms": 24.8, "connect_ms": 21.4, "tls_ms": 24.8, "samples_ms": [24.8], "failures": 0, "tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "alpn": "h2", "certificate": {"subject": "CN=example.com", "issuer": "CN=Example CA, O=Example CA", "expires": "2030-01-01", "days_left": 74}, "error": null}
```

`latency_ms` is the median sample; a failure reports how long it took to fail,
and when the TCP handshake worked but TLS did not, `connect_ms` says so.

`--markdown` prints a table instead: one row per reply, in arrival order, as it
arrives.  Nothing is merged away, so the same address from two resolvers is two
rows, and a question that got two answers shows both:

```console
$ pinkeyeballs example.com 1.1.1.1 9.9.9.9 --markdown
| address                          | type | ttl     | resolver | ip ttl  | time     | note     |
| -------------------------------- | ---- | ------- | -------- | ------- | -------- | -------- |
| 203.0.113.10                     | A    | 300     | 1.1.1.1  | 64-12   | 24.4ms   |          |
| 203.0.113.11                     | A    | 300     | 1.1.1.1  | 64-12   | 24.4ms   |          |
| 2001:db8::10                     | AAAA | 300     | 1.1.1.1  | 64-12   | 25.1ms   |          |
|                                  | A    |         | 9.9.9.9  |         |          | no reply |
|                                  | AAAA |         | 9.9.9.9  |         |          | no reply |
```

The address comes first and the note last, with `time` — when that reply landed
— next to it.  `type` is the question that reply answers, so an A row and an
AAAA row are never confused.  `note` says the one thing worth saying: `injected`
for a reply that arrived behind the real one, `duplicate`, the rcode
(`REFUSED`), or why the resolver produced nothing.

Columns are padded to widths worked out from the run itself: the resolver
addresses come from the command line, the timeouts bound every time, and the
family bounds the addresses — nothing is hardcoded, and nothing is wider than it
has to be.  On a small terminal `-4` or `-6` narrows the table further:

```console
$ pinkeyeballs example.com 1.1.1.1 -4 --markdown
| address         | type | ttl     | resolver | ip ttl  | time     | note         |
| --------------- | ---- | ------- | -------- | ------- | -------- | ------------ |
| 203.0.113.10    | A    | 300     | 1.1.1.1  | 64-12   | 24.4ms   |              |
```

A timing run grows the columns the run asked for — `--samples` adds the spread,
`--tls` adds TCP, TLS, ALPN and the certificate — and always has the resolver,
DNS TTL, IP TTL and a note for failures:

```console
| endpoint                        | handshake | samples             | tcp      | tls     | alpn | certificate          | resolver | dns ttl | ip ttl | note |
| ------------------------------- | --------- | ------------------- | -------- | ------- | ---- | -------------------- | -------- | ------- | ------ | ---- |
| [2001:db8::11]:443              | 26.4ms    | 2/2 (26.0-26.9ms)   | 21.0ms   | TLSv1.3 | h2   | CN=example.com (74d) | 1.1.1.1  | 300     | 64-12  |      |
| 203.0.113.10:443                | 24.1ms    | 2/2 (23.8-24.5ms)   | 20.3ms   | TLSv1.3 | h2   | CN=example.com (74d) | 1.1.1.1  | 300     | 64-12  |      |
```

The cipher suite is left to `-v` and `--json`, where there is room for it.

Exit codes: `0` when something answered, `1` when nothing did, `2` for bad
arguments.

## Library

The CLI measures everything and sorts nothing.  The library also has the
Happy-Eyeballs stage, which is the other trade: start dialing as the answers
stream in, keep the first handshake that lands, cancel the rest.

```python
import asyncio

from pinkeyeballs import Endpoint, compare, dial, measure, probe_all, resolve


async def main() -> None:
    lookup = await resolve("example.com", ["1.1.1.1", "8.8.8.8"], verify=True)
    print(lookup.addresses[0], lookup.intercepted, compare(lookup).unanimous)

    # Keep the fastest handshake, DNS included:
    connection = await dial("example.com", 443, resolvers=["1.1.1.1"], attempt_delay=0.25)
    print(connection.endpoint, f"handshake {connection.attempts[0].latency * 1000:.1f} ms")
    for attempt in connection.attempts:
        print(attempt.status.value, attempt.endpoint, attempt.scheduled, attempt.error)
    await connection.aclose()

    # Or time every address and decide yourself:
    async for handshake in measure([Endpoint("1.1.1.1", 443)]):
        print(handshake.endpoint, handshake.latency, handshake.error)

    for result in await probe_all(["1.1.1.1", "8.8.8.8"]):
        print(result.resolver, result.verdict, result.hops, result.responder_hops)


asyncio.run(main())
```

The pieces are exported separately too: `query` / `exchange` for a single
question, `listen` for everything one question heard back (`Poll`: the datagrams,
the wrong-id strays, the mismatches), `resolve_stream` for answers as they
arrive, `canary` for the cheapest hijack check there is, and `race` for the
dialing stage over any iterator of `Endpoint`s, DNS optional.

`Exchange.evidence` is the wire evidence of one question (`Evidence`:
`received`, `contested`, `alternatives`, `strays`, `mismatches`, `first`,
`last`), and `Reply.evidence` carries it through resolution:

```python
exchange = await listen(build_query("example.com"), "1.1.1.1", timeout=2.0)
print(len(exchange.datagrams), exchange.strays, exchange.poisoned)
```

`measure()` yields a `Handshake` per address, in completion order, at most
`concurrency` at a time, and closes each socket as soon as it has been timed.
Give it a `TLS` and it times the TLS handshake too — the certificate, the
negotiated version, cipher and ALPN come back on the handshake — and
`samples=3` gets you a median instead of one noisy number:

```python
from pinkeyeballs import TLS

async for handshake in measure([Endpoint("1.1.1.1", 443)], tls=TLS("example.com"), samples=3):
    print(handshake.endpoint, handshake.latency, handshake.certificate, handshake.failures)
```

## Checking who answered

### Replies that arrive twice

A resolver answers a question once.  An injector has to answer *first* to be
believed, which means the real reply still arrives — just late.  So after a
reply the socket stays open for a moment longer (`--settle`, 250 ms by default;
raise it to hear a slower one, up to the whole `--resolve-timeout`) and
everything that comes back is counted:

```console
$ pinkeyeballs example.com 1.1.1.1 -v
1.1.1.1: injected replies: A: 3 answers to one question, sent 0.8ms to 143.2ms
apart; not 203.0.113.66; 12 datagrams with a wrong transaction id
1.1.1.1: 203.0.113.10, 203.0.113.11, IP TTL 64-12, 143.4ms
203.0.113.10	1.1.1.1	dns ttl 300	IP TTL 64-12
```

Three things are evidence, and none of them is normal:

* **more than one datagram** carrying our transaction id — and if they disagree
  about the content, the question is *contested*;
* **datagrams with the wrong transaction id** — nobody but a blind injector
  guessing ids sends those to an ephemeral port;
* **the timing** — the burst arrives at ~1 ms, the real reply at the real RTT.

The **last** reply is the one used, because the injected ones have to come
first; what the others said is reported next to it (`not 203.0.113.66`).  With
`--verify` a contested answer is rejected outright instead: the addresses are
dropped and the resolver shows up in `Lookup.intercepted`.

`--settle 0` returns on the first reply, which is exactly the behaviour an
injector wants: it is for measuring a clean network, not for checking a dirty
one.  `--settle 2` hears out a whole two seconds, for a network where the real
answer crawls in behind the forgery.

### Canary

A random name under the reserved `.invalid` zone has no answer to give, so one
that comes back with an address was invented:

```python
result = await canary("1.1.1.1")
print(result.verdict, result.rcode_name, result.addresses)
# clean NXDOMAIN ()
```

### Hop ladder

A reply's IP TTL is `initial - hops`: the sender starts at 64, 128 or 255 and
every router on the way decrements it, which is why `-v` prints it as
`IP TTL 128-22`.  Lowering the hop limit of the same question until replies stop
measures how far away the answer really comes from:

```python
result = await probe("8.8.8.8")
print(result.verdict, result.reply_ttl, result.hops, result.responder_hops, result.probed)
# clean 57 7 5 (6, 5, 4)
```

That resolver claims to be 7 hops away, but replies stop once the hop limit
drops below 6, so the answer comes from 5 hops out — close enough to be the
resolver itself.  The two distances should agree; when replies keep arriving
from a couple of hops away while the reply's own TTL claims a long path, that
TTL was not written by a sender at that distance.  Something close by is
answering for a remote resolver, and dressing the answer up to look remote.
Routes are not symmetric, so the numbers never match exactly, and `--slack`
(6 hops by default) is the drift allowed before a reply is called injected.

| verdict        | meaning                                                                                               |
| -------------- | ----------------------------------------------------------------------------------------------------- |
| `clean`        | nothing answers where the measured distance says nothing can                                          |
| `intercepted`  | an impossible name was answered, or replies come from far closer than their TTL claims                |
| `inconclusive` | the resolver is on the local segment (or the platform reports no TTL), so nothing can be pinned on it |
| `error`        | the check could not run: no reply, no route, unparseable answer                                       |

`--verify` runs both checks and drops the addresses of anything that fails them
(`Reply.intercepted`, `Lookup.intercepted`); the reasons go to stderr.  It is
opt-in because it costs extra queries — the canary one per resolver, the ladder
a handful per reply.

### Agreement

Every resolver is asked the same question, so the answers can be lined up.
Resolvers whose answers are compatible form a group, and a group nobody joined
is reported:

```python
agreement = compare(lookup)
print(agreement.unanimous, [str(opinion.resolver) for opinion in agreement.outliers])
```

This is the check that still works against a middlebox that answers honestly
about its own distance, which is exactly where the hop ladder runs out of road.
It reports rather than judges: CDNs hand out different addresses to different
resolvers on purpose, so a lone group means "these disagree", not "this one is
lying" — and with two resolvers that disagree there is no majority to blame.

## Design notes

* The timing mode measures every address and keeps none; the library's `dial()`
  races them and keeps the fastest.  The CLI is a measuring stick, the library
  is a Happy-Eyeballs client.
* Handshake time is the first completed TCP three-way handshake, timed from the
  moment that handshake starts.
* Names carry no trailing dot (`example.com`, and `.` for the root), matching
  what libresolv returns.
* The `ns_msg` / `ns_rr` layouts are checked against the raw header on every
  parse, so an ABI surprise raises instead of being misread.
* Truncated replies fall back to TCP; a TCP answer reports no reply TTL rather
  than guessing one.
* Nothing is cached and nothing is retried: one question, one timeout, and the
  report says what happened.

## Roadmap

- [ ] DoT/DoH transports, and resolvers discovered from `resolv.conf`
- [ ] An HTTP request on top of the handshake, to time the first byte
- [ ] RFC 8305 details: restart on RST, family fallback heuristics
- [ ] TTL-aware cache, off by default
- [ ] Document the `--json` schema
- [ ] Benchmarks against `curl` and `getaddrinfo`

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and PRs are welcome.

## License

MIT — see [LICENSE](LICENSE).
