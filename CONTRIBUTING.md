# Contributing

Thanks for taking a look at PinkEyeballs.

## Development setup

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
```

The package itself has no runtime dependencies: it talks to libresolv through
`ctypes`. Development is therefore POSIX-only (Linux/glibc, macOS, the BSDs); if
you are porting it somewhere else, start with `pinkeyeballs/wire.py`, which is
where every libc symbol is bound.

## Checks

```bash
ruff check .
ruff format --check .
mypy
pytest
```

All four run in CI; please make them pass locally before opening a PR.

## Style

- Keep the code typed (`disallow_untyped_defs` is on) and in the `src/` layout.
- Tests must not depend on public DNS or any external network access. Use the
  fake resolvers in `tests/conftest.py`: they answer only for the names they
  know (NXDOMAIN otherwise), can emulate distance by answering only above a
  given received IP TTL, lie about their own reply TTL, truncate, speak TCP,
  stay silent, or answer anything at all like a hijacker.  They can also play an
  injector: `forgery=` a reply to send first, `lag=` how late the real one
  follows, `strays=` datagrams with a wrong transaction id, `duplicate=` extra
  copies of the real answer.
- A few tests need the platform to report the IP TTL on loopback; they take the
  `requires_ttl` fixture and skip where it does not.
- User-visible behaviour changes go in the README and get a test.

## Pull requests

Small, focused commits with a clear message are preferred. If a change touches
the public API, mention it in `README.md`. By contributing you agree that your
changes are licensed under the MIT license.
