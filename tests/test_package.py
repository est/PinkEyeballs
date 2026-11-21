"""Tests for the package surface itself."""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

import pinkeyeballs

ROOT = Path(__file__).resolve().parent.parent


def test_version_is_a_string() -> None:
    assert isinstance(pinkeyeballs.__version__, str)
    assert pinkeyeballs.__version__.count(".") >= 1


def test_every_export_exists_and_is_unique() -> None:
    names = pinkeyeballs.__all__
    assert len(names) == len(set(names))
    for name in names:
        assert hasattr(pinkeyeballs, name), name
    # The order itself is ruff's job (RUF022), and it wants constants first.
    assert names[0].isupper()


def test_key_names_are_exported() -> None:
    for name in [
        "Address",
        "Answer",
        "Attempt",
        "Connection",
        "Dialer",
        "Endpoint",
        "Exchange",
        "HopLadder",
        "Lookup",
        "Probe",
        "Reply",
        "ResolverSpec",
        "dial",
        "hop_budget",
        "probe",
        "probe_all",
        "query",
        "race",
        "resolve",
        "resolve_stream",
        "walk_hop_limits",
    ]:
        assert hasattr(pinkeyeballs, name)


def test_error_hierarchy() -> None:
    from pinkeyeballs import (
        DialFailed,
        DialTimeout,
        DnsTimeout,
        MessageFormatError,
        NoAddresses,
        PinkEyeballsError,
        PlatformError,
        QueryBuildError,
    )

    for error in (
        DialFailed,
        DialTimeout,
        DnsTimeout,
        MessageFormatError,
        NoAddresses,
        PlatformError,
        QueryBuildError,
    ):
        assert issubclass(error, PinkEyeballsError)


def test_package_declares_no_runtime_dependencies() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert project["dependencies"] == []
    assert project["requires-python"] == ">=3.11"


def test_module_can_be_run_as_a_program() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "pinkeyeballs", "--version"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"},
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.startswith("pinkeyeballs ")


def test_py_typed_marker_ships() -> None:
    assert (ROOT / "src" / "pinkeyeballs" / "py.typed").exists()


def test_no_stale_modules_remain() -> None:
    for name in ("models.py", "race.py", "resolver.py"):
        assert not (ROOT / "src" / "pinkeyeballs" / name).exists()


@pytest.mark.parametrize(
    "module", ["pinkeyeballs.wire", "pinkeyeballs.dns", "pinkeyeballs.dial", "pinkeyeballs.hijack"]
)
def test_submodules_import(module: str) -> None:
    __import__(module)
