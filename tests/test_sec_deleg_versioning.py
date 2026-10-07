"""PROTOCOL-CONTRACTS: receivers MUST NOT reject unless MAJOR differs."""

from __future__ import annotations

import pytest

from ampro.core.versioning import check_version, negotiate_version


@pytest.mark.parametrize("v", ["1.0.1", "1.2.0", "1.0.0-beta", "1.9.9+build.7"])
def test_same_major_accepted(v):
    assert check_version(v) == "1.0.0"


def test_exact_supported_returned_verbatim():
    assert check_version("1.0.0") == "1.0.0"
    assert check_version("0.1.0") == "0.1.0"


@pytest.mark.parametrize("v", ["2.0.0", "99.0.0", "3.1.4"])
def test_different_major_rejected(v):
    with pytest.raises(ValueError, match="Unsupported"):
        check_version(v)


def test_negotiate_accepts_same_major():
    assert negotiate_version("2.0.0, 1.4.0") == "1.0.0"
