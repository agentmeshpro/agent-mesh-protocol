"""Tests for ampro.core.versioning — SemVer shape validation (#24)."""

from __future__ import annotations

import pytest

from ampro.core.versioning import (
    CURRENT_VERSION,
    SUPPORTED_VERSIONS,
    check_version,
)


class TestCheckVersion:
    def test_check_version_none_returns_current(self):
        assert check_version(None) == CURRENT_VERSION

    def test_check_version_supported_accepted(self):
        for version in SUPPORTED_VERSIONS:
            assert check_version(version) == version

    @pytest.mark.parametrize(
        "malformed",
        [
            "1",
            "1.0",
            "1.0.0.0",
            "v1.0.0",
            "one.zero.zero",
            "latest",
            "1.0.0-",       # empty pre-release
            "1.0.0+",       # empty build
            "1.0.0-!",      # invalid pre-release char
            "",
            " ",
            "1.0.0 drop",
        ],
    )
    def test_check_version_rejects_malformed(self, malformed: str):
        with pytest.raises(ValueError) as exc:
            check_version(malformed)
        assert "Malformed" in str(exc.value) or "Unsupported" in str(exc.value)

    def test_check_version_unsupported_semver_still_rejected(self):
        # Well-formed SemVer but unsupported version.
        with pytest.raises(ValueError) as exc:
            check_version("99.0.0")
        assert "Unsupported" in str(exc.value)

    def test_check_version_semver_with_prerelease_shape_accepted(self):
        # Pre-release shape is well-formed and shares MAJOR 1 with a
        # supported version → accepted (contract: reject only on MAJOR
        # mismatch); the server speaks its own 1.x version.
        assert check_version("1.0.0-beta") == "1.0.0"
