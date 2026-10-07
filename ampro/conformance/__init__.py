"""AMP black-box conformance suite.

Tests any AMP implementation over HTTP -- the target can be written in any
language.  Each check maps to a WIRE-BINDING section and a MUST / SHOULD
requirement; MUST failures make the run fail.

    ampro-conformance --url https://agent.example.com [--level 1..5] [--report json]

See ``docs/CONFORMANCE.md``.
"""
from __future__ import annotations

from ampro.conformance.model import CheckResult, CheckSpec, Report
from ampro.conformance.signing import Signer, load_signing_key
from ampro.conformance.suite import check_specs, run_conformance

__all__ = [
    "CheckResult",
    "CheckSpec",
    "Report",
    "Signer",
    "check_specs",
    "load_signing_key",
    "run_conformance",
]
