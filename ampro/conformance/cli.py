"""``ampro-conformance`` -- run the AMP black-box conformance suite.

Examples::

    ampro-conformance --url https://agent.example.com
    ampro-conformance --url https://agent.example.com --level 1 --report json
    ampro-conformance --url https://agent.example.com \\
        --signing-key key.pem --keyid "agent://me.example.com#key-1"

Exit status: 0 when every MUST check passed, 1 when a MUST check failed,
2 on usage errors.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from ampro.conformance.signing import Signer, load_signing_key
from ampro.conformance.suite import check_specs, run_conformance


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ampro-conformance",
        description="Black-box AMP conformance suite (docs/CONFORMANCE.md).",
    )
    p.add_argument("--url", help="origin of the agent under test, e.g. https://agent.example.com")
    p.add_argument("--level", type=int, choices=range(0, 6), metavar="0..5",
                   help="highest conformance level to test (default: the level declared in agent.json, at least 1)")
    p.add_argument("--signing-key", help="Ed25519 private key (PEM file, or hex/base64 seed, or a file holding one)")
    p.add_argument("--keyid", help="RFC 9421 keyid registered with the target for --signing-key")
    p.add_argument("--sender", help="envelope sender (default: the keyid's agent address)")
    p.add_argument("--sender-bound", action="store_true",
                   help="the key is bound to --sender; also check that other senders get 403")
    p.add_argument("-H", "--header", action="append", default=[], metavar="'Name: value'",
                   help="extra HTTP header for every request (repeatable)")
    p.add_argument("--probe-rate-limit", type=int, default=0, metavar="N",
                   help="send up to N messages to provoke and check a 429")
    p.add_argument("--skip-large", action="store_true", help="skip the 10 MiB message-size checks")
    p.add_argument("--only", action="append", default=[], metavar="PREFIX",
                   help="run only checks whose id starts with PREFIX (repeatable)")
    p.add_argument("--timeout", type=float, default=15.0, help="per-request timeout in seconds")
    p.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    p.add_argument("--report", choices=("table", "json"), default="table", help="output format")
    p.add_argument("--output", type=Path, help="also write the JSON report to this file")
    p.add_argument("--list", action="store_true", help="list the checks and exit")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)

    if args.list:
        for s in check_specs():
            key = " (needs --signing-key)" if s.needs_key else ""
            print(f"L{s.level}  {s.requirement:<6} {s.section:<20} {s.id}  {s.title}{key}")
        return 0
    if not args.url:
        print("ampro-conformance: --url is required", file=sys.stderr)
        return 2
    if bool(args.signing_key) != bool(args.keyid):
        print("ampro-conformance: --signing-key and --keyid go together", file=sys.stderr)
        return 2

    headers = {}
    for h in args.header:
        name, sep, value = h.partition(":")
        if not sep or not name.strip():
            print(f"ampro-conformance: bad --header {h!r}", file=sys.stderr)
            return 2
        headers[name.strip()] = value.strip()

    signer = None
    if args.signing_key:
        try:
            signer = Signer(load_signing_key(args.signing_key), args.keyid)
        except (OSError, ValueError) as exc:
            print(f"ampro-conformance: cannot load signing key: {exc}", file=sys.stderr)
            return 2

    report = asyncio.run(run_conformance(
        args.url,
        level=args.level,
        signer=signer,
        sender=args.sender,
        sender_bound=args.sender_bound,
        headers=headers,
        probe_rate_limit=args.probe_rate_limit,
        skip_large=args.skip_large,
        only=args.only or None,
        timeout=args.timeout,
        verify=not args.insecure,
    ))

    doc = report.to_dict()
    if args.output:
        args.output.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    if args.report == "json":
        print(json.dumps(doc, indent=2))
    else:
        print(report.to_table())
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
