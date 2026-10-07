# Releasing ampro

## Pre-release checklist

Run these steps in order for every release. Do not skip.

1. All tests pass (`pytest -q` → 0 failures).
2. Run framework-purity check: `grep -rE "^(from|import) (django|flask|tornado|aiohttp|sanic)" ampro/` should return zero hits. The protocol package must remain framework-agnostic.
3. Bump `version` in `pyproject.toml`.
4. Bump `__version__` in `ampro/__init__.py`.
5. Add new `## [X.Y.Z] — YYYY-MM-DD` section at top of `CHANGELOG.md`.
6. Commit: `git commit -m "release: X.Y.Z — <summary>"`
7. Tag: `git tag -a vX.Y.Z -m "<release notes summary>"`
8. Push: `git push origin main && git push origin vX.Y.Z`
9. Create GitHub Release: `gh release create vX.Y.Z --notes-from-tag --verify-tag`

## Versioning

The protocol spec and the Python package are versioned together. A breaking change
to either the wire format or the public Python API requires a MAJOR bump.

```
0.x.y — Pre-1.0. API and wire format may evolve between minor versions.
x.Y.0 — Backwards-compatible additions (new body types, headers, streaming events).
x.y.Z — Patch: bug fixes, doc fixes, security fixes. No API changes.
1.0.0 — Stable. Wire format locked. Multiple platforms shipping.
```

Receivers MUST ignore unknown body types, headers, and streaming events — this is
what keeps additive changes non-breaking. Removing or redefining an existing
type/header/event is always a breaking change and requires a MAJOR bump.

## Installing a specific version

PyPI publication is pending; install from git until 1.0.

```bash
# Latest from main
pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git

# Pinned to a tag
pip install git+https://github.com/CatlystAI/agent-mesh-protocol.git@vX.Y.Z
```

Verify:

```bash
python -c "import ampro; print(ampro.__version__)"
```
