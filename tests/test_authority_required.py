"""403 ``urn:amp:error:authority-required`` (WIRE-BINDING 7.2.14).

Builder, typed members and their bounds, parsing of received problems,
the MCP ``insufficient_scope`` challenge, the server mapping of
:class:`AuthorityRequiredError`, the client's typed view, and the A2A /
PACT ``AuthRequired`` conversion.
"""
from __future__ import annotations

import json

import httpx
import pytest
from pydantic import ValidationError

from ampro.interop.a2a import AuthRequired
from ampro.wire.errors import (
    MAX_CONSTRAINT_BYTES,
    MAX_MISSING_SCOPES,
    MAX_REQUIRED_CONSTRAINTS,
    AuthorityConstraint,
    AuthorityRequiredError,
    AuthorityRequiredProblem,
    ErrorType,
    HumanApproval,
    PaymentRequirement,
    ProblemDetail,
    authority_required,
    insufficient_scope_challenge,
    parse_authority_required,
)

URN = "urn:amp:error:authority-required"
APPROVE = "https://auth.example.com/device?user_code=WDJB-MJHT"


def test_urn_follows_pattern():
    assert ErrorType.AUTHORITY_REQUIRED == URN


class TestBuilder:
    def test_full(self):
        p = authority_required(
            "Need orders:write",
            missing_scopes=["orders:write", "orders:read", "orders:write"],
            required_constraints=[{"type": "com.acme:region", "region": "eu"}],
            payment_required={"amount": 1250, "currency": "EUR", "methods": ["x402", "card"]},
            human_approval={"verification_uri": APPROVE, "expires_in": 600},
            audience="agent://shop.example.com",
            instance="/agent/message",
        )
        assert p.type == URN and p.status == 403 and p.title == "Authority required"
        assert p.missing_scopes == ["orders:write", "orders:read"]  # deduplicated, ordered
        assert p.required_constraints[0].model_dump() == {"type": "com.acme:region", "region": "eu"}
        assert p.payment_required == PaymentRequirement(amount=1250, currency="EUR",
                                                        methods=["x402", "card"])
        assert p.human_approval == HumanApproval(verification_uri=APPROVE, expires_in=600)
        dumped = p.model_dump(mode="json", exclude_none=True)
        assert parse_authority_required(dumped) == p
        assert isinstance(p, ProblemDetail)

    def test_accepts_models(self):
        p = authority_required(
            required_constraints=[AuthorityConstraint(type="amp:max-cost", amount=5)],
            payment_required=PaymentRequirement(amount=1, currency="USD"),
            human_approval=HumanApproval(verification_uri=APPROVE),
        )
        assert p.human_approval and p.human_approval.expires_in is None

    def test_nothing_missing_rejected(self):
        with pytest.raises(ValidationError, match="at least one"):
            authority_required()

    def test_string_scopes_rejected(self):
        with pytest.raises(ValueError):
            authority_required(missing_scopes="orders:write")

    @pytest.mark.parametrize("scopes", [
        [""],
        ["has space"],
        ['quo"te'],
        ["back\\slash"],
        ["ünïcode"],
        ["a\nb"],
        ["s" * 257],
        [f"s{i}" for i in range(MAX_MISSING_SCOPES + 1)],
        [1],
    ])
    def test_bad_scopes(self, scopes):
        with pytest.raises(ValidationError):
            authority_required(missing_scopes=scopes)

    @pytest.mark.parametrize("constraint", [
        {},
        {"type": ""},
        {"type": "1starts-with-digit"},
        {"type": "has space"},
        {"type": "t" * 129},
        {"type": 5},
        {"type": "x", "blob": "a" * MAX_CONSTRAINT_BYTES},
        {"type": "x", "n": float("nan")},
    ])
    def test_bad_constraints(self, constraint):
        with pytest.raises(ValidationError):
            authority_required(required_constraints=[constraint])

    def test_too_many_constraints(self):
        with pytest.raises(ValidationError):
            authority_required(
                required_constraints=[{"type": "x"}] * (MAX_REQUIRED_CONSTRAINTS + 1))

    @pytest.mark.parametrize("payment", [
        {"amount": 0, "currency": "USD"},
        {"amount": -1, "currency": "USD"},
        {"amount": 1.5, "currency": "USD"},
        {"amount": "100", "currency": "USD"},
        {"amount": True, "currency": "USD"},
        {"amount": 2**53, "currency": "USD"},
        {"amount": 1, "currency": "usd"},
        {"amount": 1, "currency": "US"},
        {"amount": 1, "currency": "USDT"},
        {"amount": 1},
        {"currency": "USD"},
        {"amount": 1, "currency": "USD", "methods": ["X402"]},
        {"amount": 1, "currency": "USD", "methods": ["x402", "x402"]},
        {"amount": 1, "currency": "USD", "methods": ["m"] * 17},
        {"amount": 1, "currency": "USD", "methods": "x402"},
    ])
    def test_bad_payment(self, payment):
        with pytest.raises(ValidationError):
            authority_required(payment_required=payment)

    @pytest.mark.parametrize("approval", [
        {"verification_uri": "http://auth.example.com/device"},
        {"verification_uri": "javascript:alert(1)"},
        {"verification_uri": "https://user:pw@auth.example.com/device"},
        {"verification_uri": "https://auth.example.com/device#frag"},
        {"verification_uri": "https:///nohost"},
        {"verification_uri": "https://auth.example.com/a b"},
        {"verification_uri": "https://auth.example.com/é"},
        {"verification_uri": 'https://auth.example.com/"x'},
        {"verification_uri": "https://auth.example.com:99999/"},
        {"verification_uri": "https://auth.example.com/" + "a" * 2048},
        {"verification_uri": APPROVE, "expires_in": 0},
        {"verification_uri": APPROVE, "expires_in": 86_401},
        {"verification_uri": APPROVE, "expires_in": "600"},
        {"expires_in": 600},
    ])
    def test_bad_human_approval(self, approval):
        with pytest.raises(ValidationError):
            authority_required(human_approval=approval)

    @pytest.mark.parametrize("audience", ["", "a b", "x\r\ny", "a" * 2049])
    def test_bad_audience(self, audience):
        with pytest.raises(ValidationError):
            authority_required(missing_scopes=["s"], audience=audience)

    def test_overall_size_cap(self):
        constraints = [{"type": "x", "blob": "a" * 4000}] * MAX_REQUIRED_CONSTRAINTS
        scopes = [f"{i:03d}" + "s" * 250 for i in range(MAX_MISSING_SCOPES)]
        authority_required(required_constraints=constraints)  # each part alone fits
        with pytest.raises(ValidationError, match="larger than"):
            authority_required(required_constraints=constraints, missing_scopes=scopes)

    def test_constraint_nesting_bounded(self):
        deep: dict = {"type": "x"}
        node = deep
        for _ in range(20):
            node["n"] = {}
            node = node["n"]
        with pytest.raises(ValidationError, match="nested"):
            authority_required(required_constraints=[deep])


class TestParse:
    def _wire(self, **kw):
        return authority_required(missing_scopes=["s"], **kw).model_dump(
            mode="json", exclude_none=True)

    def test_roundtrip_ignores_unknown_members(self):
        data = {**self._wire(), "x-vendor": 1}
        assert parse_authority_required(data).missing_scopes == ["s"]

    def test_wrong_type(self):
        with pytest.raises(ValueError):
            parse_authority_required({**self._wire(), "type": "urn:amp:error:forbidden"})

    def test_wrong_status(self):
        with pytest.raises(ValueError):
            parse_authority_required({**self._wire(), "status": 401})

    def test_not_a_mapping(self):
        with pytest.raises(ValueError):
            parse_authority_required(["nope"])  # type: ignore[arg-type]

    def test_empty_requirements(self):
        with pytest.raises(ValueError):
            parse_authority_required({"type": URN, "title": "t", "status": 403})


class TestChallenge:
    def test_mcp_insufficient_scope(self):
        p = authority_required(missing_scopes=["files:read", "files:write"])
        assert insufficient_scope_challenge(p) == (
            'Bearer realm="amp", error="insufficient_scope", scope="files:read files:write"'
        )

    def test_resource_metadata(self):
        p = authority_required(missing_scopes=["s"])
        value = insufficient_scope_challenge(
            p, realm="mcp", resource_metadata="https://srv.example.com/.well-known/oauth-protected-resource")
        assert value.endswith(
            'resource_metadata="https://srv.example.com/.well-known/oauth-protected-resource"')

    def test_without_scopes(self):
        p = authority_required(human_approval={"verification_uri": APPROVE})
        assert "scope=" not in insufficient_scope_challenge(p)

    @pytest.mark.parametrize("realm", ['a"b', "", "x\r\n", "r" * 129])
    def test_bad_realm(self, realm):
        with pytest.raises(ValueError):
            insufficient_scope_challenge(authority_required(missing_scopes=["s"]), realm=realm)

    def test_bad_resource_metadata(self):
        with pytest.raises(ValueError):
            insufficient_scope_challenge(authority_required(missing_scopes=["s"]),
                                         resource_metadata='https://x.example/"')


class TestException:
    def test_from_kwargs(self):
        exc = AuthorityRequiredError("need more", missing_scopes=["s"])
        assert exc.to_problem().detail == "need more"
        assert "need more" in str(exc)
        assert exc.www_authenticate().startswith("Bearer ")

    def test_from_problem(self):
        p = authority_required(missing_scopes=["s"])
        assert AuthorityRequiredError(problem=p).problem is p

    def test_both_rejected(self):
        with pytest.raises(ValueError):
            AuthorityRequiredError(problem=authority_required(missing_scopes=["s"]),
                                   missing_scopes=["t"])

    def test_bad_problem_type(self):
        with pytest.raises(ValueError):
            AuthorityRequiredError(problem=ProblemDetail(type=URN, title="t", status=403))

    def test_requires_something(self):
        with pytest.raises(ValueError):
            AuthorityRequiredError()

    def test_is_amp_error(self):
        from ampro.errors import AmpError
        assert issubclass(AuthorityRequiredError, AmpError)


# ---------------------------------------------------------------------------
# Server and client
# ---------------------------------------------------------------------------


async def test_server_maps_error_to_403_problem():
    from tests.test_server_security_pipeline import envelope, make_server, post

    async def handler(msg, ctx):
        raise AuthorityRequiredError(
            "Need write access", missing_scopes=["orders:write"],
            human_approval={"verification_uri": APPROVE, "expires_in": 300})

    server, _ = make_server(handler=handler)
    resp = await post(server, envelope())
    assert resp.status == 403
    assert resp.headers["content-type"] == "application/problem+json"
    assert resp.headers["www-authenticate"] == (
        'Bearer realm="amp", error="insufficient_scope", scope="orders:write"')
    body = json.loads(resp.body)
    assert body["type"] == URN
    assert parse_authority_required(body).human_approval.expires_in == 300


async def test_server_no_challenge_without_scopes():
    from tests.test_server_security_pipeline import envelope, make_server, post

    async def handler(msg, ctx):
        raise AuthorityRequiredError(payment_required={"amount": 100, "currency": "USD"})

    server, _ = make_server(handler=handler)
    resp = await post(server, envelope())
    assert resp.status == 403
    assert "www-authenticate" not in resp.headers
    assert json.loads(resp.body)["payment_required"] == {
        "amount": 100, "currency": "USD", "methods": []}


def _response(status: int, body: dict) -> httpx.Response:
    return httpx.Response(status, json=body,
                          request=httpx.Request("POST", "https://x.example/agent/message"))


def test_client_typed_view():
    from ampro.client.core import _raise_for_problem
    from ampro.client.errors import AmpProtocolError

    wire = authority_required(missing_scopes=["s"]).model_dump(mode="json", exclude_none=True)
    with pytest.raises(AmpProtocolError) as info:
        _raise_for_problem(_response(403, wire))
    assert info.value.authority is not None
    assert info.value.authority.missing_scopes == ["s"]


@pytest.mark.parametrize("status, body", [
    (401, {"type": URN, "title": "t", "status": 403, "missing_scopes": ["s"]}),   # HTTP mismatch
    (403, {"type": URN, "title": "t", "status": 403, "missing_scopes": ["bad scope"]}),
    (403, {"type": URN, "title": "t", "status": 403}),                            # nothing missing
    (403, {"type": "urn:amp:error:forbidden", "title": "t", "status": 403}),
])
def test_client_untyped_when_invalid(status, body):
    from ampro.client.core import _raise_for_problem
    from ampro.client.errors import AmpProtocolError

    with pytest.raises(AmpProtocolError) as info:
        _raise_for_problem(_response(status, body))
    assert info.value.authority is None


# ---------------------------------------------------------------------------
# A2A / PACT AuthRequired
# ---------------------------------------------------------------------------


class TestAuthRequiredMapping:
    def test_to_problem(self):
        exc = AuthRequired(["orders:write"], APPROVE, message="Please approve")
        p = exc.to_problem()
        assert p.missing_scopes == ["orders:write"]
        assert p.human_approval == HumanApproval(verification_uri=APPROVE)
        assert p.detail == "Please approve"

    def test_to_problem_rejects_http_uri(self):
        with pytest.raises(ValueError):
            AuthRequired(["s"], "http://auth.example.com/device").to_problem()

    def test_from_problem(self):
        p = authority_required("Approve", missing_scopes=["a"],
                               human_approval={"verification_uri": APPROVE})
        exc = AuthRequired.from_problem(p)
        assert exc.missing_scopes == ["a"]
        assert exc.verification_uri == APPROVE
        assert exc.message == "Approve"

    @pytest.mark.parametrize("extra", [
        {"required_constraints": [{"type": "x"}]},
        {"payment_required": {"amount": 1, "currency": "USD"}},
    ])
    def test_from_problem_refuses_to_drop_requirements(self, extra):
        p = authority_required(missing_scopes=["a"], **extra)
        with pytest.raises(ValueError):
            AuthRequired.from_problem(p)

    def test_from_problem_type_checked(self):
        with pytest.raises(ValueError):
            AuthRequired.from_problem(ProblemDetail(type=URN, title="t", status=403))  # type: ignore[arg-type]


def test_registry_and_schema():
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    errors = json.loads((root / "spec" / "registry" / "errors.json").read_text())
    entry = next(e for e in errors["entries"] if e["type"] == URN)
    assert entry["status"] == 403 and entry["section"] == "7.2.14"
    schema = json.loads((root / "spec" / "schemas" / "problem-authority-required.json").read_text())
    jsonschema = pytest.importorskip("jsonschema")
    validator = jsonschema.Draft202012Validator(schema)
    good = authority_required(missing_scopes=["s"]).model_dump(mode="json", exclude_none=True)
    assert validator.is_valid(good)
    assert not validator.is_valid({"type": URN, "title": "t", "status": 403})
    assert not validator.is_valid({**good, "status": 401})
    assert not validator.is_valid({**good, "missing_scopes": ["bad scope"]})


def test_exports():
    import ampro
    import ampro.wire as wire

    for name in ("AuthorityRequiredProblem", "AuthorityRequiredError", "authority_required",
                 "parse_authority_required", "insufficient_scope_challenge",
                 "AuthorityConstraint", "PaymentRequirement", "HumanApproval"):
        assert name in ampro.__all__ and name in wire.__all__
    assert AuthorityRequiredProblem is ampro.AuthorityRequiredProblem
