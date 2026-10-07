"""Delegation link format v2: whole-link signing, must-understand, agility,
principal, audience, typed constraints, revocation and credential refs."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from ampro.delegation.chain import DelegationChain, validate_chain
from ampro.delegation.v2 import (
    DelegationLinkV2,
    VerificationKey,
    authorize_action,
    canonical_link_v2_bytes,
    intent_digest,
    minor_units,
    new_link_id,
    sign_delegation_v2,
    validate_chain_v2,
)

A, B, C, D = (f"agent://{n}.example.com" for n in "abcd")
NOW = datetime.now(UTC).replace(microsecond=0)


def _ed() -> tuple[Ed25519PrivateKey, VerificationKey]:
    k = Ed25519PrivateKey.generate()
    raw = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return k, VerificationKey("EdDSA", raw)


def _p256() -> tuple[ec.EllipticCurvePrivateKey, VerificationKey]:
    k = ec.generate_private_key(ec.SECP256R1())
    raw = k.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return k, VerificationKey("ES256", raw)


KEYS = {A: _ed(), B: _ed(), C: _p256(), D: _ed()}
RESOLVER = {(agent, "k1"): pub for agent, (_, pub) in KEYS.items()}


def _link(delegator: str, delegate: str, **over) -> dict:
    base = {
        "v": 2,
        "link_id": new_link_id(),
        "delegator": delegator,
        "delegate": delegate,
        "scopes": ["orders:*"],
        "max_depth": 3,
        "created_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(hours=1),
        "alg": KEYS[delegator][1].alg,
        "kid": "k1",
    }
    base.update(over)
    return base


def _sign(data: dict, parent: DelegationLinkV2 | None = None) -> DelegationLinkV2:
    return sign_delegation_v2(KEYS[data["delegator"]][0], data, parent)


def _chain(*datas: dict) -> list[DelegationLinkV2]:
    out: list[DelegationLinkV2] = []
    for d in datas:
        out.append(_sign(d, out[-1] if out else None))
    return out


def _ok(links, **kw):
    kw.setdefault("presenter", links[-1].delegate)
    return validate_chain_v2(links, RESOLVER, **kw)


# ---------------------------------------------------------------------------
# Happy paths and algorithm agility
# ---------------------------------------------------------------------------


def test_single_hop_eddsa_valid():
    assert _ok(_chain(_link(A, B))) == (True, "valid")


def test_three_hops_mixed_algorithms_valid():
    links = _chain(
        _link(A, B, max_depth=3),
        _link(B, C, max_depth=2, scopes=["orders:read"]),
        _link(C, D, max_depth=1, scopes=["orders:read"]),
    )
    assert links[2].alg == "ES256"
    assert _ok(links) == (True, "valid")


def test_algorithm_must_match_the_key():
    # Link claims EdDSA but the resolver's key for C is ES256.
    with pytest.raises(ValueError):
        sign_delegation_v2(KEYS[C][0], _link(C, D, alg="EdDSA"))
    link = _sign(_link(A, B))
    wrong = {(A, "k1"): VerificationKey("ES256", KEYS[C][1].public_key)}
    assert validate_chain_v2([link], wrong, presenter=B)[0] is False


def test_unknown_alg_rejected():
    with pytest.raises(ValidationError):
        DelegationLinkV2.model_validate(_link(A, B, alg="HS256"))


def test_unknown_kid_rejected():
    link = _sign(_link(A, B, kid="other"))
    ok, why = _ok([link])
    assert not ok and "unknown key" in why


def test_resolver_exception_fails_closed():
    def boom(agent, kid):
        raise RuntimeError("network")

    assert validate_chain_v2(_chain(_link(A, B)), boom, presenter=B) == (
        False, "link 0: key lookup failed")


# ---------------------------------------------------------------------------
# Whole-link signing and downgrade resistance
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("scopes", ["*"]),
        ("max_depth", 4),
        ("trust_tier", "owner"),
        ("expires_at", NOW + timedelta(hours=2)),
        ("aud", ["agent://evil.example.com"]),
        ("com.acme.limit", 5),
    ],
)
def test_any_tampered_member_breaks_signature(field, value):
    link = _sign(_link(A, B, **{"com.acme.limit": 1}))
    data = link.model_dump()
    data.update(link.extension_members)
    data[field] = value
    tampered = DelegationLinkV2.model_validate(data)
    ok, why = _ok([tampered])
    assert not ok and "invalid signature" in why


def test_added_extension_member_breaks_signature():
    link = _sign(_link(A, B))
    data = link.model_dump() | {"com.acme.added": True}
    ok, why = _ok([DelegationLinkV2.model_validate(data)])
    assert not ok and "invalid signature" in why


def test_stripping_version_turns_link_into_unverifiable_v1():
    link = _sign(_link(A, B))
    raw = {k: v for k, v in link.model_dump(mode="json").items() if v is not None}
    raw.pop("v")
    chain = DelegationChain.model_validate({"links": [raw]})
    assert chain.version == 1
    ok, _ = validate_chain(chain, {A: KEYS[A][1].public_key}, allow_v1=True)
    assert not ok


def test_unknown_version_and_mixed_chains_rejected():
    v2 = _sign(_link(A, B)).model_dump(mode="json")
    v1 = {"delegator": B, "delegate": C, "scopes": ["orders:read"],
          "created_at": "2026-01-01T00:00:00Z", "expires_at": "2099-01-01T00:00:00Z"}
    for bad in ({**v2, "v": 3}, {**v2, "v": True}, {**v2, "v": "2"}):
        with pytest.raises(ValidationError):
            DelegationChain.model_validate({"links": [bad]})
    with pytest.raises(ValidationError):
        DelegationChain.model_validate({"links": [v2, v1]})


def test_validate_chain_dispatches_v2_and_needs_keys():
    chain = DelegationChain.model_validate(
        {"links": [link.model_dump(mode="json") for link in _chain(_link(A, B))]}
    )
    assert chain.version == 2
    assert validate_chain(chain) == (False, "v2 chain needs a key resolver (keys=...)")
    assert validate_chain(chain, keys=RESOLVER)[0] is False  # no presenter
    assert validate_chain(chain, keys=RESOLVER, presenter=B) == (True, "valid")


def test_allow_v1_false_refuses_v1():
    v1 = DelegationChain.model_validate({"links": [{
        "delegator": A, "delegate": B, "scopes": ["x"],
        "created_at": "2026-01-01T00:00:00Z", "expires_at": "2099-01-01T00:00:00Z"}]})
    assert validate_chain(v1, {})[0] is False  # v1 refused by default
    assert "not accepted" in validate_chain(v1, {}, allow_v1=False)[1]


def test_link_transplanted_to_another_parent_fails():
    first = _chain(_link(A, B), _link(B, C, max_depth=2, scopes=["orders:read"]))
    other_root = _sign(_link(A, B))
    ok, why = _ok([other_root, first[1]])
    assert not ok and "invalid signature" in why


def test_duplicate_link_id_rejected():
    lid = new_link_id()
    links = _chain(_link(A, B, link_id=lid), _link(B, C, link_id=lid, max_depth=2))
    assert _ok(links) == (False, "link 1: duplicate link_id")


# ---------------------------------------------------------------------------
# Must-understand
# ---------------------------------------------------------------------------


def test_critical_extension_not_understood_rejected():
    links = _chain(_link(A, B, **{"com.acme.geo": "eu", "crit": ["com.acme.geo"]}))
    assert _ok(links)[0] is False
    assert _ok(links, understood_extensions={"com.acme.geo"}) == (True, "valid")


def test_noncritical_extension_ignored_but_signed():
    links = _chain(_link(A, B, **{"com.acme.note": "hi"}))
    assert _ok(links) == (True, "valid")


@pytest.mark.parametrize(
    "over",
    [
        {"crit": ["com.acme.absent"]},
        {"crit": ["scopes"]},
        {"crit": ["com.acme.x", "com.acme.x"], "com.acme.x": 1},
        {"unnamespaced": 1},
        {"task.thing": 1},
        {"com.acme.f": 1.5},
        {"com.acme.big": 2**60},
    ],
)
def test_bad_extension_members_rejected(over):
    with pytest.raises(ValidationError):
        DelegationLinkV2.model_validate(_link(A, B, **over))


def test_child_cannot_drop_critical_extension():
    links = _chain(
        _link(A, B, **{"com.acme.geo": "eu", "crit": ["com.acme.geo"]}),
        _link(B, C, max_depth=2),
    )
    ok, why = _ok(links, understood_extensions={"com.acme.geo"})
    assert not ok and "drops critical extension" in why


def test_oversized_link_rejected():
    links = [DelegationLinkV2.model_validate(_link(A, B, **{"com.acme.blob": "x" * 20000}))]
    with pytest.raises(ValueError):
        canonical_link_v2_bytes(links[0])


# ---------------------------------------------------------------------------
# Principal, origin, presence and intent
# ---------------------------------------------------------------------------


PRINCIPAL = {"iss": "https://id.example.com", "sub": "pairwise-123", "present": True}


def test_principal_and_intent_carried_unchanged():
    intent = intent_digest({"merchant": "shop.example", "total_minor": 4200, "currency": "USD"})
    links = _chain(
        _link(A, B, principal=PRINCIPAL, intent_hash=intent),
        _link(B, C, max_depth=2, principal=PRINCIPAL, intent_hash=intent),
    )
    assert _ok(links) == (True, "valid")


@pytest.mark.parametrize(
    "child_over",
    [
        {"principal": {**PRINCIPAL, "sub": "someone-else"}},
        {"principal": None},
        {"origin": "oauth"},
    ],
)
def test_root_bound_members_cannot_change(child_over):
    root = _link(A, B, principal=PRINCIPAL)
    child = _link(B, C, max_depth=2, principal=PRINCIPAL)
    child.update(child_over)
    if child.get("origin") == "oauth":
        child["credential_refs"] = [{"type": "oauth-grant", "ref": "grant_1"}]
    ok, why = _ok(_chain(root, child))
    assert not ok and "differs from the root" in why


def test_non_agent_origin_needs_principal_and_reference():
    with pytest.raises(ValidationError):
        DelegationLinkV2.model_validate(_link(A, B, origin="oauth"))
    with pytest.raises(ValidationError):
        DelegationLinkV2.model_validate(_link(A, B, origin="oauth", principal=PRINCIPAL))
    DelegationLinkV2.model_validate(_link(
        A, B, origin="oauth", principal=PRINCIPAL,
        credential_refs=[{"type": "oauth-grant", "ref": "grant_1"}]))


@pytest.mark.parametrize(
    "principal",
    [
        {**PRINCIPAL, "iss": "http://id.example.com"},
        {**PRINCIPAL, "iss": "https://user@id.example.com"},
        {**PRINCIPAL, "present": "yes"},
        {**PRINCIPAL, "extra": 1},
    ],
)
def test_bad_principal_rejected(principal):
    with pytest.raises(ValidationError):
        DelegationLinkV2.model_validate(_link(A, B, principal=principal))


def test_intent_hash_requires_principal():
    with pytest.raises(ValidationError):
        DelegationLinkV2.model_validate(_link(A, B, intent_hash=intent_digest({"a": 1})))


def test_intent_digest_is_canonical_and_rejects_floats():
    assert intent_digest({"b": 1, "a": "x"}) == intent_digest({"a": "x", "b": 1})
    with pytest.raises(ValueError):
        intent_digest({"total": 12.5})


# ---------------------------------------------------------------------------
# Audience
# ---------------------------------------------------------------------------


SHOP = "agent://shop.example.com"


def test_audience_required_and_enforced():
    links = _chain(_link(A, B, aud=[SHOP]))
    assert _ok(links)[0] is False
    assert _ok(links, audience="agent://other.example.com")[0] is False
    assert _ok(links, audience=SHOP) == (True, "valid")


def test_child_cannot_widen_or_drop_audience():
    widen = _chain(_link(A, B, aud=[SHOP]),
                   _link(B, C, max_depth=2, aud=[SHOP, "agent://x.example.com"]))
    assert "aud widens" in _ok(widen, audience=SHOP)[1]
    drop = _chain(_link(A, B, aud=[SHOP]), _link(B, C, max_depth=2))
    assert "aud widens" in _ok(drop, audience=SHOP)[1]


# ---------------------------------------------------------------------------
# Typed constraints
# ---------------------------------------------------------------------------


AMOUNT = {"type": "amount", "currency": "USD", "max_minor": 5000}
BUDGET = {"type": "budget", "currency": "USD", "remaining_minor": 10000, "max_minor": 10000}
RES = {"type": "resource", "ids": ["order-1", "order-2"]}


@pytest.mark.parametrize(
    "child_constraints,needle",
    [
        ([], "drops parent constraint"),
        ([{**AMOUNT, "max_minor": 5001}], "raises the amount cap"),
        ([{**AMOUNT, "currency": "EUR"}], "drops parent constraint"),
    ],
)
def test_amount_constraints_only_narrow(child_constraints, needle):
    links = _chain(_link(A, B, constraints=[AMOUNT]),
                   _link(B, C, max_depth=2, constraints=child_constraints))
    ok, why = _ok(links)
    assert not ok and needle in why


def test_budget_count_resource_narrow():
    ok_links = _chain(
        _link(A, B, constraints=[BUDGET, {"type": "count", "max": 3}, RES]),
        _link(B, C, max_depth=2, constraints=[
            {**BUDGET, "remaining_minor": 4000}, {"type": "count", "max": 1},
            {"type": "resource", "ids": ["order-1"]}]),
    )
    assert _ok(ok_links) == (True, "valid")
    for bad, needle in (
        ({**BUDGET, "max_minor": 20000, "remaining_minor": 20000}, "raises the budget"),
        ({"type": "count", "max": 4}, "raises the count"),
        ({"type": "resource", "ids": ["order-3"]}, "adds resources"),
    ):
        parent_c = [BUDGET, {"type": "count", "max": 3}, RES]
        child_c = [c for c in parent_c if c["type"] != bad["type"]] + [bad]
        links = _chain(_link(A, B, constraints=parent_c),
                       _link(B, C, max_depth=2, constraints=child_c))
        ok, why = _ok(links)
        assert not ok and needle in why


@pytest.mark.parametrize(
    "constraint",
    [
        {"type": "amount", "currency": "usd", "max_minor": 1},
        {"type": "amount", "currency": "USD", "max_minor": 1.5},
        {"type": "amount", "currency": "USD", "max_minor": "100"},
        {"type": "amount", "currency": "USD", "max_minor": -1},
        {"type": "budget", "currency": "USD", "remaining_minor": 2, "max_minor": 1},
        {"type": "teleport", "to": "mars"},
        {"type": "resource", "ids": []},
    ],
)
def test_bad_constraints_rejected(constraint):
    with pytest.raises(ValidationError):
        DelegationLinkV2.model_validate(_link(A, B, constraints=[constraint]))


def test_duplicate_constraint_rejected():
    with pytest.raises(ValidationError):
        DelegationLinkV2.model_validate(_link(A, B, constraints=[AMOUNT, AMOUNT]))


def test_authorize_action():
    links = _chain(_link(A, B, constraints=[AMOUNT, RES]),
                   _link(B, C, max_depth=2, scopes=["orders:pay"],
                         constraints=[{**AMOUNT, "max_minor": 3000}, RES]))
    assert authorize_action(links, actor=links[-1].delegate, scope="orders:pay", amount_minor=3000, currency="USD",
                            resource_id="order-1") == (True, "authorized")
    assert not authorize_action(links, actor=links[-1].delegate, scope="orders:pay", amount_minor=3001,
                                currency="USD", resource_id="order-1")[0]
    assert not authorize_action(links, actor=links[-1].delegate, scope="orders:pay", amount_minor=10,
                                currency="EUR", resource_id="order-1")[0]
    assert not authorize_action(links, actor=links[-1].delegate, scope="orders:pay", spends_money=True,
                                resource_id="order-1")[0]
    assert not authorize_action(links, actor=links[-1].delegate, scope="orders:pay", amount_minor=10, currency="USD",
                                resource_id="order-9")[0]
    assert not authorize_action(links, actor=links[-1].delegate, scope="orders:refund", amount_minor=10,
                                currency="USD", resource_id="order-1")[0]
    assert not authorize_action(links, actor=links[-1].delegate, scope="orders:pay", amount_minor=True,  # type: ignore[arg-type]
                                currency="USD", resource_id="order-1")[0]


def test_spending_without_any_money_limit_refused():
    links = _chain(_link(A, B))
    ok, why = authorize_action(links, actor=links[-1].delegate, scope="orders:pay", amount_minor=1, currency="USD")
    assert not ok and "no amount or budget limit" in why
    assert authorize_action(links, actor=links[-1].delegate, scope="orders:read") == (True, "authorized")


def test_minor_units():
    assert minor_units("12.34", 2) == 1234
    assert minor_units("12", 2) == 1200
    assert minor_units("500", 0) == 500
    assert minor_units("1.234", 3) == 1234
    for bad, exp in (("12.345", 2), ("1.5", 0), ("-1", 2), ("1e3", 2), ("", 2), ("1.0", 9)):
        with pytest.raises(ValueError):
            minor_units(bad, exp)


# ---------------------------------------------------------------------------
# Credential references
# ---------------------------------------------------------------------------


JWT = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLXZhbHVl"


@pytest.mark.parametrize("ref", [JWT, "Bearer abc", "has space", "x" * 300])
def test_secrets_are_not_accepted_as_references(ref):
    with pytest.raises(ValidationError):
        DelegationLinkV2.model_validate(_link(
            A, B, origin="oauth", principal=PRINCIPAL,
            credential_refs=[{"type": "oauth-grant", "ref": ref}]))


def _ref(expires_at):
    return {"type": "ap2-mandate", "ref": "mandate_42", "expires_at": expires_at}


def test_link_cannot_outlive_its_credential():
    links = _chain(_link(A, B, origin="ap2", principal=PRINCIPAL,
                         credential_refs=[_ref(NOW + timedelta(minutes=10))]))
    ok, why = _ok(links)
    assert not ok and "outlives" in why


def test_expired_credential_rejected():
    links = _chain(_link(A, B, origin="ap2", principal=PRINCIPAL,
                         expires_at=NOW + timedelta(minutes=10),
                         credential_refs=[_ref(NOW - timedelta(minutes=5))]))
    ok, why = _ok(links)
    assert not ok and "has expired" in why


# ---------------------------------------------------------------------------
# Lifetime, revocation, key status
# ---------------------------------------------------------------------------


def test_unrevocable_links_are_short_lived():
    long = _chain(_link(A, B, expires_at=NOW + timedelta(days=2)))
    ok, why = _ok(long)
    assert not ok and "cannot be revoked" in why


def test_revocable_link_needs_a_revocation_check():
    links = _chain(_link(A, B, expires_at=NOW + timedelta(days=30),
                         status_url="https://a.example.com/status"))
    ok, why = _ok(links)
    assert not ok and "no revocation check" in why
    assert _ok(links, is_revoked=lambda lid: False) == (True, "valid")
    assert _ok(links, is_revoked=lambda lid: True) == (False, "link 0: revoked")

    def boom(lid):
        raise RuntimeError

    assert _ok(links, is_revoked=boom) == (False, "link 0: revocation check failed")


def test_lifetime_capped_even_when_revocable():
    links = _chain(_link(A, B, expires_at=NOW + timedelta(days=120),
                         status_url="https://a.example.com/status"))
    assert _ok(links, is_revoked=lambda lid: False)[0] is False


def test_compromised_key_rejected():
    links = _chain(_link(A, B))
    assert _ok(links, key_status=lambda agent, kid, at: False)[0] is False

    def boom(agent, kid, at):
        raise RuntimeError

    assert _ok(links, key_status=boom)[0] is False
    assert _ok(links, key_status=lambda agent, kid, at: True) == (True, "valid")


def test_fan_out_exhausted():
    links = _chain(_link(A, B, max_fan_out=1), _link(B, C, max_depth=2))
    assert _ok(links, fan_out_counts={links[0].link_id: 1})[0] is False
    assert _ok(links, fan_out_counts={links[0].link_id: 0}) == (True, "valid")


# ---------------------------------------------------------------------------
# Parsing strictness
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "over",
    [
        {"created_at": 1700000000},
        {"created_at": "2026-01-01 00:00:00"},
        {"created_at": datetime(2026, 1, 1)},
        {"max_depth": "3"},
        {"max_depth": True},
        {"max_depth": 11},
        {"link_id": "short"},
        {"scopes": []},
        {"scopes": ["a", "a"]},
        {"scopes": ["has space"]},
        {"trust_tier": "god"},
        {"jwks_url": "http://a.example.com/jwks"},
        {"status_url": "https://a.example.com/s#frag"},
        {"expires_at": NOW - timedelta(hours=2)},
        {"aud": []},
    ],
)
def test_strict_parsing(over):
    with pytest.raises(ValidationError):
        DelegationLinkV2.model_validate(_link(A, B, **over))


def test_self_delegation_rejected():
    data = _link(A, B)
    data["delegate"] = A
    with pytest.raises(ValidationError):
        DelegationLinkV2.model_validate(data)


def test_chain_length_capped():
    with pytest.raises(ValidationError):
        DelegationLinkV2.model_validate(_link(A, B, max_depth=11))
    links = _chain(_link(A, B))
    assert validate_chain_v2(links * 11, RESOLVER, presenter=B)[0] is False


def test_expired_and_future_links_rejected():
    old = _chain(_link(A, B, created_at=NOW - timedelta(hours=3),
                       expires_at=NOW - timedelta(hours=2)))
    assert "expired" in _ok(old)[1]
    future = _chain(_link(A, B, created_at=NOW + timedelta(hours=1),
                          expires_at=NOW + timedelta(hours=2)))
    assert "future" in _ok(future)[1]


# ---------------------------------------------------------------------------
# Hardening found in review
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "over",
    [
        {"created_at": "0001-01-01T00:30:00+23:59", "expires_at": "0001-01-02T00:00:00Z"},
        {"expires_at": "9999-12-31T23:59:59-23:59"},
        {"created_at": "1969-12-31T00:00:00Z"},
    ],
)
def test_out_of_range_timestamps_rejected_at_parse(over):
    with pytest.raises(ValidationError):
        DelegationLinkV2.model_validate(_link(A, B, **over))


def test_validate_never_raises():
    link = DelegationLinkV2.model_construct(**_link(A, B), signature="AAAA")
    link.created_at = datetime.max.replace(tzinfo=UTC)
    ok, why = _ok([link])
    assert ok is False


def test_presenter_must_be_final_delegate():
    links = _chain(_link(A, B), _link(B, C, max_depth=2))
    assert _ok(links, presenter=D)[0] is False
    assert _ok(links, presenter=B)[0] is False  # B holds link 0, not this chain
    assert _ok(links[:1], presenter=B) == (True, "valid")  # B presenting its own grant


def _crit_chain(child_value, child_crit=True):
    root = _link(A, B, **{"com.acme.max_items": 5, "crit": ["com.acme.max_items"]})
    child = _link(B, C, max_depth=2)
    if child_value is not None:
        child["com.acme.max_items"] = child_value
    if child_crit and child_value is not None:
        child["crit"] = ["com.acme.max_items"]
    return _chain(root, child)


def test_critical_extension_cannot_be_widened_or_blanked():
    understood = {"com.acme.max_items"}
    assert _ok(_crit_chain(5), understood_extensions=understood) == (True, "valid")
    assert "changes critical" in _ok(_crit_chain(10**6), understood_extensions=understood)[1]
    assert "drops critical" in _ok(_crit_chain(None), understood_extensions=understood)[1]
    assert "drops critical" in _ok(
        _crit_chain(5, child_crit=False), understood_extensions=understood)[1]


def test_critical_extension_narrowing_function():
    def boom(p, c):
        raise RuntimeError

    rules = {"com.acme.max_items": lambda p, c: isinstance(c, int) and c <= p}
    assert _ok(_crit_chain(3), understood_extensions=rules) == (True, "valid")
    assert "widens critical" in _ok(_crit_chain(9), understood_extensions=rules)[1]
    assert _ok(_crit_chain(3), understood_extensions={"com.acme.max_items": boom})[0] is False


def test_null_critical_member_rejected_at_parse():
    with pytest.raises(ValidationError):
        DelegationLinkV2.model_validate(
            _link(A, B, **{"com.acme.x": None, "crit": ["com.acme.x"]}))


def test_trust_tier_cannot_rise():
    links = _chain(_link(A, B, trust_tier="verified"),
                   _link(B, C, max_depth=2, trust_tier="internal"))
    assert "trust_tier rises" in _ok(links)[1]
    lower = _chain(_link(A, B, trust_tier="verified"),
                   _link(B, C, max_depth=2, trust_tier="external"))
    assert _ok(lower) == (True, "valid")


def test_budget_needs_spend_tracking():
    links = _chain(_link(A, B, constraints=[BUDGET]))
    kw = dict(actor=B, scope="orders:pay", amount_minor=6000, currency="USD")
    assert "spend tracking" in authorize_action(links, **kw)[1]
    assert authorize_action(links, spent_minor=lambda lid: 0, **kw) == (True, "authorized")
    assert "budget remaining" in authorize_action(links, spent_minor=lambda lid: 4001, **kw)[1]
    assert not authorize_action(links, spent_minor=lambda lid: -5, **kw)[0]

    def boom(lid):
        raise RuntimeError

    assert not authorize_action(links, spent_minor=boom, **kw)[0]


def test_spending_flag_requires_amount_and_actor_must_match():
    links = _chain(_link(A, B, constraints=[AMOUNT]))
    assert not authorize_action(links, actor=B, scope="orders:pay", spends_money=True)[0]
    assert not authorize_action(links, actor=C, scope="orders:read")[0]
    assert authorize_action(links, actor=B, scope="orders:read") == (True, "authorized")


def test_oversized_link_refused_before_parsing():
    huge = _sign(_link(A, B)).model_dump(mode="json") | {"com.acme.blob": ["x" * 100] * 500}
    with pytest.raises(ValidationError, match="exceeds"):
        DelegationChain.model_validate({"links": [huge]})


def test_es256_high_s_rejected():
    import base64

    link = _sign(_link(C, D))
    sig = base64.urlsafe_b64decode(link.signature + "==")
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    s = int.from_bytes(sig[32:], "big")
    high = sig[:32] + (n - s).to_bytes(32, "big")
    flipped = link.model_copy(
        update={"signature": base64.urlsafe_b64encode(high).rstrip(b"=").decode()})
    assert _ok([link]) == (True, "valid")
    assert _ok([flipped]) == (False, "link 0: invalid signature")
