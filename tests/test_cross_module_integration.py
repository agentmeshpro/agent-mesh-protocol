"""
Cross-module integration tests for the Agent Mesh Protocol (ampro).

Tests 8 end-to-end flows that cross module boundaries, verifying that
modules which reference each other are properly wired.
"""

from __future__ import annotations

import sys
import traceback


def test_1_handshake_session_binding_message():
    """Handshake -> Session Binding -> Message"""
    from ampro import (
        AgentMessage,
        HandshakeState,
        HandshakeStateMachine,
        SessionEstablishedBody,
        SessionInitBody,
        create_message_binding,
        derive_binding_token,
        verify_message_binding,
    )

    # Full handshake flow
    sm = HandshakeStateMachine()
    init = SessionInitBody(
        proposed_capabilities=["messaging"],
        proposed_version="1.0.0",
        client_nonce="cn",
    )
    sm.transition("send_init")
    assert sm.state == HandshakeState.INIT_SENT

    est = SessionEstablishedBody(
        confirm_nonce="test-nonce-1",
        session_id="s1",
        negotiated_capabilities=["messaging"],
        negotiated_version="1.0.0",
        trust_tier="verified",
        trust_score=450,
        server_nonce="sn",
        binding_token=derive_binding_token("cn", "sn", "s1", "secret"),
    )
    sm.transition("receive_established")
    assert sm.state == HandshakeState.ESTABLISHED

    sm.transition("send_confirm")
    assert sm.state == HandshakeState.CONFIRMED

    sm.transition("activate")
    assert sm.state == HandshakeState.ACTIVE

    # Now create a bound message
    msg = AgentMessage(
        sender="agent://a.example.com",
        recipient="agent://b.example.com",
        body_type="message",
        body={"text": "hello"},
        headers={"Session-Id": "s1"},
    )
    hmac_val = create_message_binding("s1", msg.id, est.binding_token, body=msg.body)
    assert verify_message_binding(
        "s1", msg.id, est.binding_token, hmac_val, body=msg.body
    )
    # Body tampering must be detected
    assert not verify_message_binding(
        "s1", msg.id, est.binding_token, hmac_val, body={"text": "evil"}
    )

    # Negative: wrong binding token should fail
    assert not verify_message_binding("s1", msg.id, "wrong-token", hmac_val, body=msg.body)

    print("PASS: Handshake -> Session Binding -> Message")


def test_2_trust_score_policy_visibility():
    """Trust Score -> Trust Policy -> Visibility"""
    from ampro import (
        ContactPolicy,
        VisibilityLevel,
        calculate_trust_score,
        check_contact_allowed,
        filter_agent_json,
        score_to_policy,
    )

    ts = calculate_trust_score(
        age_days=365, interactions=1000, incidents=0,
        endorsements=3, identity_type="jwt",
    )
    policy = score_to_policy(ts.score)

    # Trust score should determine what visibility allows
    allowed = check_contact_allowed(ts.tier, ContactPolicy.VERIFIED_ONLY)
    filtered = filter_agent_json(
        {
            "protocol_version": "1.0.0",
            "identifiers": [],
            "endpoint": "https://x.example.com/agent/message",
            "capabilities": {"groups": ["messaging"]},
        },
        ts.tier,
        VisibilityLevel.AUTHENTICATED,
    )
    assert allowed  # verified tier can contact verified_only
    assert "capabilities" in filtered  # verified sees full agent.json

    # Negative: external tier should NOT pass verified_only
    assert not check_contact_allowed("external", ContactPolicy.VERIFIED_ONLY)

    # Negative: external tier sees stub under AUTHENTICATED visibility
    stub = filter_agent_json(
        {
            "protocol_version": "1.0.0",
            "identifiers": [],
            "endpoint": "https://x.example.com/agent/message",
            "capabilities": {"groups": ["messaging"]},
        },
        "external",
        VisibilityLevel.AUTHENTICATED,
    )
    assert "capabilities" not in stub
    assert "protocol_version" in stub

    print("PASS: Trust Score -> Policy -> Visibility")


def test_3_delegation_cost_receipt_task_complete():
    """Delegation Chain -> Cost Receipt -> Task Complete"""
    import base64
    import json
    import secrets
    import time

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from ampro import DelegationLink, TaskCompleteBody, validate_body
    from ampro.delegation.cost_receipt import CostReceipt, CostReceiptChain
    from ampro.trust.resolver import _PUBLIC_KEY_CACHE, _reset_public_key_cache_for_tests

    _reset_public_key_cache_for_tests()

    # Seed a test key for the agent
    agent_id = "agent://b.example.com"
    pk = Ed25519PrivateKey.generate()
    _PUBLIC_KEY_CACHE[agent_id] = (time.time() + 3600, pk.public_key().public_bytes_raw())

    # Build delegation link
    link = DelegationLink(
        delegator="agent://a.example.com",
        delegate=agent_id,
        scopes=["tool:read"],
        max_depth=3,
        created_at="2026-04-10T00:00:00Z",
        expires_at="2026-04-10T01:00:00Z",
        signature="sig",
        trust_tier="verified",
        chain_budget="remaining=5.00USD;max=5.00USD",
    )

    # Complete with signed cost receipt
    nonce = secrets.token_urlsafe(16)
    canonical = json.dumps(
        {"agent_id": agent_id, "task_id": "t1", "cost_usd": 0.05,
         "currency": "USD", "issued_at": "2026-04-10T00:30:00Z", "nonce": nonce},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    sig = base64.urlsafe_b64encode(pk.sign(canonical)).rstrip(b"=").decode()

    receipt = CostReceipt(
        agent_id=agent_id,
        task_id="t1",
        cost_usd=0.05,
        nonce=nonce,
        signature=sig,
        issued_at="2026-04-10T00:30:00Z",
    )
    chain = CostReceiptChain()
    chain.add_receipt(receipt)
    assert chain.total_cost_usd_float == 0.05
    assert len(chain.receipts) == 1

    complete = validate_body("task.complete", {
        "task_id": "t1",
        "result": "done",
        "cost_receipt": chain.model_dump(),
    })
    assert isinstance(complete, TaskCompleteBody)
    assert complete.cost_receipt is not None
    # total_cost_usd is Decimal in the chain; compare via float conversion.
    assert float(complete.cost_receipt["total_cost_usd"]) == 0.05

    _reset_public_key_cache_for_tests()
    print("PASS: Delegation -> Cost Receipt -> Task Complete")


def test_4_challenge_trust_upgrade_session_resumption():
    """Challenge -> Trust Upgrade -> Session Resumption"""
    from ampro import (
        SessionInitBody,
        TaskChallengeBody,
        TaskChallengeResponseBody,
        TrustUpgradeRequestBody,
        TrustUpgradeResponseBody,
        validate_body,
    )

    # Challenge flow
    challenge = validate_body("task.challenge", {
        "challenge_id": "ch1",
        "challenge_type": "proof_of_work",
        "parameters": {"difficulty": 20},
        "expires_at": "2026-04-10T12:05:00Z",
        "reason": "first_contact",
    })
    assert isinstance(challenge, TaskChallengeBody)

    response = validate_body("task.challenge_response", {
        "challenge_id": "ch1",
        "solution": "answer",
    })
    assert isinstance(response, TaskChallengeResponseBody)

    # Trust upgrade
    upgrade_req = validate_body("trust.upgrade_request", {
        "session_id": "s1",
        "current_tier": "external",
        "required_tier": "verified",
        "verification_methods": ["jwt"],
        "reason": "need access",
    })
    assert isinstance(upgrade_req, TrustUpgradeRequestBody)

    upgrade_resp = validate_body("trust.upgrade_response", {
        "session_id": "s1",
        "method": "jwt",
        "proof": "token",
        "new_tier": "verified",
    })
    assert isinstance(upgrade_resp, TrustUpgradeResponseBody)

    # Session resumption
    init = SessionInitBody(
        proposed_capabilities=["messaging"],
        proposed_version="1.0.0",
        client_nonce="cn",
        previous_session_id="old-session",
    )
    assert init.previous_session_id == "old-session"

    print("PASS: Challenge -> Trust Upgrade -> Session Resumption")


def test_5_streaming_backpressure_channels_checkpoints():
    """Streaming Events -> Backpressure -> Channels -> Checkpoints"""
    from ampro import (
        StreamAckEvent,
        StreamAuthRefreshEvent,
        StreamChannelCloseEvent,
        StreamChannelOpenEvent,
        StreamCheckpointEvent,
        StreamingEvent,
        StreamingEventType,
        StreamPauseEvent,
        StreamResumeEvent,
    )

    # Create events of every streaming type
    for evt_type in StreamingEventType:
        event = StreamingEvent(type=evt_type, data={"test": True}, seq=1)
        sse = event.to_sse()
        assert f"event: {evt_type.value}" in sse

    # Backpressure flow
    ack = StreamAckEvent(last_seq=42, timestamp="2026-04-10T12:00:00Z")
    assert ack.last_seq == 42

    pause = StreamPauseEvent(reason="client_behind", resume_after_ack=42)
    assert pause.resume_after_ack == 42

    resume = StreamResumeEvent(from_seq=42, buffer_capacity=100)
    assert resume.from_seq == 42

    # Channel flow
    open_evt = StreamChannelOpenEvent(
        channel_id="ch1", task_id="t1", created_at="2026-04-10T12:00:00Z",
    )
    assert open_evt.channel_id == "ch1"

    close_evt = StreamChannelCloseEvent(channel_id="ch1", reason="complete")
    assert close_evt.reason == "complete"

    # Checkpoint
    checkpoint = StreamCheckpointEvent(
        checkpoint_id="cp1", seq=50,
        state_snapshot={"progress": 50},
        timestamp="2026-04-10T12:00:00Z",
    )
    assert checkpoint.seq == 50

    # Auth refresh
    auth = StreamAuthRefreshEvent(
        method="jwt", token="refreshed-jwt-token", expires_at="2026-04-10T13:00:00Z",
    )
    assert auth.method == "jwt"

    print("PASS: Streaming -> Backpressure -> Channels -> Checkpoints -> Auth")


def test_6_compliance_jurisdiction_erasure_consent():
    """Compliance -> Jurisdiction -> Erasure Propagation -> Consent Revoke"""
    from ampro import (
        DataConsentRevokeBody,
        DataResidency,
        ErasurePropagationStatusBody,
        JurisdictionInfo,
        check_jurisdiction_conflict,
        check_residency_violation,
        validate_body,
        validate_jurisdiction_code,
        validate_residency_region,
    )

    # Jurisdiction check
    j1 = JurisdictionInfo(primary="DE", frameworks=["GDPR"])
    j2 = JurisdictionInfo(primary="US", frameworks=["CCPA"])
    has_conflict, detail = check_jurisdiction_conflict(j1, j2)
    assert has_conflict
    assert "GDPR" in detail

    # Jurisdiction code validation
    assert validate_jurisdiction_code("DE")
    assert validate_jurisdiction_code("US")
    assert not validate_jurisdiction_code("usa")

    # Consent revoke
    revoke = validate_body("data.consent_revoke", {
        "grant_id": "g1",
        "requester": "agent://a.example.com",
        "target": "agent://b.example.com",
        "scopes": ["data:share"],
        "reason": "policy change",
    })
    assert isinstance(revoke, DataConsentRevokeBody)

    # Erasure propagation
    status = validate_body("erasure.propagation_status", {
        "erasure_id": "er1",
        "agent_id": "agent://b.example.com",
        "status": "completed",
        "records_affected": 42,
        "timestamp": "2026-04-10T12:00:00Z",
    })
    assert isinstance(status, ErasurePropagationStatusBody)

    # Data residency
    dr1 = DataResidency(region="eu-west-1", strict=True)
    dr2 = DataResidency(region="us-east-1", strict=True)
    has_violation, detail = check_residency_violation(dr1, dr2)
    assert has_violation
    assert "eu-west-1" in detail

    # No violation when same region
    dr3 = DataResidency(region="eu-west-1", strict=True)
    no_violation, no_detail = check_residency_violation(dr1, dr3)
    assert not no_violation

    # Residency region validation
    assert validate_residency_region("eu-west-1")
    assert validate_residency_region("us-east-1")
    assert not validate_residency_region("X")

    print("PASS: Jurisdiction -> Erasure Propagation -> Consent Revoke -> Residency")


def test_7_identity_federation_migration_attestation():
    """Identity -> Federation -> Migration -> Attestation"""
    from ampro import (
        AgentJson,
        AuditAttestationBody,
        IdentityLinkProofBody,
        IdentityMigrationBody,
        RegistryFederationRequest,
        RegistryFederationResponse,
        validate_body,
    )

    link = validate_body("identity.link_proof", {
        "source_id": "agent://a.example.com",
        "target_id": "agent://b.example.com",
        "proof_type": "ed25519_cross_sign",
        "proof": "proof-data",
        "timestamp": "2026-04-10T12:00:00Z",
        "expires_at": "2027-04-10T12:00:00Z",
    })
    assert isinstance(link, IdentityLinkProofBody)

    # trust_proof must be >= 64 chars (base64-encoded Ed25519 sig minimum)
    valid_proof = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ=="
    fed_req = validate_body("registry.federation_request", {
        "registry_id": "agent://reg.example.com",
        "capabilities": ["resolve", "search"],
        "trust_proof": valid_proof,
    })
    assert isinstance(fed_req, RegistryFederationRequest)

    fed_resp = validate_body("registry.federation_response", {
        "accepted": True,
        "federation_id": "fed-1",
        "terms": {"max_queries_per_minute": 100},
    })
    assert isinstance(fed_resp, RegistryFederationResponse)

    migration = validate_body("identity.migration", {
        "old_id": "agent://old.example.com",
        "new_id": "agent://new.example.com",
        "migration_proof": "proof",
        "effective_at": "2026-04-15T00:00:00Z",
    })
    assert isinstance(migration, IdentityMigrationBody)

    # Agent.json with moved_to
    aj = AgentJson(
        protocol_version="1.0.0",
        identifiers=["agent://old.example.com"],
        endpoint="https://old.example.com/agent/message",
        moved_to="agent://new.example.com",
        status="decommissioned",
    )
    assert aj.moved_to == "agent://new.example.com"
    assert aj.status == "decommissioned"

    attestation = validate_body("audit.attestation", {
        "audit_id": "a1",
        "agents": ["agent://a.example.com", "agent://b.example.com"],
        "events_hash": "sha256hash",
        "attestation_signatures": {
            "agent://a.example.com": "sig-a",
            "agent://b.example.com": "sig-b",
        },
        "timestamp": "2026-04-10T12:00:00Z",
    })
    assert isinstance(attestation, AuditAttestationBody)

    print("PASS: Identity -> Federation -> Migration -> Attestation")


def test_8_encryption_trust_proof_certifications():
    """Encryption -> Trust Proof -> Certifications"""
    from ampro import (
        CONTENT_ENCRYPTION_HEADER,
        AgentJson,
        AgentMessage,
        CertificationLink,
        TrustProofBody,
        validate_body,
    )

    # Encrypted message
    msg = AgentMessage(
        sender="agent://a.example.com",
        recipient="agent://b.example.com",
        body_type="task.create",
        headers={CONTENT_ENCRYPTION_HEADER: "A256GCM"},
        body={
            "ciphertext": "enc", "iv": "iv", "tag": "tag",
            "algorithm": "A256GCM", "recipient_key_id": "key-1",
        },
    )
    assert msg.headers[CONTENT_ENCRYPTION_HEADER] == "A256GCM"
    assert CONTENT_ENCRYPTION_HEADER == "Content-Encryption"

    # Trust proof
    proof = validate_body("trust.proof", {
        "agent_id": "agent://a.example.com",
        "claim": "score_above_500",
        "proof_type": "zkp",
        "proof": "zk-proof",
        "verifier_key_id": "key-1",
    })
    assert isinstance(proof, TrustProofBody)
    assert proof.claim == "score_above_500"

    # Certifications in agent.json
    cert = CertificationLink(
        standard="SOC2",
        url="https://audit.example.com/soc2.pdf",
        verified_by="agent://auditor.example.com",
        expires_at="2027-01-01T00:00:00Z",
    )
    aj = AgentJson(
        protocol_version="1.0.0",
        identifiers=["agent://a.example.com"],
        endpoint="https://a.example.com/agent/message",
        certifications=[cert.model_dump()],
    )
    assert len(aj.certifications) == 1
    assert aj.certifications[0]["standard"] == "SOC2"

    print("PASS: Encryption -> Trust Proof -> Certifications")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ALL_TESTS = [
    test_1_handshake_session_binding_message,
    test_2_trust_score_policy_visibility,
    test_3_delegation_cost_receipt_task_complete,
    test_4_challenge_trust_upgrade_session_resumption,
    test_5_streaming_backpressure_channels_checkpoints,
    test_6_compliance_jurisdiction_erasure_consent,
    test_7_identity_federation_migration_attestation,
    test_8_encryption_trust_proof_certifications,
]


def main():
    passed = 0
    failed = 0
    errors = []

    for test_fn in ALL_TESTS:
        try:
            test_fn()
            passed += 1
        except Exception as exc:
            failed += 1
            errors.append((test_fn.__name__, exc))
            print(f"FAIL: {test_fn.__name__}")
            traceback.print_exc()
            print()

    print(f"\n{'='*60}")
    print(f"Results: {passed} passed, {failed} failed out of {len(ALL_TESTS)} tests")
    if errors:
        print("\nFailed tests:")
        for name, exc in errors:
            print(f"  - {name}: {exc}")
        sys.exit(1)
    else:
        print("ALL INTEGRATION TESTS PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
