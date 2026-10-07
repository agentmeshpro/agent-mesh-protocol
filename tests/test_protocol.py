"""Comprehensive tests for agent-protocol package."""

from datetime import UTC

import pytest
from pydantic import ValidationError


class TestImports:
    def test_version(self):
        import ampro
        from importlib.metadata import version
        assert ampro.__version__ == version("ampro")

    def test_all_exports(self):
        import ampro
        assert len(ampro.__all__) >= 100


class TestAddressing:
    def test_parse_host(self):
        from ampro import AddressType, parse_agent_uri
        addr = parse_agent_uri("agent://bakery.example.com")
        assert addr.address_type == AddressType.HOST
        assert addr.host == "bakery.example.com"

    def test_parse_slug(self):
        from ampro import AddressType, parse_agent_uri
        addr = parse_agent_uri("agent://sales@acme.example.com")
        assert addr.address_type == AddressType.SLUG
        assert addr.slug == "sales"
        assert addr.registry == "acme.example.com"

    def test_parse_did(self):
        from ampro import AddressType, parse_agent_uri
        addr = parse_agent_uri("agent://did:web:example.com")
        assert addr.address_type == AddressType.DID

    def test_normalize(self):
        from ampro import normalize_shorthand
        assert normalize_shorthand("@test", "registry.example.com") == "agent://test@registry.example.com"

    def test_invalid_scheme(self):
        from ampro import parse_agent_uri
        with pytest.raises(ValueError):
            parse_agent_uri("http://bakery.example.com")


class TestEnvelope:
    def test_body_type_field(self):
        from ampro import AgentMessage
        msg = AgentMessage(sender="agent://a.example.com", recipient="agent://b.example.com", body_type="task.create")
        assert msg.body_type == "task.create"

    def test_body_type_default(self):
        from ampro import AgentMessage
        msg = AgentMessage(sender="agent://a.example.com", recipient="agent://b.example.com")
        assert msg.body_type == "message"

    def test_headers_count(self):
        from ampro import STANDARD_HEADERS
        assert len(STANDARD_HEADERS) == 51


class TestBodySchemas:
    def test_validate_task_create(self):
        from ampro import validate_body
        body = validate_body("task.create", {"description": "Do something"})
        assert body.description == "Do something"

    def test_invalid_body(self):
        from ampro import validate_body
        with pytest.raises(ValidationError):
            validate_body("task.create", {})

    def test_unknown_passthrough(self):
        from ampro import validate_body
        result = validate_body("com.custom.type", {"foo": "bar"})
        assert result == {"foo": "bar"}

    def test_escalate_body(self):
        from ampro import validate_body
        body = validate_body("task.escalate", {
            "task_id": "t-1", "escalate_to": "sender_human", "reason": "Need help"
        })
        assert body.escalate_to == "sender_human"


class TestTrust:
    def test_four_tiers(self):
        from ampro import TrustTier
        assert len(TrustTier) == 4

    def test_can_delegate(self):
        from ampro import TrustTier
        assert TrustTier.EXTERNAL.can_delegate is False
        assert TrustTier.VERIFIED.can_delegate is True
        assert TrustTier.OWNER.can_delegate is True

    def test_clock_skew(self):
        from ampro import CLOCK_SKEW_SECONDS
        assert CLOCK_SKEW_SECONDS == 30


class TestCapabilities:
    def test_eight_groups(self):
        from ampro import CapabilityGroup
        assert len(CapabilityGroup) == 8

    def test_level_computation(self):
        from ampro import CapabilityGroup, CapabilitySet
        caps = CapabilitySet(groups={CapabilityGroup.MESSAGING, CapabilityGroup.TOOLS})
        assert caps.level == 2


class TestStreaming:
    def test_seventeen_events(self):
        from ampro import StreamingEventType
        assert len(StreamingEventType) == 17

    def test_heartbeat(self):
        from ampro import StreamingEventType
        assert StreamingEventType.HEARTBEAT == "heartbeat"

    def test_seq_field(self):
        from ampro import StreamingEvent, StreamingEventType
        event = StreamingEvent(type=StreamingEventType.HEARTBEAT, seq=42, id="s:42")
        assert event.seq == 42

    def test_sse_format(self):
        from ampro import StreamingEvent, StreamingEventType
        event = StreamingEvent(type=StreamingEventType.TEXT_DELTA, seq=1, id="s:1", data={"text": "hi"})
        sse = event.to_sse()
        assert "event: text_delta" in sse
        assert "id: s:1" in sse


class TestDelegation:
    def test_delegation_link_fields(self):
        from datetime import datetime

        from ampro import DelegationLink
        link = DelegationLink(
            delegator="agent://a.example.com", delegate="agent://b.example.com",
            scopes=["tool:read"], max_fan_out=5, trust_tier="verified",
            chain_budget="remaining=3.50USD;max=5.00USD",
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC),
        )
        assert link.max_fan_out == 5
        assert link.trust_tier == "verified"

    def test_chain_budget_parse(self):
        from ampro import parse_chain_budget
        remaining, max_b = parse_chain_budget("remaining=3.50USD;max=5.00USD")
        assert remaining == 3.50
        assert max_b == 5.00

    def test_visited_agents(self):
        from ampro import check_visited_agents_loop
        assert check_visited_agents_loop("agent://a.example.com,agent://b.example.com", "agent://a.example.com") is True
        assert check_visited_agents_loop("agent://a.example.com,agent://b.example.com", "agent://c.example.com") is False


class TestAuth:
    def test_parse_bearer(self):
        from ampro import AuthMethod, parse_authorization
        auth = parse_authorization("Bearer token123")
        assert auth.method == AuthMethod.JWT

    def test_parse_did(self):
        from ampro import AuthMethod, parse_authorization
        auth = parse_authorization("DID proof123")
        assert auth.method == AuthMethod.DID

    def test_parse_apikey(self):
        from ampro import AuthMethod, parse_authorization
        auth = parse_authorization("ApiKey sk_123")
        assert auth.method == AuthMethod.API_KEY

    def test_parse_none(self):
        from ampro import AuthMethod, parse_authorization
        auth = parse_authorization(None)
        assert auth.method == AuthMethod.NONE


class TestCompliance:
    def test_content_classification(self):
        from ampro import ContentClassification
        assert ContentClassification.PII == "pii"
        assert ContentClassification.SENSITIVE_PII == "sensitive-pii"

    def test_erasure_request(self):
        from ampro import ErasureRequest
        req = ErasureRequest(
            subject_id="u-1", subject_proof="proof",
            scope="all", reason="user_request", deadline="2026-05-08T00:00:00Z",
        )
        assert req.scope == "all"

    def test_audit_logger(self):
        from ampro import AuditEntry, AuditLogger
        logger = AuditLogger()
        entry = logger.log(AuditEntry(
            message_id="m-1", sender="a", recipient="b", body_type="message",
        ))
        assert entry.hash != ""
        assert logger.verify_chain() is True


class TestSecurity:
    def test_dedup(self):
        import asyncio

        from ampro import InMemoryDedupStore
        store = InMemoryDedupStore(window_seconds=300)
        assert asyncio.run(store.is_duplicate("msg-1")) is False
        assert asyncio.run(store.is_duplicate("msg-1")) is True

    def test_nonce(self):
        from ampro import NonceTracker
        tracker = NonceTracker()
        assert tracker.is_replay("n-1") is False
        assert tracker.is_replay("n-1") is True

    def test_rate_limiter(self):
        from ampro import RateLimiter
        limiter = RateLimiter(rpm=2)
        allowed1, _ = limiter.check("s1")
        allowed2, _ = limiter.check("s1")
        allowed3, _ = limiter.check("s1")
        assert allowed1 is True
        assert allowed2 is True
        assert allowed3 is False


class TestNegotiation:
    def test_negotiate_version(self):
        from ampro import negotiate_version
        assert negotiate_version("2.0.0, 0.1.0") == "0.1.0"

    def test_negotiate_version_none(self):
        from ampro import CURRENT_VERSION, negotiate_version
        assert negotiate_version(None) == CURRENT_VERSION

    def test_negotiate_version_uses_fallback_on_no_match(self):
        """When no requested version is supported, fallback is returned."""
        from ampro import CURRENT_VERSION, negotiate_version
        assert (
            negotiate_version("9.9.9, 8.8.8", fallback_version=CURRENT_VERSION)
            == CURRENT_VERSION
        )

    def test_negotiate_version_raises_without_fallback(self):
        """No fallback provided AND no match → ValueError (existing behaviour)."""
        import pytest

        from ampro import negotiate_version
        with pytest.raises(ValueError):
            negotiate_version("9.9.9")


class TestAgentJson:
    def test_schema(self):
        from ampro import AgentJson
        aj = AgentJson(
            protocol_version="0.1.0",
            identifiers=["agent://test.local"],
            endpoint="https://test.local/agent/message",
        )
        assert aj.ttl_seconds == 3600


class TestCrossVerification:
    def test_did_key_not_verified_without_implementation(self):
        """C9: did:key cross-verification is fail-closed until key extraction is implemented."""
        import asyncio

        from ampro import cross_verify_identifiers
        results = asyncio.run(cross_verify_identifiers(
            identifiers=["agent://did:key:z6MkTest"],
            expected_endpoint="https://example.com/agent/message",
        ))
        assert results[0].verified is False
        assert "not yet implemented" in results[0].reason


class TestV011Imports:
    """Verify all v0.1.1 types are importable from ampro."""

    def test_version_bumped(self):
        import ampro
        from importlib.metadata import version
        assert ampro.__version__ == version("ampro")

    def test_handshake_imports(self):
        from ampro import (
            HandshakeState,
        )
        assert HandshakeState.IDLE.value == "idle"

    def test_session_binding_imports(self):
        from ampro import (
            derive_binding_token,
        )
        assert callable(derive_binding_token)

    def test_trust_score_imports(self):
        from ampro import (
            TrustFactor,
        )
        assert TrustFactor.AGE.value == "age"

    def test_visibility_imports(self):
        from ampro import (
            VisibilityLevel,
        )
        assert VisibilityLevel.PUBLIC.value == "public"

    def test_context_schema_imports(self):
        from ampro import parse_schema_urn
        assert callable(parse_schema_urn)

    def test_expanded_session_state(self):
        from ampro import SessionState
        # v0.1.1 added IDLE, INIT_SENT, INIT_RECEIVED, ESTABLISHED
        assert hasattr(SessionState, "IDLE")
        assert hasattr(SessionState, "INIT_SENT")
        assert hasattr(SessionState, "INIT_RECEIVED")
        assert hasattr(SessionState, "ESTABLISHED")

    def test_new_standard_headers(self):
        from ampro import STANDARD_HEADERS
        for h in ["Session-Binding", "Trust-Score", "Context-Schema", "Transaction-Id", "Correlation-Group", "Commitment-Level"]:
            assert h in STANDARD_HEADERS, f"Missing header: {h}"

    def test_agent_json_new_fields(self):
        from ampro import AgentJson
        aj = AgentJson(protocol_version="1.0.0", identifiers=["agent://test.example.com"], endpoint="https://test.example.com/agent/message")
        assert aj.visibility == {"level": "public", "contact_policy": "open"}
        assert aj.supported_schemas == []

    def test_all_exports_expanded(self):
        import ampro
        assert len(ampro.__all__) >= 115  # grew from 100+


class TestV012Imports:
    """Verify all v0.1.2 types are importable from ampro."""

    def test_version_is_016(self):
        import ampro
        from importlib.metadata import version
        assert ampro.__version__ == version("ampro")

    def test_key_revocation_imports(self):
        from ampro import RevocationReason
        assert RevocationReason.KEY_COMPROMISE.value == "key_compromise"

    def test_challenge_imports(self):
        from ampro import ChallengeReason
        assert ChallengeReason.FIRST_CONTACT.value == "first_contact"

    def test_tool_consent_imports(self):
        from ampro import ToolDefinition
        td = ToolDefinition(name="test", description="test tool")
        assert td.consent_required is False

    def test_backpressure_imports(self):
        from ampro import StreamAckEvent
        ack = StreamAckEvent(last_seq=1, timestamp="2026-01-01T00:00:00Z")
        assert ack.last_seq == 1

    def test_trust_upgrade_imports(self):
        from ampro import TrustUpgradeRequestBody
        assert TrustUpgradeRequestBody.model_fields["timeout_seconds"].default == 300

    def test_streaming_event_type_backpressure_members(self):
        from ampro import StreamingEventType
        assert hasattr(StreamingEventType, "STREAM_ACK")
        assert hasattr(StreamingEventType, "STREAM_PAUSE")
        assert hasattr(StreamingEventType, "STREAM_RESUME")

    def test_new_v012_headers(self):
        from ampro import STANDARD_HEADERS
        for h in ["Key-Revoked-At", "Anonymous-Sender-Hint"]:
            assert h in STANDARD_HEADERS, f"Missing v0.1.2 header: {h}"

    def test_all_exports_148(self):
        import ampro
        assert len(ampro.__all__) >= 148


class TestSessionResumption:
    """Test session resumption fields added in v0.1.2."""

    def test_session_init_has_previous_session_id(self):
        from ampro import SessionInitBody
        body = SessionInitBody(
            proposed_capabilities=["messaging"],
            proposed_version="1.0.0",
            client_nonce="nonce123",
            previous_session_id="old-sess-1",
        )
        assert body.previous_session_id == "old-sess-1"

    def test_session_init_previous_session_id_default_none(self):
        from ampro import SessionInitBody
        body = SessionInitBody(
            proposed_capabilities=["messaging"],
            proposed_version="1.0.0",
            client_nonce="nonce123",
        )
        assert body.previous_session_id is None

    def test_session_established_has_resumed(self):
        from ampro import SessionEstablishedBody
        body = SessionEstablishedBody(
        confirm_nonce="test-nonce-2",
            session_id="sess-new",
            negotiated_capabilities=["messaging"],
            negotiated_version="1.0.0",
            trust_tier="verified",
            trust_score=500,
            server_nonce="sn",
            binding_token="bt",
            resumed=True,
        )
        assert body.resumed is True

    def test_session_established_resumed_default_false(self):
        from ampro import SessionEstablishedBody
        body = SessionEstablishedBody(
            session_id="sess-fresh",
            negotiated_capabilities=["messaging"],
            negotiated_version="1.0.0",
            trust_tier="external",
            trust_score=100,
            server_nonce="sn",
            binding_token="bt",
            confirm_nonce="test-nonce-protocol",
        )
        assert body.resumed is False


class TestV013Imports:
    """Verify all v0.1.3 types are importable from ampro."""

    def test_agent_lifecycle_status_import(self):
        from ampro import AgentLifecycleStatus
        assert AgentLifecycleStatus.ACTIVE == "active"

    def test_agent_deactivation_notice_body_import(self):
        from ampro import AgentDeactivationNoticeBody
        body = AgentDeactivationNoticeBody(
            agent_id="agent://test.example.com",
            reason="Shutdown",
            deactivation_time="2026-04-09T00:00:00Z",
            active_sessions=0,
        )
        assert body.agent_id == "agent://test.example.com"

    def test_cost_receipt_import(self):
        import secrets

        from ampro import CostReceipt
        nonce = secrets.token_urlsafe(16)
        receipt = CostReceipt(
            agent_id="agent://a.example.com",
            task_id="t-1",
            cost_usd=0.01,
            nonce=nonce,
            signature="test-sig-placeholder",
            issued_at="2026-04-09T00:00:00Z",
        )
        assert receipt.cost_usd == 0.01

    def test_cost_receipt_chain_import(self):
        from ampro import CostReceiptChain
        chain = CostReceiptChain()
        assert chain.total_cost_usd == 0.0

    def test_all_exports_count(self):
        import ampro
        assert len(ampro.__all__) >= 152


class TestV014Imports:
    """Verify all v0.1.4 types are importable from ampro."""

    def test_registry_search_request_import(self):
        from ampro import RegistrySearchRequest
        req = RegistrySearchRequest(capability="messaging")
        assert req.max_results == 10

    def test_registry_search_match_import(self):
        from ampro import RegistrySearchMatch
        match = RegistrySearchMatch(
            agent_id="agent://test.example.com",
            endpoint="https://test.example.com/agent/message",
            capabilities=["messaging"],
            trust_score=700,
            trust_tier="verified",
        )
        assert match.agent_id == "agent://test.example.com"

    def test_registry_search_result_import(self):
        from ampro import RegistrySearchResult
        result = RegistrySearchResult()
        assert result.matches == []
        assert result.total_available == 0

    def test_task_redirect_body_import(self):
        from ampro import TaskRedirectBody
        body = TaskRedirectBody(
            task_id="t-1",
            redirect_to="agent://alt.example.com",
            reason="overloaded",
        )
        assert body.task_id == "t-1"
        assert body.reason == "overloaded"

    def test_x_load_level_header(self):
        from ampro import STANDARD_HEADERS
        assert "X-Load-Level" in STANDARD_HEADERS

    def test_all_exports_v014_count(self):
        import ampro
        assert len(ampro.__all__) >= 156


class TestV015Imports:
    """Verify all v0.1.5 types are importable from ampro."""

    def test_trace_context_import(self):
        from ampro import TraceContext
        ctx = TraceContext(trace_id="a" * 32, span_id="b" * 16)
        assert ctx.trace_id == "a" * 32

    def test_generate_trace_id_import(self):
        from ampro import generate_trace_id
        tid = generate_trace_id()
        assert len(tid) == 32

    def test_generate_span_id_import(self):
        from ampro import generate_span_id
        sid = generate_span_id()
        assert len(sid) == 16

    def test_inject_trace_headers_import(self):
        from ampro import TraceContext, inject_trace_headers
        ctx = TraceContext(trace_id="a" * 32, span_id="b" * 16)
        headers = inject_trace_headers(ctx)
        assert "Trace-Id" in headers

    def test_extract_trace_context_import(self):
        from ampro import extract_trace_context
        result = extract_trace_context({})
        assert result is None

    def test_task_revoke_body_import(self):
        from ampro import TaskRevokeBody
        body = TaskRevokeBody(task_id="t-1", reason="revoked")
        assert body.task_id == "t-1"

    def test_priority_import(self):
        from ampro import Priority
        assert Priority.URGENT == "urgent"

    def test_trace_headers_in_standard_headers(self):
        from ampro import STANDARD_HEADERS
        assert "Trace-Id" in STANDARD_HEADERS
        assert "Span-Id" in STANDARD_HEADERS

    def test_all_exports_v015_count(self):
        import ampro
        assert len(ampro.__all__) >= 163


class TestV016Imports:
    """Verify all v0.1.6 types are importable from ampro."""

    def test_jurisdiction_info_import(self):
        from ampro import JurisdictionInfo
        info = JurisdictionInfo(primary="US")
        assert info.primary == "US"

    def test_validate_jurisdiction_code_import(self):
        from ampro import validate_jurisdiction_code
        assert validate_jurisdiction_code("US") is True

    def test_check_jurisdiction_conflict_import(self):
        from ampro import check_jurisdiction_conflict
        assert callable(check_jurisdiction_conflict)

    def test_erasure_propagation_status_import(self):
        from ampro import ErasurePropagationStatus
        assert ErasurePropagationStatus.PENDING == "pending"

    def test_erasure_propagation_status_body_import(self):
        from ampro import ErasurePropagationStatusBody
        body = ErasurePropagationStatusBody(
            erasure_id="er-1",
            agent_id="agent://test.example.com",
            status="completed",
            records_affected=5,
            timestamp="2026-04-09T00:00:00Z",
        )
        assert body.records_affected == 5

    def test_data_consent_revoke_body_import(self):
        from ampro import DataConsentRevokeBody
        body = DataConsentRevokeBody(
            grant_id="g-1",
            requester="agent://a.example.com",
            target="agent://b.example.com",
            reason="user request",
        )
        assert body.grant_id == "g-1"

    def test_data_residency_import(self):
        from ampro import DataResidency
        dr = DataResidency(region="eu-west-1")
        assert dr.region == "eu-west-1"

    def test_validate_residency_region_import(self):
        from ampro import validate_residency_region
        assert validate_residency_region("us-east-1") is True

    def test_check_residency_violation_import(self):
        from ampro import check_residency_violation
        assert callable(check_residency_violation)

    def test_jurisdiction_header(self):
        from ampro import STANDARD_HEADERS
        assert "Jurisdiction" in STANDARD_HEADERS

    def test_data_residency_header(self):
        from ampro import STANDARD_HEADERS
        assert "Data-Residency" in STANDARD_HEADERS

    def test_all_exports_v016_count(self):
        import ampro
        assert len(ampro.__all__) >= 173


class TestV017Imports:
    """Verify all v0.1.7 types are importable from ampro."""

    def test_stream_channel_import(self):
        from ampro import StreamChannel
        ch = StreamChannel(
            channel_id="ch-test",
            created_at="2026-04-09T12:00:00Z",
        )
        assert ch.channel_id == "ch-test"

    def test_stream_channel_open_event_import(self):
        from ampro import StreamChannelOpenEvent
        event = StreamChannelOpenEvent(
            channel_id="ch-open",
            task_id="t-1",
            created_at="2026-04-09T12:00:00Z",
        )
        assert event.channel_id == "ch-open"

    def test_stream_channel_close_event_import(self):
        from ampro import StreamChannelCloseEvent
        event = StreamChannelCloseEvent(channel_id="ch-close")
        assert event.reason == "complete"

    def test_stream_checkpoint_event_import(self):
        from ampro import StreamCheckpointEvent
        cp = StreamCheckpointEvent(
            checkpoint_id="cp-test",
            seq=0,
            timestamp="2026-04-09T12:00:00Z",
        )
        assert cp.state_snapshot == {}

    def test_stream_auth_refresh_event_import(self):
        from ampro import StreamAuthRefreshEvent
        event = StreamAuthRefreshEvent(
            method="jwt",
            token="token-abcdef-123456",
            expires_at="2026-04-09T13:00:00Z",
        )
        assert event.method == "jwt"

    def test_stream_channel_header(self):
        from ampro import STANDARD_HEADERS
        assert "Stream-Channel" in STANDARD_HEADERS

    def test_streaming_event_type_count(self):
        from ampro import StreamingEventType
        assert len(StreamingEventType) == 17

    def test_all_exports_v017_count(self):
        import ampro
        assert len(ampro.__all__) >= 179


class TestV018Imports:
    """Verify all v0.1.8 types are importable from ampro."""

    def test_identity_link_proof_import(self):
        from ampro import IdentityLinkProofBody
        body = IdentityLinkProofBody(
            source_id="agent://a.example.com",
            target_id="agent://b.example.com",
            proof_type="ed25519_cross_sign",
            proof="sig",
            timestamp="2026-04-09T12:00:00Z",
            expires_at="2027-04-09T12:00:00Z",
        )
        assert body.source_id == "agent://a.example.com"

    def test_registry_federation_request_import(self):
        from ampro import RegistryFederationRequest
        # trust_proof must be >= 64 chars (base64-encoded Ed25519 sig minimum)
        valid_proof = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ=="
        req = RegistryFederationRequest(
            registry_id="agent://reg.example.com",
            capabilities=["resolve", "search"],
            trust_proof=valid_proof,
        )
        assert req.registry_id == "agent://reg.example.com"

    def test_registry_federation_response_import(self):
        from ampro import RegistryFederationResponse
        resp = RegistryFederationResponse(accepted=True, federation_id="fed-1")
        assert resp.accepted is True

    def test_identity_migration_body_import(self):
        from ampro import IdentityMigrationBody
        body = IdentityMigrationBody(
            old_id="agent://old.example.com",
            new_id="agent://new.example.com",
            migration_proof="proof",
            effective_at="2026-04-10T00:00:00Z",
        )
        assert body.old_id == "agent://old.example.com"

    def test_audit_attestation_body_import(self):
        from ampro import AuditAttestationBody
        body = AuditAttestationBody(
            audit_id="att-1",
            agents=["agent://a.example.com", "agent://b.example.com"],
            events_hash="sha256:abc",
            attestation_signatures={"agent://a.example.com": "sig-a", "agent://b.example.com": "sig-b"},
            timestamp="2026-04-09T15:00:00Z",
        )
        assert body.audit_id == "att-1"

    def test_all_exports_v018_count(self):
        import ampro
        assert len(ampro.__all__) >= 184


class TestV019Imports:
    """Verify all v0.1.9 types are importable from ampro."""

    def test_encrypted_body_import(self):
        from ampro import EncryptedBody
        body = EncryptedBody(
            ciphertext="ct",
            iv="iv",
            tag="tg",
            algorithm="A256GCM",
            recipient_key_id="rk-1",
        )
        assert body.algorithm == "A256GCM"

    def test_content_encryption_header_import(self):
        from ampro import CONTENT_ENCRYPTION_HEADER
        assert CONTENT_ENCRYPTION_HEADER == "Content-Encryption"

    def test_trust_proof_body_import(self):
        from ampro import TrustProofBody
        body = TrustProofBody(
            agent_id="agent://prover.example.com",
            claim="score_above_500",
            proof_type="zkp",
            proof="proof-data",
            verifier_key_id="vk-1",
        )
        assert body.claim == "score_above_500"

    def test_certification_link_import(self):
        from ampro import CertificationLink
        link = CertificationLink(
            standard="SOC2",
            url="https://example.com/soc2.pdf",
            verified_by="agent://auditor.example.com",
            expires_at="2027-01-01T00:00:00Z",
        )
        assert link.standard == "SOC2"

    def test_all_exports_v019_count(self):
        import ampro
        assert len(ampro.__all__) >= 187


# ===========================================================================
# C18 — Server levels 2-5 return 501, not 404
# ===========================================================================


class TestServerLevelStubs:
    """C18: Protocol levels 2-5 should return 501 Not Implemented (not 404)."""

    def _route(self, server, method, path):
        import asyncio
        return asyncio.run(server.route(method, path))

    def test_level1_agent_json_still_200(self):
        """Level 1 endpoint (agent.json) still returns 200."""
        from ampro.server import AgentServer
        server = AgentServer(agent_id="@test", endpoint="https://test.example.com")
        status, _, _ = self._route(server, "GET", "/.well-known/agent.json")
        assert status == 200

    def test_level1_health_still_200(self):
        """Level 1 endpoint (health) still returns 200."""
        from ampro.server import AgentServer
        server = AgentServer(agent_id="@test", endpoint="https://test.example.com")
        status, _, _ = self._route(server, "GET", "/agent/health")
        assert status == 200

    def test_level2_tools_returns_501(self):
        """Level 2 endpoint /agent/tools returns 501 with protocol_level=2."""
        import json

        from ampro.server import AgentServer
        server = AgentServer(agent_id="@test", endpoint="https://test.example.com")
        status, headers, body_str = self._route(server, "GET", "/agent/tools")
        assert status == 501
        data = json.loads(body_str)
        assert data["protocol_level"] == 2
        assert data["type"] == "urn:amp:error:not-implemented"

    def test_level3_tasks_returns_501(self):
        """Level 3 endpoint /agent/tasks returns 501 with protocol_level=3."""
        import json

        from ampro.server import AgentServer
        server = AgentServer(agent_id="@test", endpoint="https://test.example.com")
        status, headers, body_str = self._route(server, "GET", "/agent/tasks")
        assert status == 501
        data = json.loads(body_str)
        assert data["protocol_level"] == 3
        assert data["type"] == "urn:amp:error:not-implemented"

    def test_level4_delegate_returns_501(self):
        """Level 4 endpoint /agent/delegate returns 501 with protocol_level=4."""
        import json

        from ampro.server import AgentServer
        server = AgentServer(agent_id="@test", endpoint="https://test.example.com")
        status, headers, body_str = self._route(server, "POST", "/agent/delegate")
        assert status == 501
        data = json.loads(body_str)
        assert data["protocol_level"] == 4
        assert data["type"] == "urn:amp:error:not-implemented"

    def test_level5_admin_returns_501(self):
        """Level 5 endpoint /agent/admin returns 501 with protocol_level=5."""
        import json

        from ampro.server import AgentServer
        server = AgentServer(agent_id="@test", endpoint="https://test.example.com")
        status, headers, body_str = self._route(server, "GET", "/agent/admin")
        assert status == 501
        data = json.loads(body_str)
        assert data["protocol_level"] == 5
        assert data["type"] == "urn:amp:error:not-implemented"

    def test_unknown_path_still_404(self):
        """Paths outside the spec still return 404."""
        import json

        from ampro.server import AgentServer
        server = AgentServer(agent_id="@test", endpoint="https://test.example.com")
        status, _, body_str = self._route(server, "GET", "/totally/unknown")
        assert status == 404
        data = json.loads(body_str)
        assert data["type"] == "urn:amp:error:not-found"


# ===========================================================================
# C20 — Delegation tests with real Ed25519 signatures
# ===========================================================================


class TestDelegationSignatures:
    """C20: Real Ed25519 delegation chain tests — not placeholders."""

    def _make_keypair(self):
        """Generate a fresh Ed25519 keypair. Returns (private_seed, public_bytes)."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        private_key = Ed25519PrivateKey.generate()
        seed = private_key.private_bytes_raw()
        pub = private_key.public_key().public_bytes_raw()
        return seed, pub

    def _make_signed_link(self, private_seed, delegator, delegate, scopes,
                          max_depth=3, created_at=None, expires_at=None,
                          parent_delegate=None):
        """Create a DelegationLink with a real Ed25519 signature."""
        from datetime import datetime, timedelta

        from ampro.delegation.chain import DelegationLink, sign_delegation

        now = datetime.now(UTC)
        created = created_at or now
        expires = expires_at or (now + timedelta(hours=1))

        link_data = {
            "delegator": delegator,
            "delegate": delegate,
            "scopes": sorted(scopes),
            "max_depth": max_depth,
            "created_at": created.isoformat(),
            "expires_at": expires.isoformat(),
        }
        sig = sign_delegation(private_seed, link_data, parent_delegate=parent_delegate)
        return DelegationLink(
            delegator=delegator,
            delegate=delegate,
            scopes=scopes,
            max_depth=max_depth,
            created_at=created,
            expires_at=expires,
            signature=sig,
        )

    def test_single_link_real_signature_verifies(self):
        """A delegation link signed with a real Ed25519 key should verify."""
        from ampro.delegation.chain import DelegationChain, validate_chain

        seed_a, pub_a = self._make_keypair()
        link = self._make_signed_link(
            seed_a,
            delegator="agent://a.example.com",
            delegate="agent://b.example.com",
            scopes=["tool:read", "tool:execute"],
        )
        chain = DelegationChain(links=[link])
        public_keys = {"agent://a.example.com": pub_a}
        valid, reason = validate_chain(chain, public_keys)
        assert valid is True, f"Expected valid chain, got: {reason}"
        assert reason == "valid"

    def test_scope_widening_rejected(self):
        """Child claiming more scopes than parent granted must be rejected."""
        from ampro.delegation.chain import (
            DelegationChain,
            validate_chain,
        )

        seed_a, pub_a = self._make_keypair()
        seed_b, pub_b = self._make_keypair()

        # Parent grants only tool:read
        link_a = self._make_signed_link(
            seed_a,
            delegator="agent://a.example.com",
            delegate="agent://b.example.com",
            scopes=["tool:read"],
        )

        # Child tries to claim tool:read AND tool:execute (widening!)
        link_b = self._make_signed_link(
            seed_b,
            delegator="agent://b.example.com",
            delegate="agent://c.example.com",
            scopes=["tool:read", "tool:execute"],
            parent_delegate="agent://b.example.com",
        )

        chain = DelegationChain(links=[link_a, link_b])
        public_keys = {
            "agent://a.example.com": pub_a,
            "agent://b.example.com": pub_b,
        }
        valid, reason = validate_chain(chain, public_keys)
        assert valid is False
        assert "not subset" in reason or "scopes" in reason

    def test_scope_narrowing_accepted(self):
        """Child claiming fewer scopes than parent is valid narrowing."""
        from datetime import datetime, timedelta

        from ampro.delegation.chain import DelegationChain, validate_chain

        seed_a, pub_a = self._make_keypair()
        seed_b, pub_b = self._make_keypair()

        now = datetime.now(UTC)
        expires = now + timedelta(hours=1)

        # Parent grants tool:read and tool:execute
        link_a = self._make_signed_link(
            seed_a,
            delegator="agent://a.example.com",
            delegate="agent://b.example.com",
            scopes=["tool:read", "tool:execute"],
            created_at=now,
            expires_at=expires,
        )

        # Child narrows to only tool:read
        link_b = self._make_signed_link(
            seed_b,
            delegator="agent://b.example.com",
            delegate="agent://c.example.com",
            scopes=["tool:read"],
            created_at=now,
            expires_at=expires,
            parent_delegate="agent://b.example.com",
        )

        chain = DelegationChain(links=[link_a, link_b])
        public_keys = {
            "agent://a.example.com": pub_a,
            "agent://b.example.com": pub_b,
        }
        valid, reason = validate_chain(chain, public_keys)
        assert valid is True, f"Scope narrowing should be accepted, got: {reason}"

    def test_three_level_chain_all_signatures_verify(self):
        """A 3-level delegation chain with real signatures should verify end-to-end."""
        from datetime import datetime, timedelta

        from ampro.delegation.chain import DelegationChain, validate_chain

        seed_a, pub_a = self._make_keypair()
        seed_b, pub_b = self._make_keypair()
        seed_c, pub_c = self._make_keypair()

        now = datetime.now(UTC)
        expires = now + timedelta(hours=1)

        link_a = self._make_signed_link(
            seed_a,
            delegator="agent://a.example.com",
            delegate="agent://b.example.com",
            scopes=["tool:*"],
            max_depth=5,
            created_at=now,
            expires_at=expires,
        )
        link_b = self._make_signed_link(
            seed_b,
            delegator="agent://b.example.com",
            delegate="agent://c.example.com",
            scopes=["tool:read", "tool:execute"],
            max_depth=4,
            created_at=now,
            expires_at=expires,
            parent_delegate="agent://b.example.com",
        )
        link_c = self._make_signed_link(
            seed_c,
            delegator="agent://c.example.com",
            delegate="agent://d.example.com",
            scopes=["tool:read"],
            max_depth=3,
            created_at=now,
            expires_at=expires,
            parent_delegate="agent://c.example.com",
        )

        chain = DelegationChain(links=[link_a, link_b, link_c])
        public_keys = {
            "agent://a.example.com": pub_a,
            "agent://b.example.com": pub_b,
            "agent://c.example.com": pub_c,
        }
        valid, reason = validate_chain(chain, public_keys)
        assert valid is True, f"3-level chain should verify, got: {reason}"

    def test_missing_signature_rejected(self):
        """A delegation link with an empty signature must be rejected."""
        from datetime import datetime, timedelta

        from ampro.delegation.chain import (
            DelegationChain,
            DelegationLink,
            validate_chain,
        )

        _, pub_a = self._make_keypair()

        now = datetime.now(UTC)
        link = DelegationLink(
            delegator="agent://a.example.com",
            delegate="agent://b.example.com",
            scopes=["tool:read"],
            max_depth=3,
            created_at=now,
            expires_at=now + timedelta(hours=1),
            signature="",  # Empty — no signature
        )
        chain = DelegationChain(links=[link])
        public_keys = {"agent://a.example.com": pub_a}
        valid, reason = validate_chain(chain, public_keys)
        assert valid is False
        assert "signature" in reason.lower() or "invalid" in reason.lower()
