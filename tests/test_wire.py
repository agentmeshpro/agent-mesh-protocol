"""Tests for ampro.wire — HTTP transport contract for AMP."""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Endpoint tests
# ---------------------------------------------------------------------------


class TestEndpoints:
    """Tests for ampro.wire.endpoints."""

    def test_conformance_level_ordering(self) -> None:
        from ampro.wire.endpoints import ConformanceLevel

        assert ConformanceLevel.DISCOVERY < ConformanceLevel.MESSAGING
        assert ConformanceLevel.MESSAGING < ConformanceLevel.TOOLS
        assert ConformanceLevel.TOOLS < ConformanceLevel.TASK_LIFECYCLE
        assert ConformanceLevel.TASK_LIFECYCLE < ConformanceLevel.IDENTITY
        assert ConformanceLevel.IDENTITY < ConformanceLevel.PLATFORM
        assert ConformanceLevel.DISCOVERY.value == 0
        assert ConformanceLevel.PLATFORM.value == 5

    def test_http_method_values(self) -> None:
        from ampro.wire.endpoints import HttpMethod

        assert HttpMethod.GET == "GET"
        assert HttpMethod.POST == "POST"
        assert HttpMethod.PUT == "PUT"
        assert HttpMethod.PATCH == "PATCH"
        assert HttpMethod.DELETE == "DELETE"

    def test_endpoint_spec_model(self) -> None:
        from ampro.wire.endpoints import ConformanceLevel, EndpointSpec, HttpMethod

        ep = EndpointSpec(
            path="/test",
            method=HttpMethod.GET,
            level=ConformanceLevel.DISCOVERY,
            description="Test endpoint",
        )
        assert ep.path == "/test"
        assert ep.method == HttpMethod.GET
        assert ep.request_content_type == "application/json"
        assert ep.response_content_types == ["application/json"]
        assert ep.auth_required is False
        assert ep.rate_limited is False
        assert ep.idempotent is False

    def test_all_endpoints_populated(self) -> None:
        from ampro.wire.endpoints import ALL_ENDPOINTS

        assert len(ALL_ENDPOINTS) >= 21
        paths = [e.path for e in ALL_ENDPOINTS]
        assert "/.well-known/agent.json" in paths
        assert "/.well-known/agent-keys.json" in paths
        assert "/agent/health" in paths
        assert "/agent/message" in paths
        assert "/agent/tools" in paths
        assert "/agent/stream" in paths
        assert "/agent/registry/search" in paths

    def test_endpoints_for_level_discovery(self) -> None:
        from ampro.wire.endpoints import ConformanceLevel, endpoints_for_level

        discovery = endpoints_for_level(ConformanceLevel.DISCOVERY)
        assert len(discovery) == 3
        paths = {e.path for e in discovery}
        assert paths == {"/.well-known/agent.json", "/agent/health", "/.well-known/agent-keys.json"}

    def test_endpoints_for_level_messaging(self) -> None:
        from ampro.wire.endpoints import ConformanceLevel, endpoints_for_level

        messaging = endpoints_for_level(ConformanceLevel.MESSAGING)
        assert len(messaging) == 4  # 3 discovery + 1 messaging
        paths = {e.path for e in messaging}
        assert "/agent/message" in paths

    def test_endpoints_for_level_includes_lower(self) -> None:
        from ampro.wire.endpoints import ConformanceLevel, endpoints_for_level

        platform = endpoints_for_level(ConformanceLevel.PLATFORM)
        # Platform includes all levels, so should equal ALL_ENDPOINTS
        from ampro.wire.endpoints import ALL_ENDPOINTS
        assert len(platform) == len(ALL_ENDPOINTS)

    def test_endpoints_at_level(self) -> None:
        from ampro.wire.endpoints import ConformanceLevel, endpoints_at_level

        tools_only = endpoints_at_level(ConformanceLevel.TOOLS)
        assert len(tools_only) == 2  # TOOLS_LIST + TOOL_INVOKE
        for ep in tools_only:
            assert ep.level == ConformanceLevel.TOOLS

    def test_mandatory_endpoints_no_auth(self) -> None:
        from ampro.wire.endpoints import ConformanceLevel, endpoints_for_level

        discovery = endpoints_for_level(ConformanceLevel.DISCOVERY)
        for ep in discovery:
            assert ep.auth_required is False, f"{ep.path} should not require auth"

    def test_agent_json_endpoint(self) -> None:
        from ampro.wire.endpoints import AGENT_JSON, ConformanceLevel, HttpMethod

        assert AGENT_JSON.path == "/.well-known/agent.json"
        assert AGENT_JSON.method == HttpMethod.GET
        assert AGENT_JSON.level == ConformanceLevel.DISCOVERY
        assert AGENT_JSON.idempotent is True

    def test_message_endpoint(self) -> None:
        from ampro.wire.endpoints import MESSAGE, ConformanceLevel, HttpMethod

        assert MESSAGE.path == "/agent/message"
        assert MESSAGE.method == HttpMethod.POST
        assert MESSAGE.level == ConformanceLevel.MESSAGING
        assert MESSAGE.rate_limited is True

    def test_stream_endpoint_content_type(self) -> None:
        from ampro.wire.endpoints import STREAM

        assert "text/event-stream" in STREAM.response_content_types

    def test_tool_invoke_has_path_param(self) -> None:
        from ampro.wire.endpoints import TOOL_INVOKE

        assert "{tool_name}" in TOOL_INVOKE.path
        assert TOOL_INVOKE.auth_required is True

    def test_jwks_endpoint_properties(self) -> None:
        """JWKS endpoint has correct path and level."""
        from ampro.wire.endpoints import JWKS, ConformanceLevel, HttpMethod

        assert JWKS.path == "/.well-known/agent-keys.json"
        assert JWKS.method == HttpMethod.GET
        assert JWKS.level == ConformanceLevel.DISCOVERY
        assert JWKS.auth_required is False

    def test_registry_search_level_5_auth_required(self) -> None:
        """REGISTRY_SEARCH is Level 5 (PLATFORM) and requires auth."""
        from ampro.wire.endpoints import REGISTRY_SEARCH, ConformanceLevel

        assert REGISTRY_SEARCH.level == ConformanceLevel.PLATFORM
        assert REGISTRY_SEARCH.auth_required is True
        assert REGISTRY_SEARCH.rate_limited is True

    def test_endpoint_count_at_least_21(self) -> None:
        """ALL_ENDPOINTS should have at least 21 entries."""
        from ampro.wire.endpoints import ALL_ENDPOINTS

        assert len(ALL_ENDPOINTS) >= 21


# ---------------------------------------------------------------------------
# Error tests
# ---------------------------------------------------------------------------


class TestErrors:
    """Tests for ampro.wire.errors."""

    def test_problem_detail_model(self) -> None:
        from ampro.wire.errors import ProblemDetail

        pd = ProblemDetail(
            type="urn:amp:error:test",
            title="Test error",
            status=400,
            detail="Something went wrong",
        )
        assert pd.type == "urn:amp:error:test"
        assert pd.status == 400
        assert pd.retry_after_seconds is None

    def test_problem_detail_extra_fields_ignored(self) -> None:
        from ampro.wire.errors import ProblemDetail

        pd = ProblemDetail(
            type="urn:amp:error:test",
            title="Test",
            status=400,
            custom_field="hello",
        )
        # extra="ignore" means the field is silently dropped
        data = pd.model_dump()
        assert "custom_field" not in data

    def test_problem_detail_detail_max_length(self) -> None:
        from ampro.wire.errors import ProblemDetail

        # Exactly 1024 should be fine
        pd = ProblemDetail(
            type="urn:amp:error:test",
            title="Test",
            status=400,
            detail="x" * 1024,
        )
        assert len(pd.detail) == 1024

        # Over 1024 should fail
        with pytest.raises(Exception):
            ProblemDetail(
                type="urn:amp:error:test",
                title="Test",
                status=400,
                detail="x" * 1025,
            )

    def test_retry_after_seconds_non_negative(self) -> None:
        from ampro.wire.errors import ProblemDetail

        # Zero is valid
        pd = ProblemDetail(
            type="urn:amp:error:test",
            title="Test",
            status=429,
            retry_after_seconds=0,
        )
        assert pd.retry_after_seconds == 0

        # Negative should fail
        with pytest.raises(Exception):
            ProblemDetail(
                type="urn:amp:error:test",
                title="Test",
                status=429,
                retry_after_seconds=-1,
            )

    def test_error_type_constants(self) -> None:
        from ampro.wire.errors import ErrorType

        assert ErrorType.INVALID_MESSAGE == "urn:amp:error:invalid-message"
        assert ErrorType.UNAUTHORIZED == "urn:amp:error:unauthorized"
        assert ErrorType.FORBIDDEN == "urn:amp:error:forbidden"
        assert ErrorType.NOT_FOUND == "urn:amp:error:not-found"
        assert ErrorType.RATE_LIMITED == "urn:amp:error:rate-limited"
        assert ErrorType.INTERNAL_ERROR == "urn:amp:error:internal-error"
        assert ErrorType.NONCE_REPLAY == "urn:amp:error:nonce-replay"
        assert ErrorType.SESSION_EXPIRED == "urn:amp:error:session-expired"
        assert ErrorType.PAYLOAD_TOO_LARGE == "urn:amp:error:payload-too-large"
        assert ErrorType.NOT_IMPLEMENTED == "urn:amp:error:not-implemented"
        assert ErrorType.UNAVAILABLE == "urn:amp:error:unavailable"
        assert ErrorType.VERSION_MISMATCH == "urn:amp:error:version-mismatch"
        assert ErrorType.CAPABILITY_NOT_NEGOTIATED == "urn:amp:error:capability-not-negotiated"
        assert ErrorType.CONTACT_POLICY_VIOLATION == "urn:amp:error:contact-policy-violation"
        assert ErrorType.DELEGATION_DENIED == "urn:amp:error:delegation-denied"
        assert ErrorType.DELEGATION_VALIDATION_FAILED == "urn:amp:error:delegation-validation-failed"
        assert ErrorType.JURISDICTION_CONFLICT == "urn:amp:error:jurisdiction-conflict"
        assert ErrorType.RESIDENCY_VIOLATION == "urn:amp:error:residency-violation"
        assert ErrorType.CONSENT_DENIED == "urn:amp:error:consent-denied"
        assert ErrorType.TIMEOUT == "urn:amp:error:timeout"
        assert ErrorType.LOOP_DETECTED == "urn:amp:error:loop-detected"
        assert ErrorType.INVALID_CALLBACK_URL == "urn:amp:error:invalid-callback-url"
        assert ErrorType.STREAM_LIMIT_EXCEEDED == "urn:amp:error:stream-limit-exceeded"
        assert ErrorType.CONTENT_TYPE_MISMATCH == "urn:amp:error:content-type-mismatch"
        assert ErrorType.HEADER_INJECTION == "urn:amp:error:header-injection"

    def test_rate_limited_factory(self) -> None:
        from ampro.wire.errors import ErrorType, rate_limited

        err = rate_limited("Too fast", retry_after=30)
        assert err.status == 429
        assert err.type == ErrorType.RATE_LIMITED
        assert err.retry_after_seconds == 30
        assert "Too fast" in (err.detail or "")

    def test_invalid_message_factory(self) -> None:
        from ampro.wire.errors import ErrorType, invalid_message

        err = invalid_message("Missing body_type")
        assert err.status == 400
        assert err.type == ErrorType.INVALID_MESSAGE

    def test_unauthorized_factory(self) -> None:
        from ampro.wire.errors import unauthorized

        err = unauthorized()
        assert err.status == 401
        err2 = unauthorized("Bad token")
        assert err2.detail == "Bad token"

    def test_forbidden_factory(self) -> None:
        from ampro.wire.errors import forbidden

        err = forbidden("Insufficient trust tier")
        assert err.status == 403

    def test_not_found_factory(self) -> None:
        from ampro.wire.errors import not_found

        err = not_found("Agent @foo not found")
        assert err.status == 404

    def test_version_mismatch_factory(self) -> None:
        from ampro.wire.errors import version_mismatch

        err = version_mismatch("Requested v99.0")
        assert err.status == 406

    def test_nonce_replay_factory(self) -> None:
        from ampro.wire.errors import nonce_replay

        err = nonce_replay()
        assert err.status == 409

    def test_session_expired_factory(self) -> None:
        from ampro.wire.errors import session_expired

        err = session_expired()
        assert err.status == 410

    def test_payload_too_large_factory(self) -> None:
        from ampro.wire.errors import payload_too_large

        err = payload_too_large("Body exceeds 10 MB", max_bytes=10_485_760)
        assert err.status == 413
        # WIRE-BINDING 7.2.9: the problem carries the receiver's limit.
        data = err.model_dump()
        assert data["max_bytes"] == 10_485_760

    def test_internal_error_factory(self) -> None:
        from ampro.wire.errors import internal_error

        err = internal_error()
        assert err.status == 500

    def test_not_implemented_factory(self) -> None:
        from ampro.wire.errors import not_implemented

        err = not_implemented("Streaming not supported")
        assert err.status == 501

    def test_unavailable_factory(self) -> None:
        from ampro.wire.errors import unavailable

        err = unavailable("Maintenance window", retry_after=120)
        assert err.status == 503
        assert err.retry_after_seconds == 120

    def test_capability_not_negotiated_factory(self) -> None:
        from ampro.wire.errors import capability_not_negotiated

        err = capability_not_negotiated("tools capability was not negotiated")
        assert err.status == 403

    def test_contact_policy_violation_factory(self) -> None:
        from ampro.wire.errors import contact_policy_violation

        err = contact_policy_violation("Agent does not accept cold contacts")
        assert err.status == 403

    def test_delegation_denied_factory(self) -> None:
        from ampro.wire.errors import delegation_denied

        err = delegation_denied("Chain depth exceeded")
        assert err.status == 403

    def test_jurisdiction_conflict_factory(self) -> None:
        from ampro.wire.errors import jurisdiction_conflict

        err = jurisdiction_conflict("EU-US data transfer blocked")
        assert err.status == 403

    def test_residency_violation_factory(self) -> None:
        from ampro.wire.errors import residency_violation

        err = residency_violation("Data must remain in eu-west-1")
        assert err.status == 403

    def test_consent_denied_factory(self) -> None:
        from ampro.wire.errors import consent_denied

        err = consent_denied()
        assert err.status == 403

    def test_timeout_factory(self) -> None:
        from ampro.wire.errors import ErrorType, timeout

        err = timeout("Operation timed out", retry_after=10)
        assert err.status == 408
        assert err.type == ErrorType.TIMEOUT
        assert err.retry_after_seconds == 10

    def test_timeout_factory_no_retry(self) -> None:
        from ampro.wire.errors import timeout

        err = timeout("Timed out")
        assert err.status == 408
        assert err.retry_after_seconds is None

    def test_loop_detected_factory(self) -> None:
        from ampro.wire.errors import ErrorType, loop_detected

        err = loop_detected("Message already seen in delegation chain")
        assert err.status == 409
        assert err.type == ErrorType.LOOP_DETECTED

    def test_invalid_callback_url_factory(self) -> None:
        from ampro.wire.errors import ErrorType, invalid_callback_url

        err = invalid_callback_url("Callback URL is not HTTPS")
        assert err.status == 400
        assert err.type == ErrorType.INVALID_CALLBACK_URL

    def test_delegation_validation_failed_factory(self) -> None:
        from ampro.wire.errors import ErrorType, delegation_validation_failed

        err = delegation_validation_failed("Signature on hop 3 invalid")
        assert err.status == 403
        assert err.type == ErrorType.DELEGATION_VALIDATION_FAILED

    def test_stream_limit_exceeded_factory(self) -> None:
        from ampro.wire.errors import ErrorType, stream_limit_exceeded

        err = stream_limit_exceeded("Max 10 concurrent streams", retry_after=30)
        assert err.status == 429
        assert err.type == ErrorType.STREAM_LIMIT_EXCEEDED
        assert err.retry_after_seconds == 30

    def test_content_type_mismatch_factory(self) -> None:
        from ampro.wire.errors import ErrorType, content_type_mismatch

        err = content_type_mismatch("Expected application/json, got text/plain")
        assert err.status == 415
        assert err.type == ErrorType.CONTENT_TYPE_MISMATCH

    def test_header_injection_factory(self) -> None:
        from ampro.wire.errors import ErrorType, header_injection

        err = header_injection("Newline character in header value")
        assert err.status == 400
        assert err.type == ErrorType.HEADER_INJECTION


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


class TestConfig:
    """Tests for ampro.wire.config."""

    def test_defaults_exist(self) -> None:
        from ampro.wire.config import DEFAULTS, WireConfig

        assert isinstance(DEFAULTS, WireConfig)

    def test_default_values(self) -> None:
        from ampro.wire.config import DEFAULTS

        assert DEFAULTS.max_message_bytes == 10_485_760
        assert DEFAULTS.rate_limit_rpm == 60
        assert DEFAULTS.dedup_window_seconds == 300
        assert DEFAULTS.nonce_window_seconds == 300
        assert DEFAULTS.session_ttl_seconds == 3600
        assert DEFAULTS.session_max_messages == 10_000
        assert DEFAULTS.heartbeat_interval_seconds == 15
        assert DEFAULTS.stream_buffer_size == 100
        assert DEFAULTS.max_delegation_depth == 5
        assert DEFAULTS.max_concurrent_tasks == 50
        assert DEFAULTS.callback_max_retries == 3
        assert DEFAULTS.callback_retry_delays == [1, 5, 25]
        assert DEFAULTS.challenge_expiry_seconds == 300
        assert DEFAULTS.agent_json_ttl_seconds == 3600

    def test_custom_override(self) -> None:
        from ampro.wire.config import WireConfig

        cfg = WireConfig(rate_limit_rpm=120, max_concurrent_tasks=100)
        assert cfg.rate_limit_rpm == 120
        assert cfg.max_concurrent_tasks == 100
        # Other values remain defaults
        assert cfg.max_message_bytes == 10_485_760

    def test_extra_fields_allowed(self) -> None:
        from ampro.wire.config import WireConfig

        cfg = WireConfig(custom_setting="foo")
        data = cfg.model_dump()
        assert data["custom_setting"] == "foo"

    def test_validation_min_values(self) -> None:
        from ampro.wire.config import WireConfig

        with pytest.raises(Exception):
            WireConfig(max_message_bytes=0)  # ge=1024

        with pytest.raises(Exception):
            WireConfig(rate_limit_rpm=0)  # ge=1

    def test_serialization_roundtrip(self) -> None:
        from ampro.wire.config import WireConfig

        cfg = WireConfig(rate_limit_rpm=200)
        data = cfg.model_dump()
        cfg2 = WireConfig.model_validate(data)
        assert cfg2.rate_limit_rpm == 200
        assert cfg2.max_message_bytes == cfg.max_message_bytes

    def test_frozen_config(self) -> None:
        from ampro.wire.config import DEFAULTS

        with pytest.raises(Exception):
            DEFAULTS.rate_limit_rpm = 999  # type: ignore[misc]

    def test_frozen_config_any_instance(self) -> None:
        """Any WireConfig instance is frozen, not just DEFAULTS."""
        from ampro.wire.config import WireConfig

        cfg = WireConfig(rate_limit_rpm=120)
        with pytest.raises(Exception):
            cfg.rate_limit_rpm = 999  # type: ignore[misc]

    def test_new_fields_defaults(self) -> None:
        from ampro.wire.config import DEFAULTS

        assert DEFAULTS.max_response_bytes == 5_242_880
        assert DEFAULTS.max_streams_per_sender == 10
        assert DEFAULTS.rate_limiter_max_senders == 100_000

    def test_cross_field_timeout_validation(self) -> None:
        from ampro.wire.config import WireConfig

        # max_timeout must be >= default_timeout
        with pytest.raises(Exception):
            WireConfig(default_timeout_seconds=500, max_timeout_seconds=100)

    def test_cross_field_callback_retry_validation(self) -> None:
        from ampro.wire.config import WireConfig

        # callback_retry_delays must have at least 1 entry when retries > 0
        with pytest.raises(Exception):
            WireConfig(callback_max_retries=3, callback_retry_delays=[])

    def test_cross_field_callback_zero_retries_ok(self) -> None:
        from ampro.wire.config import WireConfig

        # Zero retries with empty delays is fine
        cfg = WireConfig(callback_max_retries=0, callback_retry_delays=[])
        assert cfg.callback_max_retries == 0

    def test_nonce_window_industry_standard(self) -> None:
        from ampro.wire.config import DEFAULTS

        # 5 minutes is the OWASP/OAuth2 industry standard
        assert DEFAULTS.nonce_window_seconds == 300


# ---------------------------------------------------------------------------
# Body type map tests
# ---------------------------------------------------------------------------


class TestBodyTypeMap:
    """Tests for ampro.wire.body_type_map."""

    def test_all_canonical_body_types_present(self) -> None:
        from ampro.wire.body_type_map import BODY_TYPE_BINDINGS

        # All 17 original canonical types from message_types_registry
        original_17 = {
            "message", "task.create", "task.assign", "task.delegate",
            "task.spawn", "task.quote", "notification",
            "task.progress", "task.input_required", "task.escalate",
            "task.reroute", "task.transfer", "task.acknowledge",
            "task.reject", "task.complete", "task.error",
            "task.response",
        }
        for bt in original_17:
            assert bt in BODY_TYPE_BINDINGS, f"Missing binding for {bt}"

    def test_session_types_present(self) -> None:
        from ampro.wire.body_type_map import BODY_TYPE_BINDINGS

        session_types = {
            "session.init", "session.established", "session.confirm",
            "session.ping", "session.pong",
            "session.pause", "session.resume", "session.close",
        }
        for bt in session_types:
            assert bt in BODY_TYPE_BINDINGS, f"Missing binding for {bt}"

    def test_compliance_types_present(self) -> None:
        from ampro.wire.body_type_map import BODY_TYPE_BINDINGS

        compliance_types = {
            "data.consent_request", "data.consent_response", "data.consent_revoke",
            "data.erasure_request", "data.erasure_response",
            "data.export_request", "data.export_response",
            "erasure.propagation_status",
        }
        for bt in compliance_types:
            assert bt in BODY_TYPE_BINDINGS, f"Missing binding for {bt}"

    def test_security_types_present(self) -> None:
        from ampro.wire.body_type_map import BODY_TYPE_BINDINGS

        security_types = {
            "task.challenge", "task.challenge_response", "key.revocation",
        }
        for bt in security_types:
            assert bt in BODY_TYPE_BINDINGS, f"Missing binding for {bt}"

    def test_trust_types_present(self) -> None:
        from ampro.wire.body_type_map import BODY_TYPE_BINDINGS

        trust_types = {
            "trust.upgrade_request", "trust.upgrade_response", "trust.proof",
        }
        for bt in trust_types:
            assert bt in BODY_TYPE_BINDINGS, f"Missing binding for {bt}"

    def test_binding_for_known_type(self) -> None:
        from ampro.wire.body_type_map import ResponseMode, binding_for

        b = binding_for("task.create")
        assert b is not None
        assert b.http_method == "POST"
        assert b.response_mode == ResponseMode.ASYNC
        assert b.expected_response == "task.acknowledge"
        assert b.streaming_capable is True

    def test_binding_for_unknown_type(self) -> None:
        from ampro.wire.body_type_map import binding_for

        assert binding_for("x-custom.type") is None
        assert binding_for("com.example.custom") is None

    def test_is_canonical(self) -> None:
        from ampro.wire.body_type_map import is_canonical

        assert is_canonical("message") is True
        assert is_canonical("task.create") is True
        assert is_canonical("x-custom.type") is False

    def test_streaming_body_types(self) -> None:
        from ampro.wire.body_type_map import streaming_body_types

        streamable = streaming_body_types()
        # ASYNC types that support streaming
        assert "message" in streamable
        assert "task.create" in streamable
        assert "task.delegate" in streamable
        assert "task.input_required" in streamable
        assert "task.escalate" in streamable
        # FIRE types must NOT be streaming (contradiction: fire = no response)
        assert "task.progress" not in streamable
        assert "task.acknowledge" not in streamable
        assert "task.reject" not in streamable
        assert "task.complete" not in streamable
        assert "task.error" not in streamable
        assert "task.response" not in streamable
        # Other non-streaming types
        assert "notification" not in streamable
        assert "session.init" not in streamable

    def test_idempotent_body_types(self) -> None:
        from ampro.wire.body_type_map import idempotent_body_types

        idem = idempotent_body_types()
        assert "task.acknowledge" in idem
        assert "task.reject" in idem
        assert "task.complete" in idem
        assert "task.error" in idem
        # Non-idempotent types should not appear
        assert "message" not in idem
        assert "task.create" not in idem

    def test_response_mode_enum(self) -> None:
        from ampro.wire.body_type_map import ResponseMode

        assert ResponseMode.SYNC == "sync"
        assert ResponseMode.ASYNC == "async"
        assert ResponseMode.FIRE == "fire"

    def test_post_types_use_post(self) -> None:
        from ampro.wire.body_type_map import BODY_TYPE_BINDINGS

        post_types = [
            "message", "task.create", "task.assign", "task.delegate",
            "task.spawn", "task.quote", "notification",
        ]
        for bt in post_types:
            assert BODY_TYPE_BINDINGS[bt].http_method == "POST", f"{bt} should use POST"

    def test_patch_types_use_patch(self) -> None:
        from ampro.wire.body_type_map import BODY_TYPE_BINDINGS

        patch_types = [
            "task.progress", "task.input_required", "task.escalate",
            "task.reroute", "task.transfer", "task.acknowledge",
            "task.reject", "task.complete", "task.error",
        ]
        for bt in patch_types:
            assert BODY_TYPE_BINDINGS[bt].http_method == "PATCH", f"{bt} should use PATCH"

    def test_put_types_use_put(self) -> None:
        from ampro.wire.body_type_map import BODY_TYPE_BINDINGS

        assert BODY_TYPE_BINDINGS["task.response"].http_method == "PUT"

    def test_session_close_uses_delete(self) -> None:
        from ampro.wire.body_type_map import BODY_TYPE_BINDINGS

        assert BODY_TYPE_BINDINGS["session.close"].http_method == "DELETE"

    def test_body_type_binding_model(self) -> None:
        from ampro.wire.body_type_map import BodyTypeBinding, ResponseMode

        b = BodyTypeBinding(
            body_type="test",
            http_method="POST",
            response_mode=ResponseMode.SYNC,
        )
        assert b.body_type == "test"
        assert b.error_response == "task.error"
        assert b.idempotent is False
        assert b.streaming_capable is False
        assert b.requires_nonce is False

    def test_fire_types_not_streaming(self) -> None:
        """FIRE mode and streaming_capable=True is a contradiction."""
        from ampro.wire.body_type_map import BODY_TYPE_BINDINGS, ResponseMode

        for bt, binding in BODY_TYPE_BINDINGS.items():
            if binding.response_mode == ResponseMode.FIRE:
                assert binding.streaming_capable is False, (
                    f"{bt} has FIRE response_mode but streaming_capable=True"
                )

    def test_requires_nonce_security_sensitive_types(self) -> None:
        from ampro.wire.body_type_map import BODY_TYPE_BINDINGS

        nonce_required = {
            "task.create", "task.delegate", "task.assign",
            "data.consent_request", "data.erasure_request",
            "tool.consent_request", "trust.upgrade_request",
            "session.init", "key.revocation",
        }
        for bt in nonce_required:
            assert BODY_TYPE_BINDINGS[bt].requires_nonce is True, (
                f"{bt} should require nonce"
            )

    def test_requires_nonce_not_set_on_non_sensitive_types(self) -> None:
        from ampro.wire.body_type_map import BODY_TYPE_BINDINGS

        non_nonce = {
            "message", "notification", "task.progress",
            "task.acknowledge", "task.response", "session.pong",
        }
        for bt in non_nonce:
            assert BODY_TYPE_BINDINGS[bt].requires_nonce is False, (
                f"{bt} should not require nonce"
            )

    def test_binding_for_none(self) -> None:
        from ampro.wire.body_type_map import binding_for

        assert binding_for(None) is None

    def test_binding_for_empty_string(self) -> None:
        from ampro.wire.body_type_map import binding_for

        assert binding_for("") is None

    def test_total_binding_count(self) -> None:
        from ampro.wire.body_type_map import BODY_TYPE_BINDINGS

        # Should have 49 bindings covering all canonical body types
        assert len(BODY_TYPE_BINDINGS) >= 49


# ---------------------------------------------------------------------------
# Top-level wire import tests
# ---------------------------------------------------------------------------


class TestWirePackageImport:
    """Tests that ampro.wire re-exports everything correctly."""

    def test_import_from_wire(self) -> None:
        from ampro.wire import (
            ALL_ENDPOINTS,
            BODY_TYPE_BINDINGS,
            WIRE_DEFAULTS,
            ConformanceLevel,
            WireConfig,
        )
        # Smoke test — ensure they are all real objects
        assert ConformanceLevel.DISCOVERY.value == 0
        assert isinstance(ALL_ENDPOINTS, list)
        assert isinstance(WIRE_DEFAULTS, WireConfig)
        assert isinstance(BODY_TYPE_BINDINGS, dict)

    def test_import_from_ampro_top_level(self) -> None:
        from ampro import (
            ALL_ENDPOINTS,
            ConformanceLevel,
        )
        assert ConformanceLevel.DISCOVERY.value == 0
        assert isinstance(ALL_ENDPOINTS, list)

    def test_endpoint_constants_importable(self) -> None:
        from ampro.wire import (
            AGENT_JSON,
            HEALTH,
            JWKS,
            MESSAGE,
            REGISTRY_SEARCH,
        )
        assert AGENT_JSON.path == "/.well-known/agent.json"
        assert HEALTH.path == "/agent/health"
        assert JWKS.path == "/.well-known/agent-keys.json"
        assert MESSAGE.path == "/agent/message"
        assert REGISTRY_SEARCH.path == "/agent/registry/search"

    def test_error_factories_importable(self) -> None:
        from ampro.wire import (
            rate_limited,
            timeout,
            unauthorized,
        )
        # Smoke test a couple
        err = rate_limited("test")
        assert err.status == 429
        err2 = unauthorized()
        assert err2.status == 401
        err3 = timeout("timed out")
        assert err3.status == 408
