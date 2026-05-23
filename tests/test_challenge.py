"""Tests for anti-abuse challenge body types and enum."""
import pytest
from pydantic import ValidationError


class TestChallengeReason:
    def test_first_contact(self):
        from ampro import ChallengeReason
        assert ChallengeReason.FIRST_CONTACT == "first_contact"

    def test_suspicious_behavior(self):
        from ampro import ChallengeReason
        assert ChallengeReason.SUSPICIOUS_BEHAVIOR == "suspicious_behavior"

    def test_rate_limit_exceeded(self):
        from ampro import ChallengeReason
        assert ChallengeReason.RATE_LIMIT_EXCEEDED == "rate_limit_exceeded"

    def test_trust_upgrade(self):
        from ampro import ChallengeReason
        assert ChallengeReason.TRUST_UPGRADE == "trust_upgrade"

    def test_four_values(self):
        from ampro import ChallengeReason
        assert len(ChallengeReason) == 4


class TestTaskChallengeBody:
    def test_all_fields(self):
        from ampro import TaskChallengeBody
        body = TaskChallengeBody(
            challenge_id="ch-001",
            challenge_type="proof_of_work",
            parameters={"difficulty": 20, "algorithm": "sha256"},
            expires_at="2099-01-01T00:00:00Z",
            reason="first_contact",
        )
        assert body.challenge_id == "ch-001"
        assert body.challenge_type == "proof_of_work"
        assert body.parameters == {"difficulty": 20, "algorithm": "sha256"}
        assert body.expires_at == "2099-01-01T00:00:00Z"
        assert body.reason == "first_contact"

    def test_parameters_default_empty(self):
        from ampro import TaskChallengeBody
        body = TaskChallengeBody(
            challenge_id="ch-002",
            challenge_type="captcha",
            expires_at="2099-01-01T00:00:00Z",
            reason="suspicious_behavior",
        )
        assert body.parameters == {}

    def test_missing_required_raises(self):
        from ampro import TaskChallengeBody
        with pytest.raises(ValidationError):
            TaskChallengeBody(
                challenge_id="ch-003",
                # missing challenge_type, expires_at, reason
            )


class TestTaskChallengeResponseBody:
    def test_all_fields(self):
        from ampro import TaskChallengeResponseBody
        body = TaskChallengeResponseBody(
            challenge_id="ch-001",
            solution="0000abc123def456",
        )
        assert body.challenge_id == "ch-001"
        assert body.solution == "0000abc123def456"

    def test_missing_solution_raises(self):
        from ampro import TaskChallengeResponseBody
        with pytest.raises(ValidationError):
            TaskChallengeResponseBody(challenge_id="ch-001")


class TestChallengeRegistry:
    def test_validate_body_task_challenge(self):
        from ampro import TaskChallengeBody, validate_body
        body = validate_body("task.challenge", {
            "challenge_id": "ch-100",
            "challenge_type": "proof_of_work",
            "parameters": {"difficulty": 18},
            "expires_at": "2026-04-09T14:00:00Z",
            "reason": "rate_limit_exceeded",
        })
        assert isinstance(body, TaskChallengeBody)
        assert body.challenge_id == "ch-100"
        assert body.parameters["difficulty"] == 18

    def test_validate_body_task_challenge_response(self):
        from ampro import TaskChallengeResponseBody, validate_body
        body = validate_body("task.challenge_response", {
            "challenge_id": "ch-100",
            "solution": "answer-xyz",
        })
        assert isinstance(body, TaskChallengeResponseBody)
        assert body.solution == "answer-xyz"

    def test_validate_body_not_raw_dict(self):
        from ampro import validate_body
        body = validate_body("task.challenge", {
            "challenge_id": "ch-1",
            "challenge_type": "pow",
            "expires_at": "2026-01-01T00:00:00Z",
            "reason": "first_contact",
        })
        assert not isinstance(body, dict)
