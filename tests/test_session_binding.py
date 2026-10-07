"""Tests for session binding -- HMAC-SHA256 token derivation and verification."""


class TestSessionBinding:
    def test_model_fields(self):
        from ampro import SessionBinding
        sb = SessionBinding(
            session_id="sess-1",
            binding_token="token",
            client_nonce="cn",
            server_nonce="sn",
        )
        assert sb.session_id == "sess-1"

    def test_derive_binding_token(self):
        from ampro import derive_binding_token
        token = derive_binding_token("client-n", "server-n", "sess-1", "secret")
        assert isinstance(token, str)
        assert len(token) == 64  # SHA-256 hex digest

    def test_derive_deterministic(self):
        from ampro import derive_binding_token
        t1 = derive_binding_token("cn", "sn", "s1", "secret")
        t2 = derive_binding_token("cn", "sn", "s1", "secret")
        assert t1 == t2

    def test_derive_different_secrets(self):
        from ampro import derive_binding_token
        t1 = derive_binding_token("cn", "sn", "s1", "secret1")
        t2 = derive_binding_token("cn", "sn", "s1", "secret2")
        assert t1 != t2

    def test_create_message_binding(self):
        from ampro import create_message_binding
        hmac_val = create_message_binding("sess-1", "msg-1", "token", body={"k": 1})
        assert isinstance(hmac_val, str)
        assert len(hmac_val) == 64

    def test_verify_message_binding_valid(self):
        from ampro import create_message_binding, verify_message_binding
        hmac_val = create_message_binding("sess-1", "msg-1", "token", body={"k": 1})
        assert verify_message_binding("sess-1", "msg-1", "token", hmac_val, body={"k": 1}) is True

    def test_verify_message_binding_forged(self):
        from ampro import verify_message_binding
        assert verify_message_binding("sess-1", "msg-1", "token", "forged-hmac", body={"k": 1}) is False

    def test_verify_wrong_session(self):
        from ampro import create_message_binding, verify_message_binding
        hmac_val = create_message_binding("sess-1", "msg-1", "token", body={"k": 1})
        assert verify_message_binding("sess-2", "msg-1", "token", hmac_val, body={"k": 1}) is False

    def test_verify_wrong_message(self):
        from ampro import create_message_binding, verify_message_binding
        hmac_val = create_message_binding("sess-1", "msg-1", "token", body={"k": 1})
        assert verify_message_binding("sess-1", "msg-2", "token", hmac_val, body={"k": 1}) is False

    def test_full_flow(self):
        """End-to-end: derive token, create binding, verify."""
        from ampro import create_message_binding, derive_binding_token, verify_message_binding
        token = derive_binding_token("cn", "sn", "sess-1", "shared-secret")
        hmac_val = create_message_binding("sess-1", "msg-42", token, body={"k": 1})
        assert verify_message_binding("sess-1", "msg-42", token, hmac_val, body={"k": 1}) is True
        assert verify_message_binding("sess-1", "msg-42", "wrong-token", hmac_val, body={"k": 1}) is False
