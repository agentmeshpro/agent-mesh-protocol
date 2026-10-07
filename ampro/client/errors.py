"""
AMP Client SDK — Protocol Error.

Wraps the RFC 7807 ProblemDetail returned by AMP servers into a
Python exception that callers can catch and inspect.

Usage::

    from ampro.client import send, AmpProtocolError

    try:
        reply = await send("agent://target.example.com", body={"q": "hi"})
    except AmpProtocolError as exc:
        print(exc.status_code)      # e.g. 429
        print(exc.error_type)       # e.g. "urn:amp:error:rate-limited"
        print(exc.retry_after)      # e.g. 60  (or None)
"""

from __future__ import annotations

from ampro.wire.errors import AuthorityRequiredProblem, ProblemDetail


class AmpProtocolError(Exception):
    """Server returned an RFC 7807 error response."""

    def __init__(self, problem: ProblemDetail) -> None:
        self.problem = problem
        super().__init__(f"{problem.title}: {problem.detail}")

    @property
    def status_code(self) -> int:
        """HTTP status code from the error response."""
        return self.problem.status

    @property
    def error_type(self) -> str:
        """Stable URN identifying the error (e.g. ``urn:amp:error:rate-limited``)."""
        return self.problem.type

    @property
    def authority(self) -> AuthorityRequiredProblem | None:
        """The typed 403 authority-required problem, or ``None``.

        Set only when the server answered 403 with a well-formed
        ``urn:amp:error:authority-required`` body (WIRE-BINDING 7.2.14).
        """
        return self.problem if isinstance(self.problem, AuthorityRequiredProblem) else None

    @property
    def retry_after(self) -> int | None:
        """Seconds to wait before retrying, or ``None`` if not applicable."""
        return self.problem.retry_after_seconds
