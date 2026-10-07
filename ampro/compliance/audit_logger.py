"""
Agent Protocol — Audit Logger.

Per-PII-message audit logging with hash chain integrity.

Spec ref: Section 8.5
- Minimum record: message_id, timestamp, sender, recipient, body_type,
  classification, trust_tier, action_taken
- Append-only with hash-chain integrity
- 1-year minimum retention
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)


class AuditEntry(BaseModel):
    """A single audit log entry."""

    message_id: str = Field(description="Unique identifier of the audited message")
    timestamp: float = Field(default_factory=time.time, description="Unix epoch timestamp when the entry was created")
    sender: str = Field(description="Agent or user ID that sent the message")
    recipient: str = Field(description="Agent or user ID that received the message")
    body_type: str = Field(description="Protocol body type of the message (e.g. task.assign, message.send)")
    content_classification: str = Field(default="public", description="Content sensitivity classification (public, internal, pii, etc.)")
    trust_tier: str = Field(default="external", description="Trust tier of the sender (owner, verified, external)")
    session_id: str = Field(default="", description="Session ID associated with the message, if any")
    action_taken: str = Field(default="processed", description="Action taken on the message (processed, rejected, escalated)")
    tools_invoked: list[str] = Field(default_factory=list, description="List of tool names invoked during message processing")
    hash: str = Field(default="", description="SHA-256 hash of this entry for chain integrity")
    previous_hash: str = Field(default="", description="SHA-256 hash of the preceding entry in the chain")
    sequence: int = Field(default=-1, description="Monotonic sequence number assigned at append time")

    model_config = ConfigDict(extra="ignore")


@runtime_checkable
class AuditStorage(Protocol):
    """Protocol for append-only audit log storage backends.

    Implementations MUST guarantee:
    - Entries are retrievable in insertion order.
    - Once appended, an entry MUST NOT be mutated or removed.
    """

    def append(self, entry: AuditEntry) -> None:
        """Persist *entry* at the end of the log."""
        ...

    def tail(self) -> AuditEntry | None:
        """Return the most recent entry, or ``None`` if the log is empty."""
        ...

    def entries(self) -> list[AuditEntry]:
        """Return all entries in insertion order."""
        ...

    def count(self) -> int:
        """Return the number of entries in the log."""
        ...


class InMemoryAuditStorage:
    """Default in-memory append-only storage.

    Entries are kept in a tuple that is replaced on each append, preventing
    external mutation of the backing store.  Individual entries are frozen
    (via ``model_copy``) at insertion time so callers cannot alter them
    after the fact.
    """

    def __init__(self) -> None:
        self._store: tuple[AuditEntry, ...] = ()

    def append(self, entry: AuditEntry) -> None:
        frozen = entry.model_copy(deep=True)
        # Make fields immutable by storing a deep copy in a tuple
        self._store = (*self._store, frozen)

    def tail(self) -> AuditEntry | None:
        return self._store[-1].model_copy(deep=True) if self._store else None

    def entries(self) -> list[AuditEntry]:
        # Hand out copies: mutating a returned entry must never alter the log.
        return [e.model_copy(deep=True) for e in self._store]

    def count(self) -> int:
        return len(self._store)


class AuditLogger:
    """Append-only audit logger with hash chain."""

    def __init__(self, *, storage: AuditStorage | None = None) -> None:
        self._storage: AuditStorage = storage or InMemoryAuditStorage()
        self._last_hash: str = "0" * 64

    def log(self, entry: AuditEntry) -> AuditEntry:
        """Append an entry with hash chain integrity."""
        entry.previous_hash = self._last_hash
        entry.sequence = self._storage.count()
        content = json.dumps({
            "message_id": entry.message_id,
            "timestamp": entry.timestamp,
            "sender": entry.sender,
            "recipient": entry.recipient,
            "body_type": entry.body_type,
            "content_classification": entry.content_classification,
            "trust_tier": entry.trust_tier,
            "action_taken": entry.action_taken,
            "previous_hash": entry.previous_hash,
            "sequence": entry.sequence,
        }, sort_keys=True)
        entry.hash = hashlib.sha256(content.encode()).hexdigest()
        self._last_hash = entry.hash
        self._storage.append(entry)
        logger.info("Audit: %s %s→%s [%s]", entry.message_id, entry.sender, entry.recipient, entry.action_taken)
        return entry

    def get_entries(self, message_id: str | None = None) -> list[AuditEntry]:
        """Query audit entries, optionally filtered by message_id."""
        all_entries = self._storage.entries()
        if message_id:
            return [e for e in all_entries if e.message_id == message_id]
        return all_entries

    def verify_chain(self) -> bool:
        """Verify hash chain integrity.

        Checks:
        - Hash-chain linkage (each entry's ``previous_hash`` matches the
          preceding entry's ``hash``).
        - Hash correctness (recomputed hash matches stored hash).
        - Sequence continuity (monotonically increasing with no gaps).

        Returns ``True`` if valid.
        """
        prev_hash = "0" * 64
        all_entries = self._storage.entries()
        for idx, entry in enumerate(all_entries):
            # Sequence gap detection
            if entry.sequence != idx:
                return False
            if entry.previous_hash != prev_hash:
                return False
            content = json.dumps({
                "message_id": entry.message_id,
                "timestamp": entry.timestamp,
                "sender": entry.sender,
                "recipient": entry.recipient,
                "body_type": entry.body_type,
                "content_classification": entry.content_classification,
                "trust_tier": entry.trust_tier,
                "action_taken": entry.action_taken,
                "previous_hash": entry.previous_hash,
                "sequence": entry.sequence,
            }, sort_keys=True)
            expected = hashlib.sha256(content.encode()).hexdigest()
            if entry.hash != expected:
                return False
            prev_hash = entry.hash
        return True

    @property
    def count(self) -> int:
        return self._storage.count()
