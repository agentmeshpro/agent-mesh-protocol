"""Result types for the AMP black-box conformance suite."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Requirement = Literal["MUST", "SHOULD", "MAY"]
Status = Literal["pass", "fail", "skip"]


class CheckFailed(Exception):
    """Raised inside a check when the target does not meet the requirement."""


class CheckSkipped(Exception):
    """Raised inside a check when it cannot run against this target."""


@dataclass(frozen=True)
class CheckSpec:
    """Static description of one conformance check."""

    id: str
    title: str
    section: str
    requirement: Requirement
    level: int
    needs_key: bool = False


@dataclass
class CheckResult:
    id: str
    title: str
    section: str
    requirement: Requirement
    level: int
    status: Status
    detail: str = ""
    duration_ms: int = 0


@dataclass
class Report:
    target: str
    level: int
    protocol_version: str
    tool_version: str
    started_at: str
    results: list[CheckResult] = field(default_factory=list)

    @property
    def must_failures(self) -> list[CheckResult]:
        return [r for r in self.results if r.status == "fail" and r.requirement == "MUST"]

    @property
    def ok(self) -> bool:
        return not self.must_failures

    def summary(self) -> dict[str, int]:
        counts = {"pass": 0, "fail": 0, "skip": 0}
        for r in self.results:
            counts[r.status] += 1
        counts["must_failures"] = len(self.must_failures)
        counts["should_failures"] = sum(
            1 for r in self.results if r.status == "fail" and r.requirement != "MUST"
        )
        counts["total"] = len(self.results)
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "level": self.level,
            "protocol_version": self.protocol_version,
            "tool": "ampro-conformance",
            "tool_version": self.tool_version,
            "started_at": self.started_at,
            "conformant": self.ok,
            "summary": self.summary(),
            "results": [asdict(r) for r in self.results],
        }

    def to_table(self) -> str:
        rows = [("STATUS", "REQ", "LVL", "SECTION", "CHECK", "DETAIL")]
        for r in self.results:
            rows.append((
                r.status.upper(), r.requirement, str(r.level), r.section, r.id,
                r.detail.replace("\n", " ")[:100],
            ))
        widths = [max(len(row[i]) for row in rows) for i in range(5)]
        lines = [
            "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row[:5])) + "  " + row[5]
            for row in rows
        ]
        s = self.summary()
        lines.append("")
        lines.append(
            f"{s['pass']} passed, {s['fail']} failed ({s['must_failures']} MUST, "
            f"{s['should_failures']} SHOULD), {s['skip']} skipped -- "
            + ("CONFORMANT" if self.ok else "NOT CONFORMANT")
            + f" at level {self.level}"
        )
        return "\n".join(lines)
