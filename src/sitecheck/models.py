"""Result types shared by every check."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Status = Literal["pass", "warn", "fail", "info", "skipped"]


@dataclass
class Finding:
    id: str
    title: str
    status: Status
    weight: int
    summary: str
    meaning: str
    fix: str

    @property
    def penalty(self) -> float:
        if self.status == "fail":
            return float(self.weight)
        if self.status == "warn":
            return self.weight / 2
        return 0.0


@dataclass
class Report:
    target: str
    scanned_at: str
    findings: list[Finding] = field(default_factory=list)
    requests_made: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        return max(0, round(100 - sum(f.penalty for f in self.findings)))

    @property
    def grade(self) -> str:
        score = self.score
        grade = (
            "A"
            if score >= 90
            else "B"
            if score >= 80
            else "C"
            if score >= 70
            else ("D" if score >= 60 else "F")
        )
        # An exposed secret file is serious whatever else is fine.
        exposed = any(f.id == "exposed-files" and f.status == "fail" for f in self.findings)
        if exposed and grade in "ABC":
            return "D"
        return grade

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scanned_at": self.scanned_at,
            "score": self.score,
            "grade": self.grade,
            "requests_made": self.requests_made,
            "notes": self.notes,
            "findings": [asdict(f) for f in self.findings],
        }
