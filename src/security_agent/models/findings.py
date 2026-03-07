from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class FindingLocation:
    file_path: str
    lines: list[int] = field(default_factory=list)
    start: int | None = None
    length: int | None = None
    starting_column: int | None = None
    ending_column: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "lines": self.lines,
            "start": self.start,
            "length": self.length,
            "starting_column": self.starting_column,
            "ending_column": self.ending_column,
        }


@dataclass(slots=True)
class NormalizedFinding:
    fingerprint: str
    source: str
    rule_id: str
    title: str
    severity: str
    confidence: str
    description: str
    locations: list[FindingLocation] = field(default_factory=list)
    dedupe_key: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "source": self.source,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "locations": [location.to_dict() for location in self.locations],
            "dedupe_key": self.dedupe_key,
            "metadata": self.metadata,
        }