from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import ProjectManifest


SCHEMA_VERSION = "1.1"


@dataclass(slots=True)
class ProviderSelection:
    name: str
    model: str
    api_key_source: str

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "model": self.model,
            "api_key_source": self.api_key_source,
        }
@dataclass(slots=True)
class CommandResult:
    command: str
    status: str
    provider: ProviderSelection
    manifest: ProjectManifest | None = None
    data: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "command": self.command,
            "status": self.status,
            "provider": self.provider.to_dict(),
            "manifest": None if self.manifest is None else self.manifest.to_dict(),
            "data": self.data,
            "warnings": self.warnings,
            "errors": self.errors,
        }