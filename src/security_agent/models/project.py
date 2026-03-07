from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from typing import Any


@dataclass(slots=True)
class CompilerInfo:
    version: str | None = None
    versions: list[str] = field(default_factory=list)
    auto_detect: bool | None = None
    optimizer_enabled: bool | None = None
    optimizer_runs: int | None = None
    via_ir: bool | None = None
    evm_version: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ProjectManifest:
    framework: str
    root_path: str
    config_files: list[str]
    source_directories: list[str]
    test_directories: list[str]
    script_directories: list[str]
    dependency_directories: list[str]
    include_paths: list[str]
    source_files: list[str]
    test_files: list[str]
    script_files: list[str]
    remappings: list[str] = field(default_factory=list)
    compiler: CompilerInfo = field(default_factory=CompilerInfo)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, *, indent: int = 2, sort_keys: bool = True) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=sort_keys)