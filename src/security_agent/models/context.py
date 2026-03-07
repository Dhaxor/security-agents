from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SourceLocation:
    path: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class CodeExcerpt:
    path: str
    start_line: int
    end_line: int
    content: str
    reason: str
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExternalCallSummary:
    target: str
    call_type: str
    expression: str
    summary: str
    risk_tags: tuple[str, ...] = ()
    location: SourceLocation | None = None


@dataclass(frozen=True)
class FunctionSummary:
    name: str
    signature: str
    visibility: str
    state_mutability: str
    summary: str
    modifiers: tuple[str, ...] = ()
    external_calls: tuple[ExternalCallSummary, ...] = ()
    reads: tuple[str, ...] = ()
    writes: tuple[str, ...] = ()
    location: SourceLocation | None = None


@dataclass(frozen=True)
class StateVariableSummary:
    name: str
    type_name: str
    visibility: str
    summary: str
    storage_sensitive: bool = False
    location: SourceLocation | None = None


@dataclass(frozen=True)
class ContractSummary:
    name: str
    kind: str
    source_path: str
    summary: str
    imports: tuple[str, ...] = ()
    bases: tuple[str, ...] = ()
    modifiers: tuple[str, ...] = ()
    state_variables: tuple[StateVariableSummary, ...] = ()
    functions: tuple[FunctionSummary, ...] = ()
    excerpts: tuple[CodeExcerpt, ...] = ()


@dataclass(frozen=True)
class SolidityStructureInventory:
    contracts: tuple[ContractSummary, ...] = field(default_factory=tuple)