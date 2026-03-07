from __future__ import annotations

from dataclasses import dataclass, replace
import re
from pathlib import Path

from security_agent.context.structure_aware import (
    ContextBudget,
    FindingFocus,
    StructureAwareContextBuilder,
    StructuredContextPack,
)
from security_agent.models import ProjectManifest
from security_agent.models.context import (
    CodeExcerpt,
    ContractSummary,
    ExternalCallSummary,
    FunctionSummary,
    SolidityStructureInventory,
    SourceLocation,
    StateVariableSummary,
)
from security_agent.models.findings import NormalizedFinding

_IMPORT_RE = re.compile(r'import\s+(?:[^;]*?from\s+)?["\']([^"\']+)["\'];')
_CONTRACT_RE = re.compile(
    r"\b(?:abstract\s+)?(contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s+is\s+([^\{]+))?\s*\{",
    re.DOTALL,
)
_FUNCTION_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)(.*)", re.DOTALL)
_SPECIAL_FUNCTION_RE = re.compile(r"\b(receive|fallback)\s*\((.*?)\)(.*)", re.DOTALL)
_MODIFIER_DEF_RE = re.compile(r"\bmodifier\s+([A-Za-z_][A-Za-z0-9_]*)\b")
_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_CALL_OPTIONS_RE = re.compile(r"\.\s*[A-Za-z_][A-Za-z0-9_]*\s*\{[^{}]*\}")
_STRING_RE = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|\'[^\'\\]*(?:\\.[^\'\\]*)*\'')

_VISIBILITY_KEYWORDS = {"public", "external", "internal", "private"}
_STATE_MUTABILITY_KEYWORDS = {"payable", "view", "pure"}
_HEADER_IGNORED_TOKENS = {
    "virtual",
    "override",
    "returns",
    "memory",
    "calldata",
    "storage",
    "returns",
}
_STATE_DECLARATION_PREFIXES = (
    "event ",
    "error ",
    "using ",
    "struct ",
    "enum ",
    "modifier ",
    "constructor",
    "function ",
)


@dataclass(frozen=True)
class _ParsedFunction:
    summary: FunctionSummary
    start_line: int
    end_line: int
    body_lines: tuple[str, ...]


@dataclass(frozen=True)
class _ParsedContract:
    name: str
    kind: str
    source_path: str
    start_line: int
    end_line: int
    header_end_line: int
    bases: tuple[str, ...]
    imports: tuple[str, ...]
    modifiers: tuple[str, ...]
    state_variables: tuple[StateVariableSummary, ...]
    functions: tuple[_ParsedFunction, ...]
    excerpts: tuple[CodeExcerpt, ...]
    summary: str

    def to_contract_summary(self) -> ContractSummary:
        return ContractSummary(
            name=self.name,
            kind=self.kind,
            source_path=self.source_path,
            summary=self.summary,
            imports=self.imports,
            bases=self.bases,
            modifiers=self.modifiers,
            state_variables=self.state_variables,
            functions=tuple(item.summary for item in self.functions),
            excerpts=self.excerpts,
        )


def build_finding_context_from_source(
    manifest: ProjectManifest,
    finding: NormalizedFinding,
    budget: ContextBudget | None = None,
) -> StructuredContextPack | None:
    primary_location = finding.locations[0] if finding.locations else None
    source_path = primary_location.file_path if primary_location else (manifest.source_files[0] if manifest.source_files else "")
    if not source_path:
        return None
    absolute_path = (Path(manifest.root_path) / source_path).resolve()
    if not absolute_path.is_file():
        return None

    source_text = absolute_path.read_text(encoding="utf-8")
    parsed_contracts = _parse_contracts(source_path, source_text)
    if not parsed_contracts:
        return None

    primary_line = (primary_location.lines[0] if primary_location and primary_location.lines else None)
    focal_contract = _select_contract_name(parsed_contracts, source_path, primary_line)
    focal_function = _select_function_name(parsed_contracts, focal_contract, primary_line, finding)
    reason = (finding.description.strip() or finding.title).splitlines()[0]
    risk_tags = tuple(part for part in finding.rule_id.replace("_", "-").split("-") if part)

    inventory = SolidityStructureInventory(
        contracts=tuple(contract.to_contract_summary() for contract in parsed_contracts)
    )
    builder = StructureAwareContextBuilder(budget or ContextBudget())
    pack = builder.build_finding_context(
        manifest,
        inventory,
        FindingFocus(
            contract_name=focal_contract,
            function_name=focal_function,
            reason=reason,
            risk_tags=risk_tags,
            related_contracts=tuple(_related_contract_names(parsed_contracts, focal_contract)),
        ),
    )
    return _attach_primary_excerpt(pack, source_path, source_text, primary_location, reason)


def _parse_contracts(source_path: str, source_text: str) -> list[_ParsedContract]:
    lines = source_text.splitlines()
    imports = tuple(_IMPORT_RE.findall(source_text))
    contracts: list[_ParsedContract] = []
    line_index = 1
    while line_index <= len(lines):
        if not _strip_inline_comment(lines[line_index - 1]).strip():
            line_index += 1
            continue
        header_text, header_end = _collect_header(lines, line_index)
        match = _CONTRACT_RE.search(header_text)
        if match and "{" in header_text:
            kind, name, bases_text = match.groups()
            end_line = _find_block_end(lines, line_index)
            parsed_functions = _parse_functions(lines, source_path, line_index, header_end, end_line)
            state_variables = _parse_state_variables(lines, source_path, header_end + 1, end_line - 1, parsed_functions)
            modifiers = _parse_modifier_declarations(lines, header_end + 1, end_line - 1, parsed_functions)
            excerpts = _build_excerpts(source_path, parsed_functions, state_variables)
            contracts.append(
                _ParsedContract(
                    name=name,
                    kind=kind,
                    source_path=source_path,
                    start_line=line_index,
                    end_line=end_line,
                    header_end_line=header_end,
                    bases=_parse_bases(bases_text),
                    imports=imports,
                    modifiers=modifiers,
                    state_variables=state_variables,
                    functions=tuple(parsed_functions),
                    excerpts=excerpts,
                    summary=_summarize_contract(name, parsed_functions, state_variables, modifiers),
                )
            )
            line_index = end_line + 1
            continue
        line_index += 1
    return contracts


def _collect_header(lines: list[str], start_line: int) -> tuple[str, int]:
    parts: list[str] = []
    line_index = start_line
    while line_index <= len(lines):
        stripped = _strip_inline_comment(lines[line_index - 1]).strip()
        parts.append(stripped)
        if "{" in stripped or ";" in stripped:
            break
        line_index += 1
    return " ".join(part for part in parts if part), min(line_index, len(lines))


def _find_block_end(lines: list[str], start_line: int) -> int:
    depth = 0
    saw_open = False
    for line_index in range(start_line, len(lines) + 1):
        structural = _structural_line(lines[line_index - 1])
        opens = structural.count("{")
        closes = structural.count("}")
        if opens:
            saw_open = True
        depth += opens - closes
        if saw_open and depth <= 0:
            return line_index
    return len(lines)


def _parse_functions(
    lines: list[str],
    source_path: str,
    contract_start_line: int,
    contract_header_end_line: int,
    contract_end_line: int,
) -> list[_ParsedFunction]:
    functions: list[_ParsedFunction] = []
    line_index = contract_header_end_line + 1
    while line_index < contract_end_line:
        if not _strip_inline_comment(lines[line_index - 1]).strip():
            line_index += 1
            continue
        header_text, header_end = _collect_header(lines, line_index)
        function_match = _FUNCTION_RE.search(header_text) or _SPECIAL_FUNCTION_RE.search(header_text)
        if function_match and "{" in header_text and _is_top_level_statement(lines, contract_start_line, line_index):
            name = function_match.group(1)
            params = function_match.group(2)
            trailer = function_match.group(3)
            end_line = _find_block_end(lines, line_index)
            body_lines = tuple(lines[line_index - 1 : end_line])
            signature = _build_signature(name, params)
            visibility = _extract_keyword(trailer, _VISIBILITY_KEYWORDS) or "internal"
            state_mutability = _extract_keyword(trailer, _STATE_MUTABILITY_KEYWORDS) or "nonpayable"
            modifiers = _extract_modifiers(trailer)
            location = SourceLocation(source_path, line_index, end_line)
            functions.append(
                _ParsedFunction(
                    summary=FunctionSummary(
                        name=name,
                        signature=signature,
                        visibility=visibility,
                        state_mutability=state_mutability,
                        summary="",
                        modifiers=modifiers,
                        external_calls=(),
                        reads=(),
                        writes=(),
                        location=location,
                    ),
                    start_line=line_index,
                    end_line=end_line,
                    body_lines=body_lines,
                )
            )
            line_index = end_line + 1
            continue
        line_index += 1

    state_variable_names = _collect_state_variable_names(lines, contract_header_end_line + 1, contract_end_line - 1, functions)
    finalized: list[_ParsedFunction] = []
    for parsed in functions:
        body_text = "\n".join(parsed.body_lines)
        external_calls = tuple(_extract_external_calls(parsed.summary.name, body_text, source_path, parsed.start_line))
        reads, writes = _extract_state_access(state_variable_names, body_text)
        summary = _summarize_function(parsed.summary.signature, writes, external_calls, parsed.summary.modifiers)
        finalized.append(
            _ParsedFunction(
                summary=FunctionSummary(
                    name=parsed.summary.name,
                    signature=parsed.summary.signature,
                    visibility=parsed.summary.visibility,
                    state_mutability=parsed.summary.state_mutability,
                    summary=summary,
                    modifiers=parsed.summary.modifiers,
                    external_calls=external_calls,
                    reads=reads,
                    writes=writes,
                    location=parsed.summary.location,
                ),
                start_line=parsed.start_line,
                end_line=parsed.end_line,
                body_lines=parsed.body_lines,
            )
        )
    return finalized


def _parse_state_variables(
    lines: list[str],
    source_path: str,
    start_line: int,
    end_line: int,
    functions: list[_ParsedFunction],
) -> tuple[StateVariableSummary, ...]:
    if end_line < start_line:
        return ()
    blocked_lines = {line for function in functions for line in range(function.start_line, function.end_line + 1)}
    summaries: list[StateVariableSummary] = []
    statement = ""
    statement_start = start_line
    for line_index in range(start_line, end_line + 1):
        if line_index in blocked_lines:
            statement = ""
            continue
        stripped = _strip_inline_comment(lines[line_index - 1]).strip()
        if not stripped:
            continue
        if not statement:
            statement_start = line_index
        statement = f"{statement} {stripped}".strip()
        if not stripped.endswith(";"):
            continue
        lower_statement = statement.lower()
        is_mapping = statement.lstrip().startswith("mapping(")
        if not lower_statement.startswith(_STATE_DECLARATION_PREFIXES) and (is_mapping or "(" not in statement.split("=", 1)[0]):
            parsed = _parse_state_declaration(statement)
            if parsed is not None:
                type_name, visibility, name = parsed
                summaries.append(
                    StateVariableSummary(
                        name=name,
                        type_name=type_name,
                        visibility=visibility,
                        summary=_summarize_state_variable(name, type_name),
                        storage_sensitive=_is_storage_sensitive(name, type_name),
                        location=SourceLocation(source_path, statement_start, line_index),
                    )
                )
        statement = ""
    return tuple(summaries)


def _parse_modifier_declarations(
    lines: list[str],
    start_line: int,
    end_line: int,
    functions: list[_ParsedFunction],
) -> tuple[str, ...]:
    blocked_lines = {line for function in functions for line in range(function.start_line, function.end_line + 1)}
    names: list[str] = []
    for line_index in range(start_line, end_line + 1):
        if line_index in blocked_lines:
            continue
        match = _MODIFIER_DEF_RE.search(lines[line_index - 1])
        if match:
            names.append(match.group(1))
    return tuple(dict.fromkeys(names))


def _build_excerpts(
    source_path: str,
    functions: list[_ParsedFunction],
    state_variables: tuple[StateVariableSummary, ...],
) -> tuple[CodeExcerpt, ...]:
    excerpts: list[CodeExcerpt] = []
    interesting_state = [item.name for item in state_variables[:2]]
    for parsed in functions:
        if not (parsed.summary.external_calls or parsed.summary.writes):
            continue
        reason = f"{parsed.summary.name} writes {', '.join(parsed.summary.writes) or 'tracked state'}"
        if parsed.summary.external_calls:
            reason = f"{parsed.summary.name} performs external interaction before/around state updates"
        tags = tuple({tag for call in parsed.summary.external_calls for tag in call.risk_tags})
        if not tags and parsed.summary.writes:
            tags = ("state-update",)
        excerpts.append(
            CodeExcerpt(
                path=source_path,
                start_line=parsed.start_line,
                end_line=parsed.end_line,
                reason=reason,
                tags=tags,
                content="\n".join(parsed.body_lines[: min(8, len(parsed.body_lines))]),
            )
        )
    if not excerpts and interesting_state:
        excerpts.append(
            CodeExcerpt(
                path=source_path,
                start_line=state_variables[0].location.start_line if state_variables and state_variables[0].location else 1,
                end_line=state_variables[0].location.end_line if state_variables and state_variables[0].location else 1,
                reason=f"Tracked state includes {', '.join(interesting_state)}",
                tags=("state-update",),
                content="\n".join(interesting_state),
            )
        )
    return tuple(excerpts)


def _select_contract_name(
    contracts: list[_ParsedContract],
    source_path: str,
    primary_line: int | None,
) -> str:
    if primary_line is not None:
        for contract in contracts:
            if contract.start_line <= primary_line <= contract.end_line:
                return contract.name
    stem = Path(source_path).stem
    for contract in contracts:
        if contract.name == stem:
            return contract.name
    return contracts[0].name


def _select_function_name(
    contracts: list[_ParsedContract],
    contract_name: str,
    primary_line: int | None,
    finding: NormalizedFinding,
) -> str | None:
    contract = next((item for item in contracts if item.name == contract_name), None)
    if contract is None:
        return None
    if primary_line is not None:
        for function in contract.functions:
            if function.start_line <= primary_line <= function.end_line:
                return function.summary.name
    text = f"{finding.title} {finding.description}".lower()
    for function in contract.functions:
        if function.summary.name.lower() in text:
            return function.summary.name
    return contract.functions[0].summary.name if contract.functions else None


def _related_contract_names(contracts: list[_ParsedContract], focal_contract: str) -> list[str]:
    related: list[str] = []
    for contract in contracts:
        if contract.name == focal_contract:
            related.extend(base for base in contract.bases if base != focal_contract)
        elif focal_contract in contract.bases:
            related.append(contract.name)
    return list(dict.fromkeys(related))


def _attach_primary_excerpt(
    pack: StructuredContextPack,
    source_path: str,
    source_text: str,
    primary_location,
    reason: str,
) -> StructuredContextPack:
    if primary_location is None or not primary_location.lines:
        return pack
    start_line = primary_location.lines[0]
    end_line = primary_location.lines[-1]
    snippet = _slice_excerpt(source_text.splitlines(), start_line, end_line)
    excerpt = {
        "path": source_path,
        "start_line": start_line,
        "end_line": end_line,
        "reason": f"Primary deterministic analyzer location for the selected finding: {reason}",
        "tags": tuple(part for part in pack.finding_focus.get("risk_tags", ()) if isinstance(part, str)) if pack.finding_focus else (),
        "content": snippet,
    }
    existing = [item for item in pack.excerpts if not (item.get("path") == source_path and item.get("start_line") == start_line)]
    return replace(pack, excerpts=tuple([excerpt, *existing]))


def _slice_excerpt(lines: list[str], start_line: int, end_line: int) -> str:
    lower = max(1, start_line - 1)
    upper = min(len(lines), max(end_line, start_line) + 1)
    return "\n".join(lines[lower - 1 : upper])


def _is_top_level_statement(lines: list[str], contract_start_line: int, target_line: int) -> bool:
    depth = 0
    for line_index in range(contract_start_line, target_line):
        structural = _structural_line(lines[line_index - 1])
        depth += structural.count("{") - structural.count("}")
    return depth == 1


def _build_signature(name: str, params: str) -> str:
    compact_params = " ".join(part.strip() for part in params.replace("\n", " ").split())
    return f"{name}({compact_params})"


def _extract_keyword(trailer: str, keywords: set[str]) -> str | None:
    for token in _IDENTIFIER_RE.findall(trailer):
        if token in keywords:
            return token
    return None


def _extract_modifiers(trailer: str) -> tuple[str, ...]:
    trailer = re.sub(r"returns\s*\([^)]*\)", "", trailer)
    candidates = re.findall(r"[A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?", trailer)
    modifiers = [
        token
        for token in candidates
        if token not in _VISIBILITY_KEYWORDS
        and token not in _STATE_MUTABILITY_KEYWORDS
        and token not in _HEADER_IGNORED_TOKENS
    ]
    return tuple(dict.fromkeys(modifiers))


def _collect_state_variable_names(
    lines: list[str],
    start_line: int,
    end_line: int,
    functions: list[_ParsedFunction],
) -> list[str]:
    return [item.name for item in _parse_state_variables(lines, "", start_line, end_line, functions)]


def _extract_external_calls(
    function_name: str,
    body_text: str,
    source_path: str,
    start_line: int,
) -> list[ExternalCallSummary]:
    calls: list[ExternalCallSummary] = []
    for offset, raw_line in enumerate(body_text.splitlines(), start=0):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        target, call_type = _classify_external_call(stripped)
        if target is None:
            continue
        risk_tags = ["external-call"]
        if call_type in {"call", "delegatecall", "send", "transfer"} or "call{" in stripped:
            risk_tags.append("reentrancy")
        calls.append(
            ExternalCallSummary(
                target=target,
                call_type=call_type,
                expression=stripped,
                summary=f"{function_name} performs {call_type} against {target}.",
                risk_tags=tuple(risk_tags),
                location=SourceLocation(source_path, start_line + offset, start_line + offset),
            )
        )
    return calls


def _classify_external_call(line: str) -> tuple[str | None, str]:
    patterns = [
        (r"([A-Za-z_][A-Za-z0-9_\.\[\]]*)\.delegatecall\b", "delegatecall"),
        (r"([A-Za-z_][A-Za-z0-9_\.\[\]]*)\.staticcall\b", "staticcall"),
        (r"([A-Za-z_][A-Za-z0-9_\.\[\]]*)\.call\b", "call"),
        (r"([A-Za-z_][A-Za-z0-9_\.\[\]]*)\.send\b", "send"),
        (r"([A-Za-z_][A-Za-z0-9_\.\[\]]*)\.transfer\b", "transfer"),
        (r"([A-Za-z_][A-Za-z0-9_]*)\.[A-Za-z_][A-Za-z0-9_]*\s*\(", "interface"),
    ]
    for pattern, call_type in patterns:
        match = re.search(pattern, line)
        if match:
            target = match.group(1)
            if target in {"if", "require", "assert", "emit", "return", "revert"}:
                continue
            return target, call_type
    return None, "unknown"


def _extract_state_access(variable_names: list[str], body_text: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    reads: list[str] = []
    writes: list[str] = []
    for name in variable_names:
        if re.search(rf"\b{name}\b", body_text):
            reads.append(name)
        if re.search(rf"\b{name}\b\s*(?:\[[^\]]+\])?\s*(?:[+\-*/%]?=|\+\+|--)", body_text) or re.search(rf"delete\s+{name}\b", body_text):
            writes.append(name)
    return tuple(dict.fromkeys(reads)), tuple(dict.fromkeys(writes))


def _parse_state_declaration(statement: str) -> tuple[str, str, str] | None:
    before_assign = re.split(r"(?<!>)=(?!>)", statement.rstrip(";"), maxsplit=1)[0].strip()
    tokens = before_assign.split()
    if len(tokens) < 2:
        return None
    visibility = next((token for token in tokens if token in _VISIBILITY_KEYWORDS), "internal")
    filtered = [token for token in tokens if token not in _VISIBILITY_KEYWORDS and token not in {"constant", "immutable"}]
    if len(filtered) < 2:
        return None
    name = filtered[-1]
    type_name = " ".join(filtered[:-1]).strip()
    if not name or not type_name:
        return None
    return type_name, visibility, name


def _parse_bases(bases_text: str | None) -> tuple[str, ...]:
    if not bases_text:
        return ()
    names = []
    for item in bases_text.split(","):
        candidate = item.strip().split("(", 1)[0].strip()
        if candidate:
            names.append(candidate)
    return tuple(dict.fromkeys(names))


def _summarize_contract(
    contract_name: str,
    functions: list[_ParsedFunction],
    state_variables: tuple[StateVariableSummary, ...],
    modifiers: tuple[str, ...],
) -> str:
    state_names = ", ".join(item.name for item in state_variables[:3]) or "contract state"
    function_names = ", ".join(item.summary.name for item in functions[:3]) or "its public API"
    modifier_text = f" Uses modifiers such as {', '.join(modifiers[:3])}." if modifiers else ""
    return f"{contract_name} exposes functions like {function_names} and tracks {state_names}.{modifier_text}"


def _summarize_function(
    signature: str,
    writes: tuple[str, ...],
    external_calls: tuple[ExternalCallSummary, ...],
    modifiers: tuple[str, ...],
) -> str:
    summary = f"{signature}"
    if writes:
        summary += f" writes {', '.join(writes)}."
    if external_calls:
        summary += f" Performs {external_calls[0].call_type} against {external_calls[0].target}."
    if modifiers:
        summary += f" Guarded by {', '.join(modifiers)}."
    return summary.strip()


def _summarize_state_variable(name: str, type_name: str) -> str:
    return f"Tracks {name} as {type_name}."


def _is_storage_sensitive(name: str, type_name: str) -> bool:
    signal = f"{name} {type_name}".lower()
    return any(token in signal for token in ("balance", "debt", "owner", "admin", "role", "allowance", "supply", "mapping"))


def _structural_line(line: str) -> str:
    stripped = _strip_inline_comment(line)
    stripped = _STRING_RE.sub('""', stripped)
    return _CALL_OPTIONS_RE.sub(".CALL_OPTIONS", stripped)


def _strip_inline_comment(line: str) -> str:
    return line.split("//", 1)[0]