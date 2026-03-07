from __future__ import annotations

from dataclasses import asdict, dataclass, replace

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


@dataclass(frozen=True)
class ContextBudget:
    max_tokens: int = 1200
    max_imports: int = 8
    max_related_contracts: int = 6
    max_functions: int = 8
    max_state_variables: int = 8
    max_external_calls: int = 8
    max_excerpts: int = 4
    max_summary_chars: int = 220
    max_excerpt_chars: int = 420


@dataclass(frozen=True)
class FindingFocus:
    contract_name: str
    function_name: str | None = None
    reason: str = ""
    risk_tags: tuple[str, ...] = ()
    related_contracts: tuple[str, ...] = ()


@dataclass(frozen=True)
class StructuredContextPack:
    project_root: str
    framework: str
    focal_contract: str
    source_path: str
    contract_summary: str
    finding_focus: dict[str, object] | None
    imports: tuple[str, ...]
    inheritance: tuple[str, ...]
    related_contracts: tuple[dict[str, str], ...]
    function_summaries: tuple[dict[str, object], ...]
    modifier_usage: tuple[str, ...]
    risky_external_calls: tuple[dict[str, object], ...]
    storage_sensitive_state: tuple[dict[str, object], ...]
    excerpts: tuple[dict[str, object], ...]
    budget: ContextBudget
    estimated_tokens: int


class StructureAwareContextBuilder:
    def __init__(self, budget: ContextBudget | None = None) -> None:
        self._budget = budget or ContextBudget()

    def build_contract_context(
        self,
        manifest: ProjectManifest,
        inventory: SolidityStructureInventory,
        contract_name: str,
    ) -> StructuredContextPack:
        return self._build(manifest, inventory, contract_name, None)

    def build_finding_context(
        self,
        manifest: ProjectManifest,
        inventory: SolidityStructureInventory,
        focus: FindingFocus,
    ) -> StructuredContextPack:
        return self._build(manifest, inventory, focus.contract_name, focus)

    def _build(
        self,
        manifest: ProjectManifest,
        inventory: SolidityStructureInventory,
        contract_name: str,
        focus: FindingFocus | None,
    ) -> StructuredContextPack:
        index = {contract.name: contract for contract in inventory.contracts}
        contract = index[contract_name]
        functions = self._rank_functions(contract, focus)
        pack = StructuredContextPack(
            project_root=manifest.root_path,
            framework=manifest.framework,
            focal_contract=contract.name,
            source_path=contract.source_path,
            contract_summary=self._truncate(contract.summary),
            finding_focus=asdict(focus) if focus else None,
            imports=tuple(contract.imports[: self._budget.max_imports]),
            inheritance=tuple(contract.bases),
            related_contracts=tuple(
                self._related_contracts(contract, inventory, focus)[: self._budget.max_related_contracts]
            ),
            function_summaries=tuple(
                self._function_payload(function)
                for function in functions[: self._budget.max_functions]
            ),
            modifier_usage=tuple(self._modifier_usage(contract, functions)),
            risky_external_calls=tuple(
                self._external_calls(functions)[: self._budget.max_external_calls]
            ),
            storage_sensitive_state=tuple(
                self._state_variables(contract, functions)[: self._budget.max_state_variables]
            ),
            excerpts=tuple(
                self._rank_excerpts(contract, focus, functions)[: self._budget.max_excerpts]
            ),
            budget=self._budget,
            estimated_tokens=0,
        )
        return self._trim_to_budget(pack)

    def _related_contracts(
        self,
        contract: ContractSummary,
        inventory: SolidityStructureInventory,
        focus: FindingFocus | None,
    ) -> list[dict[str, str]]:
        related = [{"name": base, "relationship": "base"} for base in contract.bases]
        related.extend(
            {"name": candidate.name, "relationship": "derived"}
            for candidate in inventory.contracts
            if contract.name in candidate.bases
        )
        if focus:
            related.extend(
                {"name": name, "relationship": "finding-related"}
                for name in focus.related_contracts
                if name != contract.name
            )
        seen: set[str] = set()
        ordered: list[dict[str, str]] = []
        for item in related:
            if item["name"] in seen:
                continue
            seen.add(item["name"])
            ordered.append(item)
        return ordered

    def _rank_functions(
        self, contract: ContractSummary, focus: FindingFocus | None
    ) -> list[FunctionSummary]:
        return sorted(
            contract.functions,
            key=lambda function: (
                0 if focus and function.name == focus.function_name else 1,
                0 if function.external_calls else 1,
                0 if function.writes else 1,
                function.name,
            ),
        )

    def _function_payload(self, function: FunctionSummary) -> dict[str, object]:
        return {
            "name": function.name,
            "signature": function.signature,
            "visibility": function.visibility,
            "state_mutability": function.state_mutability,
            "summary": self._truncate(function.summary),
            "modifiers": function.modifiers,
            "reads": function.reads,
            "writes": function.writes,
            "external_call_count": len(function.external_calls),
        }

    def _modifier_usage(
        self, contract: ContractSummary, functions: list[FunctionSummary]
    ) -> list[str]:
        usage = set(contract.modifiers)
        for function in functions:
            usage.update(function.modifiers)
        return sorted(usage)

    def _external_calls(self, functions: list[FunctionSummary]) -> list[dict[str, object]]:
        calls: list[dict[str, object]] = []
        for function in functions:
            for call in function.external_calls:
                calls.append(
                    {
                        "function": function.name,
                        "summary": self._truncate(call.summary),
                        "target": call.target,
                        "call_type": call.call_type,
                        "expression": self._truncate(call.expression),
                        "risk_tags": call.risk_tags,
                    }
                )
        return calls

    def _state_variables(
        self, contract: ContractSummary, functions: list[FunctionSummary]
    ) -> list[dict[str, object]]:
        writes = {name for function in functions for name in function.writes}
        state: list[dict[str, object]] = []
        for variable in contract.state_variables:
            if variable.storage_sensitive or variable.name in writes:
                state.append(
                    {
                        "name": variable.name,
                        "type_name": variable.type_name,
                        "visibility": variable.visibility,
                        "summary": self._truncate(variable.summary),
                        "storage_sensitive": variable.storage_sensitive,
                    }
                )
        return state

    def _rank_excerpts(
        self,
        contract: ContractSummary,
        focus: FindingFocus | None,
        functions: list[FunctionSummary],
    ) -> list[dict[str, object]]:
        target_names = {function.name for function in functions[:2]}
        risk_tags = set(focus.risk_tags if focus else ())
        scored: list[tuple[int, CodeExcerpt]] = []
        for excerpt in contract.excerpts:
            score = 0
            if focus and focus.function_name and focus.function_name in excerpt.reason:
                score -= 3
            if risk_tags.intersection(excerpt.tags):
                score -= 2
            if any(name in excerpt.reason for name in target_names):
                score -= 1
            scored.append((score, excerpt))
        scored.sort(key=lambda item: (item[0], item[1].start_line, item[1].path))
        return [
            {
                "path": excerpt.path,
                "start_line": excerpt.start_line,
                "end_line": excerpt.end_line,
                "reason": self._truncate(excerpt.reason),
                "tags": excerpt.tags,
                "content": self._truncate(excerpt.content, self._budget.max_excerpt_chars),
            }
            for _, excerpt in scored
        ]

    def _trim_to_budget(self, pack: StructuredContextPack) -> StructuredContextPack:
        current = pack
        while True:
            estimated = self._estimate_tokens(current)
            if estimated <= self._budget.max_tokens:
                return replace(current, estimated_tokens=estimated)
            if len(current.excerpts) > 1:
                current = replace(current, excerpts=current.excerpts[:-1])
                continue
            if len(current.storage_sensitive_state) > 1:
                current = replace(
                    current, storage_sensitive_state=current.storage_sensitive_state[:-1]
                )
                continue
            if len(current.imports) > 1:
                current = replace(current, imports=current.imports[:-1])
                continue
            if len(current.risky_external_calls) > 1:
                current = replace(
                    current, risky_external_calls=current.risky_external_calls[:-1]
                )
                continue
            if len(current.function_summaries) > 1:
                current = replace(
                    current, function_summaries=current.function_summaries[:-1]
                )
                continue
            if len(current.related_contracts) > 1:
                current = replace(current, related_contracts=current.related_contracts[:-1])
                continue
            if current.excerpts:
                excerpt = dict(current.excerpts[0])
                trimmed_content = self._truncate(excerpt["content"], 120)
                if trimmed_content != excerpt["content"]:
                    excerpt["content"] = trimmed_content
                    current = replace(current, excerpts=(excerpt,))
                    continue
            return replace(current, estimated_tokens=estimated)

    def _estimate_tokens(self, pack: StructuredContextPack) -> int:
        parts = [
            pack.project_root,
            pack.framework,
            pack.focal_contract,
            pack.source_path,
            pack.contract_summary,
        ]
        if pack.finding_focus:
            parts.extend(
                str(value)
                for value in (
                    pack.finding_focus.get("function_name"),
                    pack.finding_focus.get("reason"),
                    pack.finding_focus.get("risk_tags"),
                )
                if value
            )
        parts.extend(pack.imports)
        parts.extend(pack.inheritance)
        parts.extend(f"{item['name']}:{item['relationship']}" for item in pack.related_contracts)
        parts.extend(
            " ".join(
                str(value)
                for value in (
                    item["name"],
                    item["signature"],
                    item["summary"],
                    item["modifiers"],
                    item["reads"],
                    item["writes"],
                )
            )
            for item in pack.function_summaries
        )
        parts.extend(
            " ".join(
                str(value)
                for value in (
                    item["function"],
                    item["summary"],
                    item["target"],
                    item["expression"],
                    item["risk_tags"],
                )
            )
            for item in pack.risky_external_calls
        )
        parts.extend(
            " ".join(str(value) for value in (item["name"], item["type_name"], item["summary"]))
            for item in pack.storage_sensitive_state
        )
        parts.extend(
            " ".join(str(value) for value in (item["path"], item["reason"], item["content"]))
            for item in pack.excerpts
        )
        return max(1, len(" ".join(parts)) // 4)

    def _truncate(self, value: str, limit: int | None = None) -> str:
        bound = limit or self._budget.max_summary_chars
        if len(value) <= bound:
            return value
        return value[: bound - 3].rstrip() + "..."