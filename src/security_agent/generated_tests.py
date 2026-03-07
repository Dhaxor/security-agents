from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Mapping

from .models import ProjectManifest
from .reports import FindingReport, build_assessment_state

GENERATED_TEST_SCHEMA_VERSION = "1.5"
SUPPORTED_EXECUTION_MODES = ("exploit", "invariant", "fuzz")


@dataclass(slots=True)
class RunnerHint:
    command: list[str]
    working_directory: str

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "RunnerHint":
        return cls(
            command=[str(item) for item in payload.get("command") or []],
            working_directory=str(payload.get("working_directory") or ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "working_directory": self.working_directory,
        }


@dataclass(slots=True)
class ValidationPlan:
    scenario: str = "generic_exploit_validation"
    objective: str = "Validate whether the selected finding can be turned into a concrete exploit under project-specific conditions."
    entry_function: str = ""
    entry_signature: str = ""
    modes: list[str] = field(default_factory=list)
    actor_roles: list[str] = field(default_factory=list)
    state_targets: list[str] = field(default_factory=list)
    call_targets: list[str] = field(default_factory=list)
    call_expressions: list[str] = field(default_factory=list)
    entry_call: dict[str, Any] = field(default_factory=dict)
    setup_calls: list[dict[str, Any]] = field(default_factory=list)
    domain_signals: list[str] = field(default_factory=list)
    sequence_variants: list[dict[str, Any]] = field(default_factory=list)
    fuzz_inputs: list[str] = field(default_factory=list)
    fuzz_assertions: list[str] = field(default_factory=list)
    differential_targets: list[str] = field(default_factory=list)
    differential_assertions: list[str] = field(default_factory=list)
    symbolic_adapters: list[dict[str, Any]] = field(default_factory=list)
    setup_steps: list[str] = field(default_factory=list)
    attack_steps: list[str] = field(default_factory=list)
    assertions: list[str] = field(default_factory=list)
    invariant_candidates: list[str] = field(default_factory=list)
    harness_notes: list[str] = field(default_factory=list)
    guidance: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    multi_transaction: bool = False
    requires_attacker_harness: bool = False
    include_invariant_candidate: bool = True

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ValidationPlan":
        return cls(
            scenario=str(payload.get("scenario") or "generic_exploit_validation"),
            objective=str(payload.get("objective") or cls().objective),
            entry_function=str(payload.get("entry_function") or ""),
            entry_signature=str(payload.get("entry_signature") or ""),
            modes=[str(item) for item in payload.get("modes") or []],
            actor_roles=[str(item) for item in payload.get("actor_roles") or []],
            state_targets=[str(item) for item in payload.get("state_targets") or []],
            call_targets=[str(item) for item in payload.get("call_targets") or []],
            call_expressions=[str(item) for item in payload.get("call_expressions") or []],
            entry_call=dict(_as_mapping(payload.get("entry_call"))),
            setup_calls=[dict(item) for item in payload.get("setup_calls") or [] if isinstance(item, Mapping)],
            domain_signals=[str(item) for item in payload.get("domain_signals") or []],
            sequence_variants=[dict(item) for item in payload.get("sequence_variants") or [] if isinstance(item, Mapping)],
            fuzz_inputs=[str(item) for item in payload.get("fuzz_inputs") or []],
            fuzz_assertions=[str(item) for item in payload.get("fuzz_assertions") or []],
            differential_targets=[str(item) for item in payload.get("differential_targets") or []],
            differential_assertions=[str(item) for item in payload.get("differential_assertions") or []],
            symbolic_adapters=[dict(item) for item in payload.get("symbolic_adapters") or [] if isinstance(item, Mapping)],
            setup_steps=[str(item) for item in payload.get("setup_steps") or []],
            attack_steps=[str(item) for item in payload.get("attack_steps") or []],
            assertions=[str(item) for item in payload.get("assertions") or []],
            invariant_candidates=[str(item) for item in payload.get("invariant_candidates") or []],
            harness_notes=[str(item) for item in payload.get("harness_notes") or []],
            guidance=[str(item) for item in payload.get("guidance") or []],
            references=[str(item) for item in payload.get("references") or []],
            multi_transaction=bool(payload.get("multi_transaction")),
            requires_attacker_harness=bool(payload.get("requires_attacker_harness")),
            include_invariant_candidate=payload.get("include_invariant_candidate") is not False,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "objective": self.objective,
            "entry_function": self.entry_function,
            "entry_signature": self.entry_signature,
            "modes": self.modes,
            "actor_roles": self.actor_roles,
            "state_targets": self.state_targets,
            "call_targets": self.call_targets,
            "call_expressions": self.call_expressions,
            "entry_call": self.entry_call,
            "setup_calls": self.setup_calls,
            "domain_signals": self.domain_signals,
            "sequence_variants": self.sequence_variants,
            "fuzz_inputs": self.fuzz_inputs,
            "fuzz_assertions": self.fuzz_assertions,
            "differential_targets": self.differential_targets,
            "differential_assertions": self.differential_assertions,
            "symbolic_adapters": self.symbolic_adapters,
            "setup_steps": self.setup_steps,
            "attack_steps": self.attack_steps,
            "assertions": self.assertions,
            "invariant_candidates": self.invariant_candidates,
            "harness_notes": self.harness_notes,
            "guidance": self.guidance,
            "references": self.references,
            "multi_transaction": self.multi_transaction,
            "requires_attacker_harness": self.requires_attacker_harness,
            "include_invariant_candidate": self.include_invariant_candidate,
        }


@dataclass(slots=True)
class ExecutionResult:
    state: str
    summary: str
    command: list[str]
    working_directory: str
    return_code: int | None
    result_path: str
    stdout_path: str
    stderr_path: str
    environment_limitation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "state": self.state,
            "summary": self.summary,
            "command": self.command,
            "working_directory": self.working_directory,
            "return_code": self.return_code,
            "result_path": self.result_path,
            "stdout_path": self.stdout_path,
            "stderr_path": self.stderr_path,
        }
        if self.environment_limitation:
            payload["environment_limitation"] = self.environment_limitation
        return payload


@dataclass(slots=True)
class GeneratedTestArtifact:
    artifact_id: str
    framework: str
    language: str
    strategy: str
    output_directory: str
    test_path: str
    report_path: str
    metadata_path: str
    runner_hint: RunnerHint
    provenance: dict[str, Any]
    selected_mode: str = "exploit"
    validation_plan: ValidationPlan = field(default_factory=ValidationPlan)
    execution: ExecutionResult | None = None
    schema_version: str = GENERATED_TEST_SCHEMA_VERSION

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "GeneratedTestArtifact":
        execution_payload = payload.get("execution")
        execution = None
        if isinstance(execution_payload, Mapping):
            execution = ExecutionResult(
                state=str(execution_payload.get("state") or "inconclusive"),
                summary=str(execution_payload.get("summary") or ""),
                command=[str(item) for item in execution_payload.get("command") or []],
                working_directory=str(execution_payload.get("working_directory") or ""),
                return_code=execution_payload.get("return_code") if isinstance(execution_payload.get("return_code"), int) else None,
                result_path=str(execution_payload.get("result_path") or ""),
                stdout_path=str(execution_payload.get("stdout_path") or ""),
                stderr_path=str(execution_payload.get("stderr_path") or ""),
                environment_limitation=str(execution_payload.get("environment_limitation")) if execution_payload.get("environment_limitation") else None,
            )
        return cls(
            artifact_id=str(payload.get("artifact_id") or "candidate"),
            framework=str(payload.get("framework") or "unknown"),
            language=str(payload.get("language") or "unknown"),
            strategy=str(payload.get("strategy") or "exploit_validation_candidate"),
            output_directory=str(payload.get("output_directory") or ""),
            test_path=str(payload.get("test_path") or ""),
            report_path=str(payload.get("report_path") or ""),
            metadata_path=str(payload.get("metadata_path") or ""),
            runner_hint=RunnerHint.from_dict(_as_mapping(payload.get("runner_hint"))),
            provenance=dict(_as_mapping(payload.get("provenance"))),
            selected_mode=str(payload.get("selected_mode") or "exploit"),
            validation_plan=ValidationPlan.from_dict(_as_mapping(payload.get("validation_plan"))),
            execution=execution,
            schema_version=str(payload.get("schema_version") or GENERATED_TEST_SCHEMA_VERSION),
        )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": self.schema_version,
            "artifact_id": self.artifact_id,
            "framework": self.framework,
            "language": self.language,
            "strategy": self.strategy,
            "output_directory": self.output_directory,
            "test_path": self.test_path,
            "report_path": self.report_path,
            "metadata_path": self.metadata_path,
            "runner_hint": self.runner_hint.to_dict(),
            "provenance": self.provenance,
            "selected_mode": self.selected_mode,
            "validation_plan": self.validation_plan.to_dict(),
        }
        if self.execution is not None:
            payload["execution"] = self.execution.to_dict()
        return payload


def generate_candidate_test(
    manifest: ProjectManifest,
    report: FindingReport | Mapping[str, Any],
    *,
    output_dir: str | Path,
    selected_mode: str = "exploit",
    retrieval: Mapping[str, Any] | None = None,
) -> GeneratedTestArtifact:
    report_payload = report.to_dict() if isinstance(report, FindingReport) else dict(report)
    root = Path(manifest.root_path)
    resolved_output_dir = Path(output_dir)
    if not resolved_output_dir.is_absolute():
        resolved_output_dir = (root / resolved_output_dir).resolve()

    artifact_slug = _slug(report_payload.get("finding_id") or report_payload.get("title") or "candidate")
    validation_plan = _build_validation_plan(report_payload, retrieval)
    normalized_mode = _normalize_selected_mode(selected_mode, validation_plan)
    artifact_dir = resolved_output_dir / manifest.framework / artifact_slug / normalized_mode
    artifact_dir.mkdir(parents=True, exist_ok=True)

    test_filename = _build_test_filename(manifest.framework, report_payload)
    test_path = artifact_dir / test_filename
    report_path = artifact_dir / "report.json"
    metadata_path = artifact_dir / "generated-test.json"

    report_path.write_text(json.dumps(report_payload, indent=2, sort_keys=True), encoding="utf-8")
    test_path.write_text(
        _render_candidate_test(
            framework=manifest.framework,
            report=report_payload,
            report_path=_display_path(root, report_path),
            validation_plan=validation_plan,
        ),
        encoding="utf-8",
    )

    artifact = GeneratedTestArtifact(
        artifact_id=f"{artifact_slug}:{manifest.framework}:{normalized_mode}",
        framework=manifest.framework,
        language="solidity" if manifest.framework == "foundry" else "javascript",
        strategy=_select_strategy(report_payload),
        output_directory=_display_path(root, artifact_dir),
        test_path=_display_path(root, test_path),
        report_path=_display_path(root, report_path),
        metadata_path=_display_path(root, metadata_path),
        runner_hint=_build_runner_hint(manifest.framework, root, test_path, report_payload, validation_plan, normalized_mode),
        provenance=_build_provenance(report_payload, _display_path(root, report_path), retrieval),
        selected_mode=normalized_mode,
        validation_plan=validation_plan,
    )
    metadata_path.write_text(json.dumps(artifact.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return artifact


def execute_generated_test(
    artifact: GeneratedTestArtifact | Mapping[str, Any],
    *,
    report: FindingReport | Mapping[str, Any] | None = None,
) -> tuple[GeneratedTestArtifact, dict[str, Any]]:
    artifact_model = artifact if isinstance(artifact, GeneratedTestArtifact) else GeneratedTestArtifact.from_dict(artifact)
    root = Path(artifact_model.runner_hint.working_directory).resolve()
    artifact_dir = _resolve_path(root, artifact_model.output_directory)
    report_path = _resolve_path(root, artifact_model.report_path)
    metadata_path = _resolve_path(root, artifact_model.metadata_path)
    stdout_path = artifact_dir / "runner.stdout.log"
    stderr_path = artifact_dir / "runner.stderr.log"
    result_path = artifact_dir / "execution-result.json"

    stdout = ""
    stderr = ""
    return_code: int | None = None
    environment_limitation: str | None = None
    try:
        completed = subprocess.run(
            artifact_model.runner_hint.command,
            cwd=artifact_model.runner_hint.working_directory,
            capture_output=True,
            text=True,
            check=False,
        )
        stdout = completed.stdout
        stderr = completed.stderr
        return_code = completed.returncode
        state, summary = _classify_execution(
            artifact_model.framework,
            artifact_model.selected_mode,
            completed.returncode,
            completed.stdout,
            completed.stderr,
        )
    except FileNotFoundError as exc:
        environment_limitation = str(exc)
        stderr = str(exc)
        state = "inconclusive"
        summary = f"{artifact_model.framework.title()} runner is unavailable in this environment; validation could not be executed."

    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")

    execution = ExecutionResult(
        state=state,
        summary=summary,
        command=list(artifact_model.runner_hint.command),
        working_directory=artifact_model.runner_hint.working_directory,
        return_code=return_code,
        result_path=_display_path(root, result_path),
        stdout_path=_display_path(root, stdout_path),
        stderr_path=_display_path(root, stderr_path),
        environment_limitation=environment_limitation,
    )
    result_path.write_text(json.dumps(execution.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    report_payload = _load_report_payload(report, report_path)
    report_payload["validation"] = _build_validation_payload(artifact_model, execution)
    report_payload["assessment"] = build_assessment_state(
        report_payload.get("provider_reasoning"),
        report_payload["validation"],
    ).to_dict()
    report_path.write_text(json.dumps(report_payload, indent=2, sort_keys=True), encoding="utf-8")

    artifact_model.execution = execution
    metadata_path.write_text(json.dumps(artifact_model.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return artifact_model, report_payload


def _build_runner_hint(
    framework: str,
    root: Path,
    test_path: Path,
    report: Mapping[str, Any],
    validation_plan: ValidationPlan,
    selected_mode: str,
) -> RunnerHint:
    relative_test_path = _display_path(root, test_path)
    selector = _build_execution_selector(framework, report, validation_plan, selected_mode)
    if framework == "foundry":
        command = ["forge", "test", "--match-path", relative_test_path, "--match-test", selector]
    else:
        command = ["npx", "hardhat", "test", relative_test_path, "--grep", selector]
    return RunnerHint(command=command, working_directory=str(root))


def _build_provenance(
    report: Mapping[str, Any],
    report_path: str,
    retrieval: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    provider_reasoning = _as_mapping(report.get("provider_reasoning"))
    deterministic_evidence = _as_mapping(report.get("deterministic_evidence"))
    validation = _as_mapping(report.get("validation"))
    assessment = _as_mapping(report.get("assessment"))
    hypotheses = provider_reasoning.get("exploit_hypotheses") or []
    provenance = {
        "report_path": report_path,
        "report_schema_version": report.get("schema_version"),
        "finding_id": report.get("finding_id"),
        "assessment_verdict": assessment.get("verdict"),
        "finding_reference": dict(_as_mapping(provider_reasoning.get("finding_reference"))),
        "deterministic_evidence": {
            "source": deterministic_evidence.get("source"),
            "rule_id": deterministic_evidence.get("rule_id"),
            "locations": list(deterministic_evidence.get("locations") or []),
        },
        "provider_reasoning": {
            "summary": provider_reasoning.get("summary"),
            "evidence_references": list(provider_reasoning.get("evidence_references") or []),
            "hypothesis_titles": [
                str(item.get("title"))
                for item in hypotheses
                if isinstance(item, Mapping) and str(item.get("title") or "").strip()
            ],
        },
        "validation_state": validation.get("state"),
    }
    retrieval_payload = _as_mapping(retrieval)
    retrieval_matches = retrieval_payload.get("matches") or []
    if retrieval_matches:
        provenance["retrieval"] = {
            "kind": retrieval_payload.get("kind"),
            "store": retrieval_payload.get("store"),
            "matches": [
                {
                    "pattern_id": item.get("pattern_id"),
                    "source": item.get("source"),
                    "summary": item.get("summary"),
                }
                for item in retrieval_matches
                if isinstance(item, Mapping)
            ],
        }
    return provenance


def _render_candidate_test(*, framework: str, report: Mapping[str, Any], report_path: str, validation_plan: ValidationPlan) -> str:
    if framework == "foundry":
        return _render_foundry_candidate(report, report_path, validation_plan)
    return _render_hardhat_candidate(report, report_path, validation_plan)


def _render_foundry_candidate(report: Mapping[str, Any], report_path: str, validation_plan: ValidationPlan) -> str:
    label = _pascal_case(report.get("title") or report.get("finding_id") or "Generated")
    contract_name = f"{label}CandidateTest"
    attack_test_name = _build_execution_selector("foundry", report, validation_plan, "exploit")
    invariant_test_name = _build_execution_selector("foundry", report, validation_plan, "invariant")
    fuzz_test_name = _build_execution_selector("foundry", report, validation_plan, "fuzz")
    focal_contract = _as_mapping(report.get("structure_context")).get("focal_contract") or "UnknownContract"
    lines = [
        "// SPDX-License-Identifier: MIT",
        "pragma solidity ^0.8.13;",
        "",
    ]
    if validation_plan.requires_attacker_harness:
        lines.extend(_render_foundry_attacker_harness(label, validation_plan))
        lines.append("")
    lines.extend(
        [
            f"contract {contract_name} {{",
            f"    function {attack_test_name}() public {{",
            f"        // report_path: {report_path}",
            f"        // finding_id: {report.get('finding_id', 'unknown')}",
            f"        // focal_contract: {focal_contract}",
            f"        // rule_id: {_rule_id(report)}",
            f"        // hypothesis: {_primary_hypothesis(report)}",
            f"        // evidence: {_primary_evidence_reference(report)}",
            f"        // objective: {validation_plan.objective}",
            f"        // entrypoint: {validation_plan.entry_signature or validation_plan.entry_function or 'unknown'}",
            f"        // modes: {', '.join(validation_plan.modes) if validation_plan.modes else 'exploit'}",
            "        // setup plan:",
        ]
    )
    if validation_plan.actor_roles:
        lines.append(f"        // actors: {', '.join(validation_plan.actor_roles)}")
    if validation_plan.domain_signals:
        lines.append(f"        // domain signals: {', '.join(validation_plan.domain_signals)}")
    if validation_plan.setup_calls:
        lines.append("        // suggested setup calls:")
        lines.extend(_render_solidity_call_hints(validation_plan.setup_calls, indent="        //   "))
    if validation_plan.entry_call:
        lines.append("        // suggested entry call:")
        lines.extend(_render_solidity_call_hints([validation_plan.entry_call], indent="        //   "))
    lines.extend(_render_solidity_comment_block(validation_plan.setup_steps, indent="        //   ", fallback="Adapt setup to the target project."))
    lines.append("        // attack sequence:")
    lines.extend(_render_solidity_comment_block(validation_plan.attack_steps, indent="        //   ", fallback="Drive the focal entrypoint with attacker-controlled inputs."))
    if validation_plan.sequence_variants:
        lines.append("        // sequence variants:")
        lines.extend(_render_solidity_sequence_variants(validation_plan.sequence_variants, indent="        //   "))
    lines.append("        // assertions:")
    lines.extend(_render_solidity_comment_block(validation_plan.assertions, indent="        //   ", fallback="Assert attacker gain, state drift, or unauthorized success."))
    if validation_plan.harness_notes:
        lines.append("        // attacker harness notes:")
        lines.extend(_render_solidity_comment_block(validation_plan.harness_notes, indent="        //   "))
    if validation_plan.guidance:
        lines.append("        // extra guidance:")
        lines.extend(_render_solidity_comment_block(validation_plan.guidance, indent="        //   "))
    lines.extend(_render_foundry_call_preparation(validation_plan, include_fuzz_bindings=False))
    lines.extend(
        [
            "        // TODO: Deploy the focal contract and wire the scenario-specific actors or mocks.",
            "        // TODO: Translate the steps above into concrete calls and assertions for this repository.",
            "    }",
        ]
    )
    lines.extend(_render_foundry_candidate_helpers(validation_plan))
    if validation_plan.include_invariant_candidate:
        lines.extend(
            [
                "",
                f"    function {invariant_test_name}() public {{",
                *_render_foundry_call_preparation(validation_plan, include_fuzz_bindings=False),
                "        bytes32[] memory invariantHashes = _candidateInvariantHashes();",
                '        require(invariantHashes.length > 0, "expected invariant candidates");',
                "        // invariant candidates:",
            ]
        )
        lines.extend(
            _render_solidity_comment_block(
                validation_plan.invariant_candidates,
                indent="        //   ",
                fallback="Assert the protected state still matches the expected accounting or authorization invariant.",
            )
        )
        lines.extend(
            [
                "        // TODO: Convert one invariant candidate into a reusable helper or fuzzable assertion.",
                "    }",
            ]
        )
    if "fuzz" in validation_plan.modes:
        lines.extend(
            [
                "",
                f"    function {fuzz_test_name}(uint256 amount, address actor) public {{",
                "        uint256 boundedAmount = _boundCandidateAmount(amount);",
                "        address normalizedActor = _normalizeCandidateActor(actor);",
                *_render_foundry_call_preparation(validation_plan, include_fuzz_bindings=True),
                "        bytes32[] memory invariantHashes = _candidateInvariantHashes();",
                '        require(boundedAmount > 0, "expected bounded fuzz amount");',
                '        require(normalizedActor != address(0), "expected fuzz actor");',
                '        require(invariantHashes.length > 0, "expected invariant candidates");',
                "        // fuzz inputs:",
            ]
        )
        lines.extend(_render_solidity_comment_block(validation_plan.fuzz_inputs, indent="        //   ", fallback="Bound attacker-controlled inputs before invoking the target path."))
        lines.append("        // fuzz assertions:")
        lines.extend(_render_solidity_comment_block(validation_plan.fuzz_assertions, indent="        //   ", fallback="Assert the security property still holds across bounded inputs."))
        lines.extend(
            [
                "        // TODO: Replace the placeholder comments above with target-specific calls that use boundedAmount and normalizedActor.",
                "    }",
            ]
        )
    if validation_plan.differential_targets:
        lines.extend(
            [
                "",
                f"    function testDifferentialCandidate{label}() public {{",
                f"        // reference targets: {', '.join(validation_plan.differential_targets)}",
                "        // differential assertions:",
            ]
        )
        lines.extend(_render_solidity_comment_block(validation_plan.differential_assertions, indent="        //   ", fallback="Compare focal behavior against the reference implementation for the same sequence."))
        lines.extend(
            [
                "        // TODO: Deploy the focal contract and reference target side-by-side, then compare post-state and revert behavior.",
                "    }",
            ]
        )
    if validation_plan.symbolic_adapters:
        lines.extend(
            [
                "",
                "    function testSymbolicAdapterHints() public {",
                "        // optional symbolic adapters:",
            ]
        )
        lines.extend(_render_solidity_tool_adapters(validation_plan.symbolic_adapters, indent="        //   "))
        lines.extend(
            [
                "        // TODO: Use an available symbolic engine to explore the candidate path more exhaustively.",
                "    }",
            ]
        )
    lines.extend(["}", ""])
    return "\n".join(lines)


def _render_hardhat_candidate(report: Mapping[str, Any], report_path: str, validation_plan: ValidationPlan) -> str:
    title = str(report.get("title") or report.get("finding_id") or "Generated candidate")
    exploit_title = _build_execution_selector("hardhat", report, validation_plan, "exploit")
    invariant_title = _build_execution_selector("hardhat", report, validation_plan, "invariant")
    fuzz_title = _build_execution_selector("hardhat", report, validation_plan, "fuzz")
    lines = [
        'const assert = require("assert").strict;',
        "",
        f"const validationPlan = {json.dumps(validation_plan.to_dict(), indent=2)};",
        f"const sequenceVariants = {json.dumps(validation_plan.sequence_variants, indent=2)};",
        'const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";',
        'const DEFAULT_ACTOR = "0x000000000000000000000000000000000000bEEF";',
        "",
        "function normalizeFuzzAmount(rawAmount) {",
        '  const candidate = typeof rawAmount === "bigint" ? rawAmount : BigInt(rawAmount);',
        "  if (candidate <= 0n) {",
        "    return 1n;",
        "  }",
        "  const upperBound = (1n << 96n) - 1n;",
        "  return candidate > upperBound ? upperBound : candidate;",
        "}",
        "",
        "function normalizeCandidateActor(rawActor) {",
        '  if (typeof rawActor === "string" && /^0x[0-9a-fA-F]{40}$/.test(rawActor) && rawActor !== ZERO_ADDRESS) {',
        "    return rawActor;",
        "  }",
        "  return DEFAULT_ACTOR;",
        "}",
        "",
        "function candidateInvariantChecks() {",
        "  const candidates = Array.isArray(validationPlan.invariant_candidates) ? validationPlan.invariant_candidates : [];",
        "  return candidates.map((name, index) => ({ index, name, tag: `candidate-invariant-${index + 1}` }));",
        "}",
        "",
        "function buildCandidateFuzzSeeds() {",
        "  const roles = Array.isArray(validationPlan.actor_roles) && validationPlan.actor_roles.length ? validationPlan.actor_roles : [\"attacker\"];",
        "  return roles.map((role, index) => ({",
        "    role,",
        "    amount: normalizeFuzzAmount(BigInt(index + 1)),",
        "    actor: normalizeCandidateActor(undefined),",
        "  }));",
        "}",
        "",
        *_render_javascript_call_helpers(validation_plan),
        "",
        "async function runExploitSequence(context) {",
        "  // setup plan:",
    ]
    lines.extend(_render_javascript_comment_block(validation_plan.setup_steps, indent="  //   ", fallback="Adapt deployment and actor setup to the project fixtures."))
    lines.append("  // attack sequence:")
    lines.extend(_render_javascript_comment_block(validation_plan.attack_steps, indent="  //   ", fallback="Trigger the focal entrypoint and any required follow-up transactions."))
    if validation_plan.harness_notes:
        lines.append("  // attacker harness notes:")
        lines.extend(_render_javascript_comment_block(validation_plan.harness_notes, indent="  //   "))
    lines.extend(["  return context;", "}", "", f'describe({json.dumps(title + " [candidate]")}, function () {{'])
    lines.extend(
        [
            f"  it({json.dumps(exploit_title)}, async function () {{",
            f"    // report_path: {report_path}",
            f"    // finding_id: {report.get('finding_id', 'unknown')}",
            f"    // rule_id: {_rule_id(report)}",
            f"    // hypothesis: {_primary_hypothesis(report)}",
            f"    // evidence: {_primary_evidence_reference(report)}",
            f"    // objective: {validation_plan.objective}",
            f"    // entrypoint: {validation_plan.entry_signature or validation_plan.entry_function or 'unknown'}",
            "    const context = {};",
            "    const setupCalls = buildCandidateSetupCalls();",
            "    const entryCall = buildCandidateEntryCall();",
            "    await runExploitSequence(context);",
            "    // assertions:",
        ]
    )
    if validation_plan.actor_roles:
        lines.append(f"    // actors: {', '.join(validation_plan.actor_roles)}")
    if validation_plan.domain_signals:
        lines.append(f"    // domain signals: {', '.join(validation_plan.domain_signals)}")
    if validation_plan.setup_calls:
        lines.append("    // suggested setup calls:")
        lines.extend(_render_javascript_call_hints(validation_plan.setup_calls, indent="    //   "))
    if validation_plan.entry_call:
        lines.append("    // suggested entry call:")
        lines.extend(_render_javascript_call_hints([validation_plan.entry_call], indent="    //   "))
    lines.extend(_render_javascript_comment_block(validation_plan.assertions, indent="    //   ", fallback="Assert a security-relevant post-state difference or unexpected success path."))
    if validation_plan.guidance:
        lines.append("    // extra guidance:")
        lines.extend(_render_javascript_comment_block(validation_plan.guidance, indent="    //   "))
    lines.extend(
        [
                '    assert.ok(entryCall.signature.length >= 3, "Expected a concrete entry-call signature.");',
                "    assert.ok(Array.isArray(entryCall.args), \"Expected entry-call args.\");",
                '    assert.ok(Array.isArray(setupCalls), "Expected setup call hints.");',
            '    assert.ok(true, "Replace placeholder assertion after adapting this candidate to the target project.");',
            "  });",
        ]
    )
    if validation_plan.include_invariant_candidate:
        lines.extend(
            [
                "",
                f"  it({json.dumps(invariant_title)}, async function () {{",
                "    const invariantChecks = candidateInvariantChecks();",
                "    const entryCall = buildCandidateEntryCall();",
                '    assert.ok(invariantChecks.length >= 1, "Expected at least one invariant candidate.");',
                "    // invariant candidates:",
            ]
        )
        lines.extend(
            _render_javascript_comment_block(
                validation_plan.invariant_candidates,
                indent="    //   ",
                fallback="Assert that balances, permissions, or supply stay within expected bounds.",
            )
        )
        lines.extend(
            [
                "    for (const check of invariantChecks) {",
                '      assert.ok(check.name.length > 0, "Invariant candidate names should be non-empty.");',
                '      assert.ok(entryCall.signature.length >= 3, "Expected a concrete invariant entry-call signature.");',
                "    }",
                '    assert.ok(true, "Replace placeholder invariant assertion after adapting this candidate.");',
                "  });",
            ]
        )
    if "fuzz" in validation_plan.modes:
        lines.extend(
            [
                "",
                f"  it({json.dumps(fuzz_title)}, async function () {{",
                "    const fuzzSeeds = buildCandidateFuzzSeeds();",
                "    const entryCall = buildCandidateEntryCall({ amount: 1n, actor: DEFAULT_ACTOR });",
                '    assert.ok(fuzzSeeds.length >= 1, "Expected at least one fuzz seed.");',
                "    // fuzz inputs:",
            ]
        )
        lines.extend(_render_javascript_comment_block(validation_plan.fuzz_inputs, indent="    //   ", fallback="Create bounded numeric/address seeds for the candidate path."))
        lines.append("    // fuzz assertions:")
        lines.extend(_render_javascript_comment_block(validation_plan.fuzz_assertions, indent="    //   ", fallback="Assert the core security property across the chosen seeds."))
        lines.extend(
            [
                "    for (const seed of fuzzSeeds) {",
                "      const seededEntryCall = buildCandidateEntryCall({ amount: seed.amount, actor: seed.actor });",
                '      assert.ok(seed.amount > 0n, "Fuzz amount should be bounded above zero.");',
                '      assert.notEqual(seed.actor, ZERO_ADDRESS, "Fuzz actor should be normalized away from the zero address.");',
                '      assert.ok(seededEntryCall.signature.length >= 3, "Expected fuzz entry-call hints.");',
                "    }",
                '    assert.ok(entryCall.signature.length >= 3, "Expected a concrete fuzz entry-call signature.");',
                '    assert.ok(true, "Replace placeholder fuzz assertions after adapting this candidate.");',
                "  });",
            ]
        )
    if validation_plan.sequence_variants:
        lines.extend(
            [
                "",
                '  it("covers candidate multi-transaction sequence variants", async function () {',
                "    // sequence variants:",
            ]
        )
        lines.extend(_render_javascript_sequence_variants(validation_plan.sequence_variants, indent="    //   "))
        lines.extend(
            [
                '    assert.ok(sequenceVariants.length >= 1, "Expected at least one candidate sequence variant.");',
                "  });",
            ]
        )
    if validation_plan.differential_targets:
        lines.extend(
            [
                "",
                '  it("describes a differential comparison candidate", async function () {',
                f"    // reference targets: {', '.join(validation_plan.differential_targets)}",
                "    // differential assertions:",
            ]
        )
        lines.extend(_render_javascript_comment_block(validation_plan.differential_assertions, indent="    //   ", fallback="Compare the focal contract against a reference implementation."))
        lines.extend(
            [
                '    assert.ok(true, "Replace placeholder differential assertions after adapting this candidate.");',
                "  });",
            ]
        )
    if validation_plan.symbolic_adapters:
        lines.extend(
            [
                "",
                '  it("records optional symbolic adapter hints", async function () {',
                "    // optional symbolic adapters:",
            ]
        )
        lines.extend(_render_javascript_tool_adapters(validation_plan.symbolic_adapters, indent="    //   "))
        lines.extend(
            [
                '    assert.ok(true, "Symbolic adapter hints are metadata-only until a tool is installed.");',
                "  });",
            ]
        )
    lines.extend(["});", ""])
    return "\n".join(lines)


def _render_foundry_attacker_harness(label: str, validation_plan: ValidationPlan) -> list[str]:
    harness_name = f"{label}AttackerHarness"
    entry_signature = validation_plan.entry_signature or validation_plan.entry_function or "the focal entrypoint"
    lines = [
        f"contract {harness_name} {{",
        "    address public target;",
        "    bool internal callbackTriggered;",
        "",
        "    function configure(address target_) external {",
        "        target = target_;",
        "    }",
        "",
        "    function attack() external payable {",
        f"        // TODO: Seed the target with any required balances and trigger {entry_signature} once.",
        "    }",
        "",
        "    receive() external payable {",
        "        if (callbackTriggered) {",
        "            return;",
        "        }",
        "        callbackTriggered = true;",
        f"        // TODO: Reenter {entry_signature} before the first call restores the expected invariant.",
    ]
    if validation_plan.harness_notes:
        lines.extend(_render_solidity_comment_block(validation_plan.harness_notes, indent="        //   "))
    lines.extend(["    }", "}"])
    return lines


def _build_validation_plan(report: Mapping[str, Any], retrieval: Mapping[str, Any] | None = None) -> ValidationPlan:
    rule_id = _rule_id(report)
    if "reentrancy" in rule_id:
        plan = _build_reentrancy_plan(report, retrieval)
    elif _contains_any(rule_id, ("access", "authorization", "owner", "role")):
        plan = _build_access_control_plan(report, retrieval)
    elif _contains_any(rule_id, ("unchecked", "return", "call")):
        plan = _build_unchecked_call_plan(report, retrieval)
    else:
        plan = _build_generic_plan(report, retrieval)
    return _decorate_validation_plan(report, plan)


def _build_reentrancy_plan(report: Mapping[str, Any], retrieval: Mapping[str, Any] | None) -> ValidationPlan:
    focal_contract, function_name, hypothesis, preconditions, impact = _plan_inputs(report)
    entry_signature = _entry_signature(report) or function_name
    storage_targets = _storage_targets(report)
    risky_targets = _risky_call_targets(report)
    call_expressions = _call_expressions(report)
    seed_signature = _supporting_function_signature(report, ("deposit", "mint", "fund", "credit", "stake"))
    actor_roles = _actor_roles(report, "reentrancy")
    setup_steps = [
        f"Deploy {focal_contract} and an attacker-controlled receiver with a callback hook.",
        (
            f"Use {seed_signature} from the attacker to seed the vulnerable path before invoking {entry_signature}."
            if seed_signature
            else f"Seed the prerequisite state so {entry_signature} can move value or tokens on behalf of the attacker."
        ),
        f"Capture pre-state for {', '.join(storage_targets) if storage_targets else 'balances, debt, and asset holdings'} before calling {entry_signature}.",
    ]
    setup_steps.extend(preconditions)
    attack_steps = [
        f"Invoke {entry_signature} from the attacker-controlled account to reach the callback-capable interaction{_target_suffix(risky_targets)}.",
        (
            f"Expect the suspicious external interaction `{call_expressions[0]}` to occur before finalizing {', '.join(storage_targets)}."
            if call_expressions and storage_targets
            else "Expect the suspicious external interaction to occur before final state reconciliation."
        ),
        f"From the callback, call back into {entry_signature} or a state-dependent helper before the original frame restores accounting.",
        "Bound the callback loop so the candidate demonstrates at least one unexpected second execution without hanging the runner.",
    ]
    attack_steps.extend(_retrieval_candidate_test_ideas(retrieval))
    assertions = [
        f"Assert that the attacker receives value, permissions, or state transitions more than once for a single {entry_signature} path.",
        f"Assert that {', '.join(storage_targets) if storage_targets else 'tracked balances or debt'} no longer reconcile with the expected post-{function_name} state.",
    ]
    if impact:
        assertions.append(f"Check whether the observed impact matches the hypothesis: {impact}")
    invariant_candidates = [
        f"{focal_contract} should not allow callback-driven reentry to observe stale authorization or accounting state.",
        f"After {entry_signature} returns, assets moved to the attacker should still reconcile with the final recorded balance/debt state.",
    ]
    harness_notes = [
        "Use a boolean guard in receive/fallback so the harness reenters exactly once unless the target requires a deeper sequence.",
        f"Expose a helper that triggers {entry_signature} and records whether the callback was able to reenter successfully.",
    ]
    return ValidationPlan(
        scenario="multi_transaction_reentrancy",
        objective=f"Validate whether {hypothesis} can be reproduced through a callback-driven multi-transaction path.",
        entry_function=function_name,
        entry_signature=entry_signature,
        actor_roles=actor_roles,
        state_targets=storage_targets,
        call_targets=risky_targets,
        call_expressions=call_expressions,
        setup_steps=_dedupe_preserve_order(setup_steps),
        attack_steps=_dedupe_preserve_order(attack_steps),
        assertions=_dedupe_preserve_order(assertions),
        invariant_candidates=_dedupe_preserve_order(invariant_candidates),
        harness_notes=_dedupe_preserve_order(harness_notes),
        guidance=_dedupe_preserve_order(_retrieval_guidance(retrieval)),
        references=_dedupe_preserve_order([_primary_evidence_reference(report), *_retrieval_references(retrieval)]),
        multi_transaction=True,
        requires_attacker_harness=True,
    )


def _build_access_control_plan(report: Mapping[str, Any], retrieval: Mapping[str, Any] | None) -> ValidationPlan:
    focal_contract, function_name, hypothesis, preconditions, impact = _plan_inputs(report)
    entry_signature = _entry_signature(report) or function_name
    actor_roles = _actor_roles(report, "access")
    modifier_hint = _guard_hint(report)
    storage_targets = _storage_targets(report)
    setup_steps = [
        f"Deploy {focal_contract} with a known privileged account and at least one untrusted account.",
        f"Record the protected state that {entry_signature} is expected to guard.",
        (f"Document the intended guard before the call: {modifier_hint}." if modifier_hint else "Document the intended ownership or role guard before the call."),
    ]
    setup_steps.extend(preconditions)
    attack_steps = [
        f"Call {entry_signature} from the untrusted account without satisfying the intended ownership or role checks.",
        "If the first call succeeds, attempt a follow-up state transition that should only be reachable after privileged execution.",
    ]
    attack_steps.extend(_retrieval_candidate_test_ideas(retrieval))
    assertions = [
        f"Assert that the unauthorized caller can reach a privileged state change, fund movement, or configuration update via {entry_signature}.",
        "Assert that the call path either avoids an expected revert or grants a durable privilege it should not grant.",
    ]
    if storage_targets:
        assertions.append(f"Check whether protected state changed unexpectedly: {', '.join(storage_targets)}")
    if impact:
        assertions.append(f"Check whether the resulting state change matches the hypothesized impact: {impact}")
    invariant_candidates = [
        "Only explicitly privileged roles should be able to mutate the protected configuration or administrative state.",
        "Unauthorized callers should not gain ownership, role membership, or access to privileged execution paths.",
    ]
    return ValidationPlan(
        scenario="unauthorized_access_validation",
        objective=f"Validate whether {hypothesis} can be reproduced by an unauthorized caller.",
        entry_function=function_name,
        entry_signature=entry_signature,
        actor_roles=actor_roles,
        state_targets=storage_targets,
        setup_steps=_dedupe_preserve_order(setup_steps),
        attack_steps=_dedupe_preserve_order(attack_steps),
        assertions=_dedupe_preserve_order(assertions),
        invariant_candidates=_dedupe_preserve_order(invariant_candidates),
        guidance=_dedupe_preserve_order(_retrieval_guidance(retrieval)),
        references=_dedupe_preserve_order([_primary_evidence_reference(report), *_retrieval_references(retrieval)]),
        multi_transaction=True,
    )


def _build_unchecked_call_plan(report: Mapping[str, Any], retrieval: Mapping[str, Any] | None) -> ValidationPlan:
    focal_contract, function_name, hypothesis, preconditions, impact = _plan_inputs(report)
    entry_signature = _entry_signature(report) or function_name
    actor_roles = _actor_roles(report, "unchecked-call")
    call_expressions = _call_expressions(report)
    call_targets = _risky_call_targets(report)
    storage_targets = _storage_targets(report)
    setup_steps = [
        f"Deploy {focal_contract} and a downstream mock that can deterministically fail or return false during {entry_signature}.",
        "Record the state that should only commit after a successful external interaction.",
    ]
    setup_steps.extend(preconditions)
    attack_steps = [
        f"Trigger {entry_signature} while the downstream call path is forced to fail, return false, or revert under controlled conditions.",
        (
            f"Force the external interaction `{call_expressions[0]}` to fail so the candidate observes whether execution still commits state."
            if call_expressions
            else "Force the downstream external interaction to fail so the candidate observes whether execution still commits state."
        ),
        "Observe whether the caller continues execution and commits state even though the external interaction was unsuccessful.",
    ]
    attack_steps.extend(_retrieval_candidate_test_ideas(retrieval))
    assertions = [
        f"Assert that the state change still commits when the downstream call from {entry_signature} should have prevented it.",
        "Assert that the function either suppresses or mishandles the external-call failure signal.",
    ]
    if storage_targets:
        assertions.append(f"Check whether protected state still changed after the forced failure: {', '.join(storage_targets)}")
    if impact:
        assertions.append(f"Check whether the committed state matches the hypothesized impact: {impact}")
    invariant_candidates = [
        "Critical state changes should not commit when a required external transfer or call fails.",
        "The post-state should distinguish successful and failed downstream interactions.",
    ]
    harness_notes = ["Use a mock callee or token that can fail on demand so the negative path is deterministic."]
    return ValidationPlan(
        scenario="unchecked_call_failure_validation",
        objective=f"Validate whether {hypothesis} can be reproduced by forcing a downstream call failure.",
        entry_function=function_name,
        entry_signature=entry_signature,
        actor_roles=actor_roles,
        state_targets=storage_targets,
        call_targets=call_targets,
        call_expressions=call_expressions,
        setup_steps=_dedupe_preserve_order(setup_steps),
        attack_steps=_dedupe_preserve_order(attack_steps),
        assertions=_dedupe_preserve_order(assertions),
        invariant_candidates=_dedupe_preserve_order(invariant_candidates),
        harness_notes=_dedupe_preserve_order(harness_notes),
        guidance=_dedupe_preserve_order(_retrieval_guidance(retrieval)),
        references=_dedupe_preserve_order([_primary_evidence_reference(report), *_retrieval_references(retrieval)]),
    )


def _build_generic_plan(report: Mapping[str, Any], retrieval: Mapping[str, Any] | None) -> ValidationPlan:
    focal_contract, function_name, hypothesis, preconditions, impact = _plan_inputs(report)
    entry_signature = _entry_signature(report) or function_name
    storage_targets = _storage_targets(report)
    actor_roles = _actor_roles(report, "generic")
    seed_signature = _supporting_function_signature(report, ("deposit", "mint", "set", "configure", "initialize"))
    call_expressions = _call_expressions(report)
    call_targets = _risky_call_targets(report)
    setup_steps = [
        f"Deploy {focal_contract} and any collaborators needed to reach {function_name}.",
        "Create at least one attacker-controlled actor and one expected-good actor.",
        (
            f"Use {seed_signature} first if the vulnerable sequence requires seeded state before {entry_signature}."
            if seed_signature
            else f"Capture pre-state for {', '.join(storage_targets) if storage_targets else 'the state called out by the finding'} before the sequence begins."
        ),
    ]
    setup_steps.extend(preconditions)
    attack_steps = [
        f"Drive {entry_signature} through the shortest sequence that can satisfy the hypothesis: {hypothesis}",
        (
            f"Use the suspicious interaction `{call_expressions[0]}` as the pivot for the candidate sequence."
            if call_expressions
            else f"Use the suspicious interaction against {', '.join(call_targets)} as the pivot for the candidate sequence."
            if call_targets
            else "Use the most suspicious state transition as the pivot for the candidate sequence."
        ),
        "If one transaction is insufficient, add the smallest follow-up transaction that preserves attacker control over the next state transition.",
    ]
    attack_steps.extend(_retrieval_candidate_test_ideas(retrieval))
    assertions = [
        "Assert that the observed post-state differs from the intended secure behavior in a way that benefits the attacker or breaks a security property.",
    ]
    if impact:
        assertions.append(f"Check whether the resulting state aligns with the hypothesized impact: {impact}")
    invariant_candidates = [
        "Critical balances, permissions, or supply values should remain consistent across the adapted sequence.",
        f"{function_name} should not leave the contract in a state that contradicts the documented or inferred security assumptions.",
    ]
    return ValidationPlan(
        scenario="generic_exploit_validation",
        objective=f"Validate whether {hypothesis} can be reproduced with a concrete transaction sequence.",
        entry_function=function_name,
        entry_signature=entry_signature,
        actor_roles=actor_roles,
        state_targets=storage_targets,
        call_targets=call_targets,
        call_expressions=call_expressions,
        setup_steps=_dedupe_preserve_order(setup_steps),
        attack_steps=_dedupe_preserve_order(attack_steps),
        assertions=_dedupe_preserve_order(assertions),
        invariant_candidates=_dedupe_preserve_order(invariant_candidates),
        guidance=_dedupe_preserve_order(_retrieval_guidance(retrieval)),
        references=_dedupe_preserve_order([_primary_evidence_reference(report), *_retrieval_references(retrieval)]),
        multi_transaction=True,
    )


def _decorate_validation_plan(report: Mapping[str, Any], plan: ValidationPlan) -> ValidationPlan:
    entry_call = _build_call_hint(plan.entry_signature or plan.entry_function, purpose="entry")
    setup_calls = _build_setup_call_hints(report, plan.scenario)
    domain_signals = _derive_domain_signals(report, plan)
    sequence_variants = _build_sequence_variants(plan)
    fuzz_inputs = _build_fuzz_inputs(plan, domain_signals)
    fuzz_assertions = _build_fuzz_assertions(plan, domain_signals)
    differential_targets = _detect_differential_targets(report)
    differential_assertions = _build_differential_assertions(plan, differential_targets)
    symbolic_adapters = _detect_symbolic_adapters(plan)
    invariant_candidates = _dedupe_preserve_order(plan.invariant_candidates + _domain_invariant_candidates(plan, domain_signals))
    assertions = _dedupe_preserve_order(plan.assertions + _domain_assertions(plan, domain_signals))
    modes = _derive_validation_modes(plan, differential_targets, symbolic_adapters)
    return replace(
        plan,
        modes=modes,
        entry_call=entry_call,
        setup_calls=setup_calls,
        domain_signals=domain_signals,
        sequence_variants=sequence_variants,
        fuzz_inputs=fuzz_inputs,
        fuzz_assertions=fuzz_assertions,
        differential_targets=differential_targets,
        differential_assertions=differential_assertions,
        symbolic_adapters=symbolic_adapters,
        invariant_candidates=invariant_candidates,
        assertions=assertions,
    )


def _plan_inputs(report: Mapping[str, Any]) -> tuple[str, str, str, list[str], str]:
    context = _as_mapping(report.get("structure_context"))
    finding_focus = _as_mapping(context.get("finding_focus"))
    focal_contract = str(context.get("focal_contract") or finding_focus.get("contract_name") or "the focal contract")
    function_name = str(finding_focus.get("function_name") or "the reported entrypoint")
    hypothesis = _primary_hypothesis(report)
    hypothesis_payload = _primary_hypothesis_payload(report)
    preconditions = [str(item) for item in hypothesis_payload.get("preconditions") or []]
    impact = str(hypothesis_payload.get("impact") or "").strip()
    if not impact:
        impact = str(_as_mapping(_as_mapping(report.get("provider_reasoning")).get("exploitability")).get("rationale") or "").strip()
    return focal_contract, function_name, hypothesis, preconditions, impact


def _focus_function_summary(report: Mapping[str, Any]) -> Mapping[str, Any]:
    context = _as_mapping(report.get("structure_context"))
    finding_focus = _as_mapping(context.get("finding_focus"))
    focus_name = str(finding_focus.get("function_name") or context.get("focal_function") or "").strip()
    functions = [item for item in context.get("function_summaries") or [] if isinstance(item, Mapping)]
    for item in functions:
        if str(item.get("name") or "").strip() == focus_name:
            return item
    return functions[0] if functions else {}


def _normalize_selected_mode(selected_mode: str, validation_plan: ValidationPlan) -> str:
    normalized = str(selected_mode or "exploit").strip().lower()
    if normalized not in SUPPORTED_EXECUTION_MODES:
        supported = ", ".join(SUPPORTED_EXECUTION_MODES)
        raise ValueError(f"Unsupported validation mode '{selected_mode}'. Supported modes: {supported}")
    available = [mode for mode in validation_plan.modes if mode in SUPPORTED_EXECUTION_MODES] or ["exploit"]
    if normalized not in available:
        raise ValueError(f"Validation mode '{normalized}' is unavailable for this finding. Available modes: {', '.join(available)}")
    return normalized


def _build_execution_selector(
    framework: str,
    report: Mapping[str, Any],
    validation_plan: ValidationPlan,
    selected_mode: str,
) -> str:
    label = _pascal_case(report.get("title") or report.get("finding_id") or "Generated")
    title = str(report.get("title") or report.get("finding_id") or "Generated candidate").strip() or "Generated candidate"
    if framework == "foundry":
        if selected_mode == "invariant":
            return f"testInvariantCandidate{label}"
        if selected_mode == "fuzz":
            return f"testFuzzCandidate{label}"
        return f"testExploitSequence{label}"
    if selected_mode == "invariant":
        return f"tracks invariant candidate behavior for {title}"
    if selected_mode == "fuzz":
        return f"explores bounded fuzz inputs for {title}"
    return f"runs exploit candidate sequence for {title}"


def _entry_signature(report: Mapping[str, Any]) -> str:
    focus = _focus_function_summary(report)
    signature = str(focus.get("signature") or "").strip()
    if signature:
        return signature
    context = _as_mapping(report.get("structure_context"))
    return str(_as_mapping(context.get("finding_focus")).get("function_name") or context.get("focal_function") or "").strip()


def _supporting_function_signature(report: Mapping[str, Any], keywords: tuple[str, ...]) -> str:
    context = _as_mapping(report.get("structure_context"))
    focus_name = str(_as_mapping(context.get("finding_focus")).get("function_name") or context.get("focal_function") or "").strip()
    for item in context.get("function_summaries") or []:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or "").strip().lower()
        if not name or name == focus_name.lower():
            continue
        if any(keyword in name for keyword in keywords):
            return str(item.get("signature") or item.get("name") or "").strip()
    return ""


def _supporting_function_signatures(report: Mapping[str, Any], keywords: tuple[str, ...], *, limit: int = 2) -> list[str]:
    context = _as_mapping(report.get("structure_context"))
    focus_name = str(_as_mapping(context.get("finding_focus")).get("function_name") or context.get("focal_function") or "").strip().lower()
    matches: list[str] = []
    for item in context.get("function_summaries") or []:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or "").strip().lower()
        if not name or name == focus_name:
            continue
        if any(keyword in name for keyword in keywords):
            signature = str(item.get("signature") or item.get("name") or "").strip()
            if signature:
                matches.append(signature)
    return _dedupe_preserve_order(matches)[:limit]


def _build_setup_call_hints(report: Mapping[str, Any], scenario: str) -> list[dict[str, Any]]:
    if scenario == "unauthorized_access_validation":
        keywords = ("initialize", "configure", "grant", "set", "owner", "admin")
    elif scenario == "unchecked_call_failure_validation":
        keywords = ("approve", "deposit", "mint", "configure", "set")
    else:
        keywords = ("deposit", "mint", "fund", "credit", "stake", "approve", "initialize", "configure")
    return [
        hint
        for signature in _supporting_function_signatures(report, keywords)
        if (hint := _build_call_hint(signature, purpose="setup"))
    ]


def _build_call_hint(signature: str, *, purpose: str) -> dict[str, Any]:
    normalized_signature = str(signature or "").strip()
    if normalized_signature and "(" not in normalized_signature and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", normalized_signature):
        normalized_signature = f"{normalized_signature}()"
    parsed = _parse_signature_shape(normalized_signature)
    if not parsed:
        return {}
    name = parsed["name"]
    parameters = [_argument_hint(item, index=index) for index, item in enumerate(parsed["parameters"], start=1)]
    canonical_signature = f"{name}({','.join(item['canonical_type'] for item in parameters)})"
    display_arguments = ", ".join(item["name"] for item in parameters)
    return {
        "purpose": purpose,
        "name": name,
        "signature": normalized_signature,
        "canonical_signature": canonical_signature,
        "display_call": f"{name}({display_arguments})" if parameters else f"{name}()",
        "supported": all(bool(item.get("supported")) for item in parameters),
        "args": parameters,
    }


def _parse_signature_shape(signature: str) -> dict[str, Any]:
    raw = str(signature or "").strip()
    match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\((.*)\)$", raw)
    if not match:
        return {}
    name = match.group(1)
    body = match.group(2).strip()
    parameters = []
    if body:
        for index, chunk in enumerate(_split_signature_parameters(body), start=1):
            parsed = _parse_parameter_chunk(chunk, index=index)
            if parsed:
                parameters.append(parsed)
    return {"name": name, "parameters": parameters}


def _split_signature_parameters(body: str) -> list[str]:
    items: list[str] = []
    current: list[str] = []
    paren_depth = 0
    bracket_depth = 0
    for char in body:
        if char == "," and paren_depth == 0 and bracket_depth == 0:
            chunk = "".join(current).strip()
            if chunk:
                items.append(chunk)
            current = []
            continue
        current.append(char)
        if char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth = max(paren_depth - 1, 0)
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth = max(bracket_depth - 1, 0)
    chunk = "".join(current).strip()
    if chunk:
        items.append(chunk)
    return items


def _parse_parameter_chunk(chunk: str, *, index: int) -> dict[str, str] | None:
    normalized = " ".join(chunk.replace("\n", " ").split())
    if not normalized:
        return None
    tokens = normalized.split()
    filtered = [token for token in tokens if token not in {"memory", "calldata", "storage", "indexed"}]
    if not filtered:
        return None
    candidate_name = filtered[-1]
    if len(filtered) == 1 or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", candidate_name):
        type_name = " ".join(filtered)
        name = f"arg{index}"
    else:
        type_name = " ".join(filtered[:-1]).strip()
        name = candidate_name
        if not type_name:
            type_name = candidate_name
            name = f"arg{index}"
    canonical_type = _canonical_type_name(type_name)
    return {"name": name, "type_name": type_name, "canonical_type": canonical_type}


def _canonical_type_name(type_name: str) -> str:
    normalized = " ".join(type_name.split())
    normalized = normalized.replace(" payable", "")
    if normalized == "uint":
        return "uint256"
    if normalized == "int":
        return "int256"
    return normalized


def _argument_hint(parameter: Mapping[str, str], *, index: int) -> dict[str, Any]:
    name = str(parameter.get("name") or f"arg{index}")
    type_name = str(parameter.get("type_name") or "bytes")
    canonical_type = str(parameter.get("canonical_type") or _canonical_type_name(type_name))
    lower_name = name.lower()
    lower_type = canonical_type.lower()
    supported = True
    if "address" in lower_type:
        solidity_default = "_normalizeCandidateActor(address(0))"
        solidity_fuzz = "normalizedActor"
        javascript_default = "normalizeCandidateActor(undefined)"
        javascript_fuzz = "seed.actor"
        javascript_override = "actor"
    elif any(token in lower_type for token in ("uint", "int")):
        default_numeric = "1 ether" if any(token in lower_name for token in ("amount", "value", "asset", "debt", "price", "share", "collateral")) else "1"
        solidity_default = f"_boundCandidateAmount({default_numeric})"
        solidity_fuzz = "boundedAmount"
        javascript_default = "normalizeFuzzAmount(10n ** 18n)" if default_numeric == "1 ether" else "normalizeFuzzAmount(1n)"
        javascript_fuzz = "seed.amount"
        javascript_override = "amount"
    elif lower_type == "bool":
        solidity_default = "true"
        solidity_fuzz = "true"
        javascript_default = "true"
        javascript_fuzz = "true"
        javascript_override = name
    elif lower_type == "bytes32":
        solidity_default = 'keccak256(abi.encodePacked("candidate-proof"))'
        solidity_fuzz = 'keccak256(abi.encodePacked("candidate-proof"))'
        javascript_default = '"0x" + "11".repeat(32)'
        javascript_fuzz = '"0x" + "11".repeat(32)'
        javascript_override = name
    elif lower_type == "bytes":
        solidity_default = 'hex"cafe"'
        solidity_fuzz = 'hex"cafe"'
        javascript_default = '"0xcafe"'
        javascript_fuzz = '"0xcafe"'
        javascript_override = name
    elif lower_type == "string":
        solidity_default = '"candidate-note"'
        solidity_fuzz = '"candidate-note"'
        javascript_default = '"candidate-note"'
        javascript_fuzz = '"candidate-note"'
        javascript_override = name
    else:
        supported = False
        solidity_default = ""
        solidity_fuzz = ""
        javascript_default = "null"
        javascript_fuzz = "null"
        javascript_override = name
    return {
        "name": name,
        "type_name": type_name,
        "canonical_type": canonical_type,
        "supported": supported,
        "solidity_default": solidity_default,
        "solidity_fuzz": solidity_fuzz,
        "javascript_default": javascript_default,
        "javascript_fuzz": javascript_fuzz,
        "javascript_override": javascript_override,
    }


def _guard_hint(report: Mapping[str, Any]) -> str:
    focus = _focus_function_summary(report)
    modifiers = [str(item) for item in focus.get("modifiers") or [] if str(item).strip()]
    if modifiers:
        return ", ".join(modifiers)
    context = _as_mapping(report.get("structure_context"))
    usage = [str(item) for item in context.get("modifier_usage") or [] if str(item).strip()]
    for item in usage:
        lower = item.lower()
        if any(token in lower for token in ("owner", "admin", "role", "auth", "only")):
            return item
    return ""


def _actor_roles(report: Mapping[str, Any], scenario: str) -> list[str]:
    roles = ["attacker"]
    guard_hint = _guard_hint(report).lower()
    if any(token in guard_hint for token in ("owner", "admin", "role")):
        roles.append("privileged-admin")
        roles.append("unauthorized-caller")
    if scenario == "reentrancy":
        roles.append("attacker-receiver")
    entry_signature = _entry_signature(report).lower()
    if any(token in entry_signature for token in ("deposit", "withdraw", "redeem", "borrow", "claim")):
        roles.append("funded-user")
    return _dedupe_preserve_order(roles)


def _call_expressions(report: Mapping[str, Any]) -> list[str]:
    context = _as_mapping(report.get("structure_context"))
    values = []
    for item in context.get("risky_external_calls") or []:
        if isinstance(item, Mapping):
            expression = str(item.get("expression") or "").strip()
            if expression:
                values.append(expression)
    return values[:2]


def _derive_validation_modes(
    plan: ValidationPlan,
    differential_targets: list[str],
    symbolic_adapters: list[dict[str, Any]],
) -> list[str]:
    modes = ["exploit"]
    if plan.include_invariant_candidate:
        modes.append("invariant")
    if plan.multi_transaction or plan.sequence_variants:
        modes.append("sequence-variants")
    modes.append("fuzz")
    if differential_targets:
        modes.append("differential")
    if symbolic_adapters:
        modes.append("symbolic-hints")
    return _dedupe_preserve_order(modes)


def _derive_domain_signals(report: Mapping[str, Any], plan: ValidationPlan) -> list[str]:
    signal_space = " ".join(
        [
            _rule_id(report),
            plan.entry_signature,
            plan.entry_function,
            " ".join(plan.state_targets),
            " ".join(plan.call_targets),
            " ".join(plan.call_expressions),
        ]
    ).lower()
    signals: list[str] = []
    if any(token in signal_space for token in ("balance", "reserve", "amount", "vault", "asset", "debt")):
        signals.append("balance-accounting")
    if any(token in signal_space for token in ("owner", "admin", "role", "auth", "permit")):
        signals.append("authorization")
    if any(token in signal_space for token in ("supply", "mint", "burn", "shares")):
        signals.append("supply-integrity")
    if any(token in signal_space for token in ("allowance", "approve")):
        signals.append("allowance-integrity")
    if any(token in signal_space for token in ("collateral", "borrow", "liquidat", "debt")):
        signals.append("collateralization")
    if any(token in signal_space for token in ("oracle", "price", "twap")):
        signals.append("oracle-dependency")
    if any(token in signal_space for token in ("reward", "claim", "accru")):
        signals.append("rewards-accounting")
    if "reentrancy" in signal_space:
        signals.append("callback-reentry")
    return _dedupe_preserve_order(signals)


def _domain_invariant_candidates(plan: ValidationPlan, domain_signals: list[str]) -> list[str]:
    invariants: list[str] = []
    if "balance-accounting" in domain_signals:
        invariants.append(
            f"Tracked balances and moved assets should reconcile after {plan.entry_signature or plan.entry_function or 'the focal entrypoint'} completes."
        )
    if "authorization" in domain_signals:
        invariants.append("Only explicitly privileged actors should mutate authorization-sensitive state.")
    if "supply-integrity" in domain_signals:
        invariants.append("Mint and burn flows should preserve authorized total-supply accounting.")
    if "allowance-integrity" in domain_signals:
        invariants.append("Allowance state should only change under authorized approval or spend flows.")
    if "collateralization" in domain_signals:
        invariants.append("Collateral and debt should remain within expected solvency bounds after each sequence.")
    if "oracle-dependency" in domain_signals:
        invariants.append("Value-sensitive state transitions should not be exploitable via one-step oracle manipulation.")
    if "rewards-accounting" in domain_signals:
        invariants.append("Reward accrual and claims should remain monotonic and bounded per user position.")
    return invariants


def _domain_assertions(plan: ValidationPlan, domain_signals: list[str]) -> list[str]:
    assertions: list[str] = []
    if "balance-accounting" in domain_signals and plan.state_targets:
        assertions.append(f"Compare pre/post accounting for {', '.join(plan.state_targets)} against actual assets moved to the attacker.")
    if "authorization" in domain_signals:
        assertions.append("Verify that unauthorized actors cannot retain any privileged capability after the sequence.")
    if "supply-integrity" in domain_signals:
        assertions.append("Check that total supply, share count, or minted amount stays consistent with authorized state transitions.")
    if "collateralization" in domain_signals:
        assertions.append("Check whether the sequence leaves debt undercollateralized or bypasses a solvency check.")
    if "oracle-dependency" in domain_signals:
        assertions.append("Check whether price-sensitive state changes can be forced using attacker-controlled timing or updates.")
    if "callback-reentry" in domain_signals:
        assertions.append("Check whether callback-driven reentry observes stale state between the first and second call frames.")
    return assertions


def _build_sequence_variants(plan: ValidationPlan) -> list[dict[str, Any]]:
    entrypoint = plan.entry_signature or plan.entry_function or "the focal entrypoint"
    variants = [
        {
            "name": "minimal-sequence",
            "goal": f"Exercise the shortest candidate path through {entrypoint}.",
            "steps": [plan.setup_steps[0] if plan.setup_steps else f"Prepare prerequisites for {entrypoint}.", f"Call {entrypoint} once and evaluate the security signal."],
            "expected_signal": plan.assertions[0] if plan.assertions else "Observe a suspicious post-state difference.",
        }
    ]
    if plan.multi_transaction:
        variants.append(
            {
                "name": "seed-then-follow-up",
                "goal": f"Check whether a seeded state plus a follow-up call amplifies the issue in {entrypoint}.",
                "steps": [*(plan.setup_steps[:2] or [f"Seed state for {entrypoint}."]), plan.attack_steps[0] if plan.attack_steps else f"Call {entrypoint}.", "Repeat or follow up with one more state-dependent transaction before assertions."],
                "expected_signal": "A two-step path succeeds where the single-step path should not.",
            }
        )
    if plan.call_expressions:
        variants.append(
            {
                "name": "external-interaction-pivot",
                "goal": "Use the suspicious external interaction as the pivot of the candidate sequence.",
                "steps": [f"Reach `{plan.call_expressions[0]}` under attacker-controlled conditions.", "Observe whether state is committed before or after that interaction in the undesired order."],
                "expected_signal": "The post-state after the external interaction contradicts the intended invariant.",
            }
        )
    return variants[:3]


def _build_fuzz_inputs(plan: ValidationPlan, domain_signals: list[str]) -> list[str]:
    entrypoint = plan.entry_signature or plan.entry_function or "the focal entrypoint"
    inputs = [
        f"Bound a numeric amount input around the value-sensitive path for {entrypoint}.",
        "Vary the caller/actor identity across attacker, honest user, and privileged user roles where applicable.",
    ]
    if "callback-reentry" in domain_signals:
        inputs.append("Fuzz callback depth or repeated entry attempts while keeping the sequence bounded.")
    if "collateralization" in domain_signals:
        inputs.append("Fuzz collateral and debt magnitudes near solvency boundaries.")
    if "oracle-dependency" in domain_signals:
        inputs.append("Fuzz price-like inputs or update ordering when a manipulable oracle is involved.")
    return _dedupe_preserve_order(inputs)


def _build_fuzz_assertions(plan: ValidationPlan, domain_signals: list[str]) -> list[str]:
    assertions = [
        f"Across bounded inputs, {plan.entry_signature or plan.entry_function or 'the focal entrypoint'} should preserve the core security invariant.",
    ]
    assertions.extend(_domain_invariant_candidates(plan, domain_signals)[:2])
    assertions.extend(_domain_assertions(plan, domain_signals)[:2])
    return _dedupe_preserve_order(assertions)


def _detect_differential_targets(report: Mapping[str, Any]) -> list[str]:
    context = _as_mapping(report.get("structure_context"))
    focal_contract = str(context.get("focal_contract") or "").strip()
    candidates: list[str] = []
    keywords = ("reference", "mock", "legacy", "v1", "v2", "impl")
    for item in context.get("related_contracts") or []:
        if isinstance(item, Mapping):
            name = str(item.get("name") or item.get("contract") or "").strip()
            if name and name != focal_contract and any(keyword in name.lower() for keyword in keywords):
                candidates.append(name)
    for item in context.get("imports") or []:
        name = Path(str(item)).stem
        if name and name != focal_contract and any(keyword in name.lower() for keyword in keywords):
            candidates.append(name)
    return _dedupe_preserve_order(candidates)[:2]


def _build_differential_assertions(plan: ValidationPlan, differential_targets: list[str]) -> list[str]:
    if not differential_targets:
        return []
    entrypoint = plan.entry_signature or plan.entry_function or "the focal entrypoint"
    return [
        f"Replay the same sequence against {', '.join(differential_targets)} and compare post-state against {entrypoint}.",
        "Compare both revert behavior and security-sensitive state deltas after equivalent inputs.",
    ]


def _detect_symbolic_adapters(plan: ValidationPlan) -> list[dict[str, Any]]:
    entrypoint = plan.entry_function or "candidate"
    adapters = [
        {
            "name": "halmos",
            "purpose": "stateful symbolic execution for Foundry-oriented tests",
            "available": shutil.which("halmos") is not None,
            "command": ["halmos", "--function", entrypoint],
        },
        {
            "name": "myth",
            "purpose": "symbolic analysis of compiled contracts or bytecode",
            "available": shutil.which("myth") is not None,
            "command": ["myth", "analyze"],
        },
        {
            "name": "manticore",
            "purpose": "stateful symbolic exploration of EVM paths",
            "available": shutil.which("manticore") is not None,
            "command": ["manticore"],
        },
    ]
    return adapters


def _primary_hypothesis_payload(report: Mapping[str, Any]) -> Mapping[str, Any]:
    provider_reasoning = _as_mapping(report.get("provider_reasoning"))
    for item in provider_reasoning.get("exploit_hypotheses") or []:
        if isinstance(item, Mapping):
            return item
    return {}


def _storage_targets(report: Mapping[str, Any]) -> list[str]:
    context = _as_mapping(report.get("structure_context"))
    values = []
    for item in context.get("storage_sensitive_state") or []:
        if isinstance(item, Mapping):
            name = str(item.get("name") or "").strip()
            if name:
                values.append(name)
    return values[:3]


def _risky_call_targets(report: Mapping[str, Any]) -> list[str]:
    context = _as_mapping(report.get("structure_context"))
    values = []
    for item in context.get("risky_external_calls") or []:
        if isinstance(item, Mapping):
            target = str(item.get("target") or "").strip()
            if target:
                values.append(target)
    return values[:2]


def _retrieval_candidate_test_ideas(retrieval: Mapping[str, Any] | None) -> list[str]:
    ideas: list[str] = []
    for item in _retrieval_matches(retrieval):
        if isinstance(item, Mapping):
            ideas.extend(str(idea) for idea in item.get("candidate_test_ideas") or [] if str(idea).strip())
    return ideas[:2]


def _retrieval_guidance(retrieval: Mapping[str, Any] | None) -> list[str]:
    guidance: list[str] = []
    for item in _retrieval_matches(retrieval):
        if isinstance(item, Mapping):
            guidance.extend(str(entry) for entry in item.get("guidance") or [] if str(entry).strip())
    return guidance[:3]


def _retrieval_references(retrieval: Mapping[str, Any] | None) -> list[str]:
    references: list[str] = []
    for item in _retrieval_matches(retrieval):
        if not isinstance(item, Mapping):
            continue
        pattern_id = str(item.get("pattern_id") or "").strip()
        source = str(item.get("source") or "").strip()
        if pattern_id:
            references.append(pattern_id)
        if source:
            references.append(source)
        references.extend(str(entry) for entry in item.get("references") or [] if str(entry).strip())
    return references[:4]


def _retrieval_matches(retrieval: Mapping[str, Any] | None) -> list[Any]:
    return list(_as_mapping(retrieval).get("matches") or [])


def _target_suffix(targets: list[str]) -> str:
    if not targets:
        return ""
    return f" against {', '.join(targets)}"


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for item in items:
        value = str(item).strip()
        if not value or value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def _render_solidity_comment_block(items: list[str], *, indent: str, fallback: str | None = None) -> list[str]:
    values = items or ([fallback] if fallback else [])
    return [f"{indent}{index}. {item}" for index, item in enumerate(values, start=1)]


def _render_javascript_comment_block(items: list[str], *, indent: str, fallback: str | None = None) -> list[str]:
    values = items or ([fallback] if fallback else [])
    return [f"{indent}{index}. {item}" for index, item in enumerate(values, start=1)]


def _render_foundry_candidate_helpers(validation_plan: ValidationPlan) -> list[str]:
    invariant_candidates = validation_plan.invariant_candidates or [
        "Assert the protected state still matches the expected accounting or authorization invariant."
    ]
    lines = [
        "",
        "    function _boundCandidateAmount(uint256 rawAmount) internal pure returns (uint256) {",
        "        uint256 upperBound = type(uint96).max;",
        "        if (rawAmount == 0) {",
        "            return 1;",
        "        }",
        "        if (rawAmount > upperBound) {",
        "            return upperBound;",
        "        }",
        "        return rawAmount;",
        "    }",
        "",
        "    function _normalizeCandidateActor(address rawActor) internal pure returns (address) {",
        "        if (rawActor == address(0)) {",
        "            return address(0xBEEF);",
        "        }",
        "        return rawActor;",
        "    }",
        "",
        "    function _candidateInvariantHashes() internal pure returns (bytes32[] memory hashes) {",
        f"        hashes = new bytes32[]({len(invariant_candidates)});",
    ]
    for index, item in enumerate(invariant_candidates):
        lines.append(f"        hashes[{index}] = keccak256(bytes({json.dumps(item)}));")
    lines.extend(
        [
            "        return hashes;",
            "    }",
        ]
    )
    lines.extend(_render_foundry_call_helpers(validation_plan))
    return lines


def _render_foundry_call_preparation(validation_plan: ValidationPlan, *, include_fuzz_bindings: bool) -> list[str]:
    lines: list[str] = []
    if validation_plan.setup_calls:
        if include_fuzz_bindings:
            lines.append("        bytes[] memory setupCalls = _candidateSetupCalldatasFor(boundedAmount, normalizedActor);")
        else:
            lines.append("        bytes[] memory setupCalls = _candidateSetupCalldatas();")
        lines.append('        require(setupCalls.length > 0, "expected candidate setup call hints");')
    if validation_plan.entry_call:
        if include_fuzz_bindings:
            lines.append("        bytes memory entryCall = _candidateEntryCalldataFor(boundedAmount, normalizedActor);")
        else:
            lines.append("        bytes memory entryCall = _candidateEntryCalldata();")
        lines.append('        require(entryCall.length > 4, "expected candidate entry calldata");')
    return lines


def _render_foundry_call_helpers(validation_plan: ValidationPlan) -> list[str]:
    lines: list[str] = []
    entry_call = validation_plan.entry_call if isinstance(validation_plan.entry_call, Mapping) else {}
    if entry_call:
        lines.extend(
            [
                "",
                "    function _candidateEntryCalldata() internal pure returns (bytes memory) {",
                f"        return {_solidity_encoded_call(entry_call, for_fuzz=False)};",
                "    }",
                "",
                "    function _candidateEntryCalldataFor(uint256 boundedAmount, address normalizedActor) internal pure returns (bytes memory) {",
                f"        return {_solidity_encoded_call(entry_call, for_fuzz=True)};",
                "    }",
            ]
        )
    setup_calls = [item for item in validation_plan.setup_calls if isinstance(item, Mapping)]
    lines.extend(
        [
            "",
            "    function _candidateSetupCalldatas() internal pure returns (bytes[] memory calls) {",
            f"        calls = new bytes[]({len(setup_calls)});",
        ]
    )
    for index, item in enumerate(setup_calls):
        lines.append(f"        calls[{index}] = {_solidity_encoded_call(item, for_fuzz=False)};")
    lines.extend(
        [
            "        return calls;",
            "    }",
            "",
            "    function _candidateSetupCalldatasFor(uint256 boundedAmount, address normalizedActor) internal pure returns (bytes[] memory calls) {",
            f"        calls = new bytes[]({len(setup_calls)});",
        ]
    )
    for index, item in enumerate(setup_calls):
        lines.append(f"        calls[{index}] = {_solidity_encoded_call(item, for_fuzz=True)};")
    lines.extend(
        [
            "        return calls;",
            "    }",
        ]
    )
    return lines


def _render_solidity_call_hints(items: list[dict[str, Any]], *, indent: str) -> list[str]:
    lines: list[str] = []
    for index, item in enumerate(items, start=1):
        display = str(item.get("display_call") or item.get("signature") or f"candidate-call-{index}")
        support = "concrete args" if item.get("supported") else "partial args"
        lines.append(f"{indent}{index}. {display} ({support})")
    return lines


def _render_javascript_call_helpers(validation_plan: ValidationPlan) -> list[str]:
    entry_call = validation_plan.entry_call if isinstance(validation_plan.entry_call, Mapping) else {}
    setup_calls = [item for item in validation_plan.setup_calls if isinstance(item, Mapping)]
    lines = [
        "function buildCandidateEntryCall(overrides = {}) {",
        f"  return {_javascript_call_object(entry_call, for_fuzz=False)};" if entry_call else "  return { signature: \"\", displayCall: \"\", args: [] };",
        "}",
        "",
        "function buildCandidateSetupCalls(overrides = {}) {",
        "  return [",
    ]
    for item in setup_calls:
        lines.append(f"    {_javascript_call_object(item, for_fuzz=False)},")
    lines.extend(["  ];", "}"])
    return lines


def _render_javascript_call_hints(items: list[dict[str, Any]], *, indent: str) -> list[str]:
    return _render_solidity_call_hints(items, indent=indent)


def _solidity_encoded_call(call_hint: Mapping[str, Any], *, for_fuzz: bool) -> str:
    signature = str(call_hint.get("canonical_signature") or "")
    args = []
    for item in call_hint.get("args") or []:
        if not isinstance(item, Mapping):
            continue
        expression = str(item.get("solidity_fuzz") if for_fuzz else item.get("solidity_default") or "").strip()
        if expression:
            args.append(expression)
    quoted_signature = json.dumps(signature)
    if not args:
        return f"abi.encodeWithSignature({quoted_signature})"
    return f"abi.encodeWithSignature({quoted_signature}, {', '.join(args)})"


def _javascript_call_object(call_hint: Mapping[str, Any], *, for_fuzz: bool) -> str:
    if not call_hint:
        return "{ signature: \"\", displayCall: \"\", args: [] }"
    signature = json.dumps(str(call_hint.get("canonical_signature") or ""))
    display = json.dumps(str(call_hint.get("display_call") or call_hint.get("signature") or ""))
    args: list[str] = []
    for item in call_hint.get("args") or []:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or "arg")
        default_value = str(item.get("javascript_fuzz") if for_fuzz else item.get("javascript_default") or "null")
        override = str(item.get("javascript_override") or name)
        if override != name:
            args.append(f"overrides.{name} ?? overrides.{override} ?? {default_value}")
        else:
            args.append(f"overrides.{name} ?? {default_value}")
    return f"{{ signature: {signature}, displayCall: {display}, args: [{', '.join(args)}] }}"


def _render_solidity_sequence_variants(items: list[dict[str, Any]], *, indent: str) -> list[str]:
    lines: list[str] = []
    for index, item in enumerate(items, start=1):
        name = str(item.get("name") or f"variant-{index}")
        goal = str(item.get("goal") or "Explore an alternate exploit sequence.")
        lines.append(f"{indent}{index}. {name}: {goal}")
        for step_index, step in enumerate(item.get("steps") or [], start=1):
            lines.append(f"{indent}   {step_index}) {step}")
    return lines


def _render_javascript_sequence_variants(items: list[dict[str, Any]], *, indent: str) -> list[str]:
    return _render_solidity_sequence_variants(items, indent=indent)


def _render_solidity_tool_adapters(items: list[dict[str, Any]], *, indent: str) -> list[str]:
    lines: list[str] = []
    for index, item in enumerate(items, start=1):
        name = str(item.get("name") or f"adapter-{index}")
        availability = "available" if item.get("available") else "not on PATH"
        purpose = str(item.get("purpose") or "symbolic exploration")
        command = " ".join(str(part) for part in item.get("command") or [])
        lines.append(f"{indent}{index}. {name} ({availability}) - {purpose}")
        if command:
            lines.append(f"{indent}   cmd: {command}")
    return lines


def _render_javascript_tool_adapters(items: list[dict[str, Any]], *, indent: str) -> list[str]:
    return _render_solidity_tool_adapters(items, indent=indent)


def _build_test_filename(framework: str, report: Mapping[str, Any]) -> str:
    stem = _slug(report.get("finding_id") or report.get("title") or "candidate")
    return f"{stem}.t.sol" if framework == "foundry" else f"{stem}.test.js"


def _select_strategy(report: Mapping[str, Any]) -> str:
    rule_id = _rule_id(report)
    if "reentrancy" in rule_id:
        return "reentrancy_validation_candidate"
    return "exploit_validation_candidate"


def _primary_hypothesis(report: Mapping[str, Any]) -> str:
    provider_reasoning = _as_mapping(report.get("provider_reasoning"))
    hypotheses = provider_reasoning.get("exploit_hypotheses") or []
    for item in hypotheses:
        if isinstance(item, Mapping):
            title = str(item.get("title") or "").strip()
            narrative = str(item.get("narrative") or "").strip()
            if title:
                return title
            if narrative:
                return narrative
    return str(provider_reasoning.get("summary") or report.get("summary") or "No hypothesis was recorded.")


def _primary_evidence_reference(report: Mapping[str, Any]) -> str:
    provider_reasoning = _as_mapping(report.get("provider_reasoning"))
    evidence_references = provider_reasoning.get("evidence_references") or []
    if evidence_references:
        return str(evidence_references[0])
    locations = _as_mapping(report.get("deterministic_evidence")).get("locations") or []
    if locations and isinstance(locations[0], Mapping):
        location = locations[0]
        lines = location.get("lines") or []
        suffix = f":{lines[0]}" if lines else ""
        return f"{location.get('file_path', 'unknown')}{suffix}"
    return "No evidence reference recorded."


def _rule_id(report: Mapping[str, Any]) -> str:
    evidence = _as_mapping(report.get("deterministic_evidence"))
    return str(evidence.get("rule_id") or "unknown-rule")


def _display_path(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _resolve_path(root: Path, candidate: str | Path) -> Path:
    path = Path(candidate)
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _load_report_payload(report: FindingReport | Mapping[str, Any] | None, report_path: Path) -> dict[str, Any]:
    if report is not None:
        return report.to_dict() if isinstance(report, FindingReport) else dict(report)
    return json.loads(report_path.read_text(encoding="utf-8"))


def _build_validation_payload(artifact: GeneratedTestArtifact, execution: ExecutionResult) -> dict[str, Any]:
    evidence = [
        f"artifact_id: {artifact.artifact_id}",
        f"selected_mode: {artifact.selected_mode}",
        f"validation_modes: {', '.join(artifact.validation_plan.modes) if artifact.validation_plan.modes else 'exploit'}",
        f"test_path: {artifact.test_path}",
        f"report_path: {artifact.report_path}",
        f"metadata_path: {artifact.metadata_path}",
        f"execution_result_path: {execution.result_path}",
        f"command: {' '.join(artifact.runner_hint.command)}",
        f"working_directory: {artifact.runner_hint.working_directory}",
        f"return_code: {execution.return_code if execution.return_code is not None else 'unavailable'}",
        f"stdout_log: {execution.stdout_path}",
        f"stderr_log: {execution.stderr_path}",
    ]
    if execution.environment_limitation:
        evidence.append(f"environment_limitation: {execution.environment_limitation}")
    return {
        "state": execution.state,
        "summary": execution.summary,
        "evidence": evidence,
    }


def _classify_execution(framework: str, selected_mode: str, return_code: int, stdout: str, stderr: str) -> tuple[str, str]:
    combined = f"{stdout}\n{stderr}".lower()
    if framework == "hardhat" and "0 passing" in combined and "failing" not in combined:
        return "inconclusive", "Hardhat completed without executing any generated candidate tests; validation did not actually run."
    if return_code == 0:
        return "reproduced", f"{framework.title()} runner completed successfully; the generated {selected_mode} validation candidate reproduced as written."
    if _contains_any(
        combined,
        (
            "no such file or directory",
            "command not found",
            "cannot find module",
            "not installed",
            "is not recognized as an internal or external command",
            "hh12",
            "trying to use a non-local installation of hardhat",
        ),
    ):
        return "inconclusive", f"{framework.title()} runner could not execute because the local toolchain is unavailable or incomplete."
    if _contains_any(
        combined,
        (
            "parsererror",
            "declarationerror",
            "typeerror",
            "compilererror",
            "compilation failed",
            "error hh",
            "module not found",
        ),
    ):
        return "inconclusive", f"{framework.title()} runner hit a compilation or setup error before the candidate could be validated."
    if framework == "foundry" and _contains_any(combined, ("[fail", "failing tests:", "suite result: failed")):
        return "not_reproduced", f"Foundry executed the generated {selected_mode} candidate test, but the validation assertions failed."
    if framework == "hardhat" and _contains_any(combined, (" failing", "assertionerror", "expected ", "reverted with")):
        return "not_reproduced", f"Hardhat executed the generated {selected_mode} candidate test, but the validation assertions failed."
    return "inconclusive", f"{framework.title()} runner returned a non-zero exit code without a stable validation verdict."


def _contains_any(value: str, candidates: tuple[str, ...]) -> bool:
    return any(candidate in value for candidate in candidates)


def _slug(value: object) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "-", str(value or "candidate")).strip("-").lower()
    return text or "candidate"


def _pascal_case(value: object) -> str:
    parts = [part for part in re.split(r"[^a-zA-Z0-9]+", str(value or "Generated")) if part]
    candidate = "".join(part[:1].upper() + part[1:] for part in parts)
    if not candidate or candidate[0].isdigit():
        return f"Generated{candidate}"
    return candidate


def _as_mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}