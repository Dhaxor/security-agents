from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .context import StructuredContextPack
from .models.findings import NormalizedFinding

REPORT_SCHEMA_VERSION = "1.1"


@dataclass(slots=True)
class DeterministicEvidence:
    source: str
    rule_id: str
    severity: str
    analyzer_confidence: str
    description: str
    locations: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_finding(cls, finding: NormalizedFinding) -> "DeterministicEvidence":
        return cls(
            source=finding.source,
            rule_id=finding.rule_id,
            severity=finding.severity,
            analyzer_confidence=finding.confidence,
            description=finding.description,
            locations=[location.to_dict() for location in finding.locations],
            metadata=dict(finding.metadata),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "analyzer_confidence": self.analyzer_confidence,
            "description": self.description,
            "locations": self.locations,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class ExploitHypothesis:
    title: str
    narrative: str
    preconditions: list[str] = field(default_factory=list)
    impact: str = ""
    supporting_signals: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "narrative": self.narrative,
            "preconditions": self.preconditions,
            "impact": self.impact,
            "supporting_signals": self.supporting_signals,
            "gaps": self.gaps,
        }


@dataclass(slots=True)
class ExploitabilityAssessment:
    verdict: str = "insufficient_context"
    rationale: str = "Provider reasoning has not been generated."

    @classmethod
    def pending(cls) -> "ExploitabilityAssessment":
        return cls()

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "rationale": self.rationale,
        }


@dataclass(slots=True)
class ConfidenceScore:
    label: str = "unscored"
    score: float | None = None
    rationale: str = "Provider reasoning has not been generated."

    @classmethod
    def pending(cls) -> "ConfidenceScore":
        return cls()

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "score": self.score,
            "rationale": self.rationale,
        }


@dataclass(slots=True)
class FindingReference:
    fingerprint: str
    rule_id: str
    title: str
    severity: str
    analyzer_confidence: str

    @classmethod
    def from_finding(cls, finding: NormalizedFinding) -> "FindingReference":
        return cls(
            fingerprint=finding.fingerprint,
            rule_id=finding.rule_id,
            title=finding.title,
            severity=finding.severity,
            analyzer_confidence=finding.confidence,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "analyzer_confidence": self.analyzer_confidence,
        }


@dataclass(slots=True)
class ValidationState:
    state: str = "not_run"
    summary: str = "No framework validation has been executed."
    evidence: list[str] = field(default_factory=list)

    @classmethod
    def not_run(cls) -> "ValidationState":
        return cls()

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "summary": self.summary,
            "evidence": self.evidence,
        }


@dataclass(slots=True)
class AssessmentState:
    verdict: str = "suspicious"
    rationale: str = "Only deterministic analyzer evidence is available so far."
    next_steps: list[str] = field(default_factory=list)

    @classmethod
    def pending(cls) -> "AssessmentState":
        return cls(
            next_steps=[
                "Investigate the finding with bounded reasoning to identify a plausible exploit path.",
                "Generate and run a validation candidate before treating the issue as verified.",
            ]
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "rationale": self.rationale,
            "next_steps": self.next_steps,
        }


@dataclass(slots=True)
class ProviderReasoningResult:
    finding_reference: FindingReference
    summary: str = "Provider reasoning has not been generated."
    exploitability: ExploitabilityAssessment = field(default_factory=ExploitabilityAssessment.pending)
    exploit_hypotheses: list[ExploitHypothesis] = field(default_factory=list)
    confidence: ConfidenceScore = field(default_factory=ConfidenceScore.pending)
    assumptions: list[str] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)
    evidence_references: list[str] = field(default_factory=list)
    remediation_notes: list[str] = field(default_factory=list)

    @classmethod
    def pending(cls, finding: NormalizedFinding) -> "ProviderReasoningResult":
        return cls(finding_reference=FindingReference.from_finding(finding))

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_reference": self.finding_reference.to_dict(),
            "summary": self.summary,
            "exploitability": self.exploitability.to_dict(),
            "exploit_hypotheses": [item.to_dict() for item in self.exploit_hypotheses],
            "confidence": self.confidence.to_dict(),
            "assumptions": self.assumptions,
            "caveats": self.caveats,
            "evidence_references": self.evidence_references,
            "remediation_notes": self.remediation_notes,
        }


@dataclass(slots=True)
class ContextSnapshot:
    framework: str
    focal_contract: str
    source_path: str
    contract_summary: str
    focal_function: str | None = None
    finding_focus: dict[str, Any] = field(default_factory=dict)
    imports: list[str] = field(default_factory=list)
    inheritance: list[str] = field(default_factory=list)
    related_contracts: list[dict[str, str]] = field(default_factory=list)
    function_summaries: list[dict[str, Any]] = field(default_factory=list)
    modifier_usage: list[str] = field(default_factory=list)
    risky_external_calls: list[dict[str, Any]] = field(default_factory=list)
    storage_sensitive_state: list[dict[str, Any]] = field(default_factory=list)
    excerpts: list[dict[str, Any]] = field(default_factory=list)
    estimated_tokens: int = 0

    @classmethod
    def from_pack(cls, pack: StructuredContextPack) -> "ContextSnapshot":
        focus = pack.finding_focus or {}
        return cls(
            framework=pack.framework,
            focal_contract=pack.focal_contract,
            source_path=pack.source_path,
            contract_summary=pack.contract_summary,
            focal_function=focus.get("function_name") if isinstance(focus, dict) else None,
            finding_focus=dict(focus) if isinstance(focus, dict) else {},
            imports=list(pack.imports),
            inheritance=list(pack.inheritance),
            related_contracts=[dict(item) for item in pack.related_contracts],
            function_summaries=[dict(item) for item in pack.function_summaries],
            modifier_usage=list(pack.modifier_usage),
            risky_external_calls=[dict(item) for item in pack.risky_external_calls],
            storage_sensitive_state=[dict(item) for item in pack.storage_sensitive_state],
            excerpts=[dict(item) for item in pack.excerpts],
            estimated_tokens=pack.estimated_tokens,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "focal_contract": self.focal_contract,
            "source_path": self.source_path,
            "contract_summary": self.contract_summary,
            "focal_function": self.focal_function,
            "finding_focus": self.finding_focus,
            "imports": self.imports,
            "inheritance": self.inheritance,
            "related_contracts": self.related_contracts,
            "function_summaries": self.function_summaries,
            "modifier_usage": self.modifier_usage,
            "risky_external_calls": self.risky_external_calls,
            "storage_sensitive_state": self.storage_sensitive_state,
            "excerpts": self.excerpts,
            "estimated_tokens": self.estimated_tokens,
        }


@dataclass(slots=True)
class FindingReport:
    finding_id: str
    title: str
    severity: str
    deterministic_evidence: DeterministicEvidence
    provider_reasoning: ProviderReasoningResult
    assessment: AssessmentState
    validation: ValidationState = field(default_factory=ValidationState.not_run)
    structure_context: ContextSnapshot | None = None
    summary: str = ""
    schema_version: str = REPORT_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "summary": self.summary,
            "deterministic_evidence": self.deterministic_evidence.to_dict(),
            "structure_context": None if self.structure_context is None else self.structure_context.to_dict(),
            "provider_reasoning": self.provider_reasoning.to_dict(),
            "assessment": self.assessment.to_dict(),
            "validation": self.validation.to_dict(),
        }


def build_finding_report(
    finding: NormalizedFinding,
    *,
    context_pack: StructuredContextPack | None = None,
    provider_reasoning: ProviderReasoningResult | None = None,
    validation: ValidationState | None = None,
) -> FindingReport:
    summary = finding.title if not finding.description else finding.description.splitlines()[0].strip()
    provider_reasoning_result = provider_reasoning or ProviderReasoningResult.pending(finding)
    validation_state = validation or ValidationState.not_run()
    return FindingReport(
        finding_id=finding.fingerprint,
        title=finding.title,
        severity=finding.severity,
        summary=summary,
        deterministic_evidence=DeterministicEvidence.from_finding(finding),
        structure_context=ContextSnapshot.from_pack(context_pack) if context_pack else None,
        provider_reasoning=provider_reasoning_result,
        assessment=build_assessment_state(provider_reasoning_result, validation_state),
        validation=validation_state,
    )


def build_assessment_state(
    provider_reasoning: ProviderReasoningResult | Mapping[str, Any] | None,
    validation: ValidationState | Mapping[str, Any] | None,
) -> AssessmentState:
    reasoning_payload = provider_reasoning.to_dict() if isinstance(provider_reasoning, ProviderReasoningResult) else _as_mapping(provider_reasoning)
    validation_payload = validation.to_dict() if isinstance(validation, ValidationState) else _as_mapping(validation)
    validation_state = str(validation_payload.get("state") or "not_run")
    hypotheses = [item for item in reasoning_payload.get("exploit_hypotheses") or [] if isinstance(item, Mapping)]
    confidence = _as_mapping(reasoning_payload.get("confidence"))
    confidence_label = str(confidence.get("label") or "").strip().lower()
    confidence_score = _float_or_none(confidence.get("score"))

    if validation_state == "reproduced":
        return AssessmentState(
            verdict="verified",
            rationale="The generated validation candidate reproduced the suspected issue in the local framework runner.",
            next_steps=[
                "Review the proof-of-concept output and confirm real exploit impact.",
                "Patch the contract and rerun the validation flow to confirm the fix.",
            ],
        )
    if validation_state == "not_reproduced":
        return AssessmentState(
            verdict="not_reproduced",
            rationale="A validation candidate executed but did not reproduce the suspected issue as written.",
            next_steps=[
                "Review the hypothesis assumptions and generated assertions for gaps.",
                "Refine the candidate or downgrade the finding if the exploit path no longer looks plausible.",
            ],
        )
    if validation_state == "inconclusive":
        return AssessmentState(
            verdict="inconclusive",
            rationale="Validation could not complete cleanly, so the finding remains unverified.",
            next_steps=[
                "Resolve the runner or environment limitation and rerun validation.",
                "Keep deterministic evidence separate from any unverified exploit claim.",
            ],
        )
    if hypotheses:
        if confidence_label in {"high", "very_high", "critical"} or (confidence_score is not None and confidence_score >= 0.75):
            return AssessmentState(
                verdict="high_confidence",
                rationale="Bounded reasoning identified a concrete exploit path with strong supporting evidence, but it has not been reproduced yet.",
                next_steps=[
                    "Generate and run a focused proof-of-concept or invariant test.",
                    "Confirm the attacker preconditions before escalating the finding.",
                ],
            )
        return AssessmentState(
            verdict="hypothesis",
            rationale="Bounded reasoning identified a plausible exploit path, but execution-backed validation is still pending.",
            next_steps=[
                "Translate the hypothesis into a concrete multi-step validation candidate.",
                "Run the candidate and keep the finding provisional until reproduced.",
            ],
        )
    return AssessmentState.pending()


def render_reports_text(reports: FindingReport | Mapping[str, Any] | list[FindingReport | Mapping[str, Any]]) -> str:
    items = reports if isinstance(reports, list) else [reports]
    return ("\n\n" + ("-" * 72) + "\n\n").join(render_report_text(item) for item in items)


def render_report_text(report: FindingReport | Mapping[str, Any]) -> str:
    payload = report.to_dict() if isinstance(report, FindingReport) else dict(report)
    evidence = _as_mapping(payload.get("deterministic_evidence"))
    context = _as_mapping(payload.get("structure_context"))
    provider_reasoning = _as_mapping(payload.get("provider_reasoning") or payload.get("reasoning"))
    assessment = _as_mapping(payload.get("assessment"))
    finding_reference = _as_mapping(provider_reasoning.get("finding_reference") or provider_reasoning.get("finding"))
    exploitability = _as_mapping(provider_reasoning.get("exploitability"))
    confidence = _as_mapping(provider_reasoning.get("confidence"))
    validation = _as_mapping(payload.get("validation"))

    lines = [
        f"finding: {payload.get('finding_id', 'unknown')}",
        f"title: {payload.get('title', 'unknown')}",
        f"severity: {payload.get('severity', 'unknown')}",
    ]
    if payload.get("summary"):
        lines.append(f"summary: {payload['summary']}")

    lines.extend(
        [
            "",
            "[deterministic evidence]",
            f"source: {evidence.get('source', 'unknown')}",
            f"rule: {evidence.get('rule_id', 'unknown')}",
            f"analyzer_confidence: {evidence.get('analyzer_confidence', 'unknown')}",
            f"description: {evidence.get('description', '')}",
        ]
    )
    locations = evidence.get("locations") or []
    if locations:
        lines.append("locations:")
        lines.extend(f"  - {_format_location(location)}" for location in locations if isinstance(location, Mapping))
    metadata = evidence.get("metadata") or {}
    if isinstance(metadata, Mapping) and metadata:
        lines.append("metadata:")
        lines.extend(f"  - {key}: {value}" for key, value in sorted(metadata.items()))

    if context:
        lines.extend(
            [
                "",
                "[structure-aware context]",
                f"framework: {context.get('framework', 'unknown')}",
                f"contract: {context.get('focal_contract', 'unknown')}",
                f"source_path: {context.get('source_path', 'unknown')}",
                f"estimated_tokens: {context.get('estimated_tokens', 'unknown')}",
                f"contract_summary: {context.get('contract_summary', '')}",
            ]
        )
        if context.get("focal_function"):
            lines.append(f"focal_function: {context['focal_function']}")
        _append_nested_items(lines, "related_contracts", context.get("related_contracts") or [], ("name", "relationship"))
        _append_nested_items(lines, "risky_external_calls", context.get("risky_external_calls") or [], ("function", "target", "call_type"))
        _append_nested_items(lines, "storage_sensitive_state", context.get("storage_sensitive_state") or [], ("name", "type_name", "storage_sensitive"))
        _append_nested_items(lines, "excerpts", context.get("excerpts") or [], ("path", "reason", "start_line"))

    lines.extend(
        [
            "",
            "[assessment]",
            f"verdict: {assessment.get('verdict', 'suspicious')}",
            f"rationale: {assessment.get('rationale', '')}",
        ]
    )
    for item in assessment.get("next_steps") or []:
        lines.append(f"  - next_step: {item}")

    lines.extend(
        [
            "",
            "[provider reasoning]",
            f"reasoning_summary: {provider_reasoning.get('summary', '')}",
            f"exploitability_verdict: {exploitability.get('verdict', 'insufficient_context')}",
            f"exploitability_rationale: {exploitability.get('rationale', '')}",
        ]
    )
    if finding_reference:
        lines.append(f"finding_reference: {_format_finding_reference(finding_reference)}")

    lines.extend(["", "[exploit hypotheses]"])
    hypotheses = provider_reasoning.get("exploit_hypotheses") or []
    if hypotheses:
        for index, hypothesis in enumerate(hypotheses, start=1):
            if not isinstance(hypothesis, Mapping):
                continue
            lines.append(f"  {index}. {hypothesis.get('title', 'untitled')}: {hypothesis.get('narrative', '')}")
            for precondition in hypothesis.get("preconditions") or []:
                lines.append(f"     - precondition: {precondition}")
            if hypothesis.get("impact"):
                lines.append(f"     - impact: {hypothesis['impact']}")
            for signal in hypothesis.get("supporting_signals") or []:
                lines.append(f"     - signal: {signal}")
            for gap in hypothesis.get("gaps") or []:
                lines.append(f"     - gap: {gap}")
    else:
        lines.append("  - none")

    lines.extend(
        [
            "",
            "[confidence scoring]",
            f"label: {confidence.get('label', 'unknown')}",
            f"score: {confidence.get('score', 'n/a')}",
            f"rationale: {confidence.get('rationale', '')}",
        ]
    )

    lines.extend(["", "[assumptions and caveats]"])
    wrote_context = False
    for item in provider_reasoning.get("assumptions") or []:
        lines.append(f"  - assumption: {item}")
        wrote_context = True
    for item in provider_reasoning.get("caveats") or []:
        lines.append(f"  - caveat: {item}")
        wrote_context = True
    for item in provider_reasoning.get("evidence_references") or []:
        lines.append(f"  - evidence_ref: {item}")
        wrote_context = True
    for item in provider_reasoning.get("remediation_notes") or []:
        lines.append(f"  - remediation_note: {item}")
        wrote_context = True
    if not wrote_context:
        lines.append("  - none")

    lines.extend(
        [
            "",
            "[validation state]",
            f"state: {validation.get('state', 'unknown')}",
            f"summary: {validation.get('summary', '')}",
        ]
    )
    for item in validation.get("evidence") or []:
        lines.append(f"  - evidence: {item}")
    return "\n".join(lines)


def _float_or_none(value: object) -> float | None:
    if value in {None, ""}:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _append_nested_items(
    lines: list[str],
    label: str,
    items: list[object],
    keys: tuple[str, ...],
) -> None:
    rendered = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        values = [f"{key}={item[key]}" for key in keys if key in item and item[key] not in {None, "", ()}]
        if values:
            rendered.append("; ".join(values))
    if rendered:
        lines.append(f"{label}:")
        lines.extend(f"  - {value}" for value in rendered)


def _format_location(location: Mapping[str, Any]) -> str:
    file_path = str(location.get("file_path", "unknown"))
    lines = location.get("lines") or []
    if lines:
        rendered = ",".join(str(line) for line in lines)
        return f"{file_path}:{rendered}"
    start = location.get("start")
    return file_path if start is None else f"{file_path}@{start}"


def _format_finding_reference(reference: Mapping[str, Any]) -> str:
    keys = ("fingerprint", "rule_id", "title", "severity", "analyzer_confidence")
    rendered = [f"{key}={reference[key]}" for key in keys if key in reference and reference[key] not in {None, ""}]
    return "; ".join(rendered) if rendered else "unknown"


def _as_mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}