from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from .context import StructuredContextPack
from .models.findings import NormalizedFinding

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_-]+")
_DEFAULT_STORE = "local-curated-v1"


@dataclass(frozen=True)
class RetrievalSettings:
    enabled: bool = False
    max_matches: int = 2

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "max_matches": self.max_matches,
        }


@dataclass(frozen=True)
class CuratedPattern:
    pattern_id: str
    title: str
    source: str
    summary: str
    exploit_shape: str
    rule_ids: tuple[str, ...] = ()
    frameworks: tuple[str, ...] = ()
    severities: tuple[str, ...] = ()
    risk_tags: tuple[str, ...] = ()
    signal_terms: tuple[str, ...] = ()
    validation_states: tuple[str, ...] = ()
    guidance: tuple[str, ...] = ()
    candidate_test_ideas: tuple[str, ...] = ()
    references: tuple[str, ...] = ()


@dataclass(slots=True)
class RetrievedPattern:
    pattern_id: str
    title: str
    source: str
    summary: str
    exploit_shape: str
    score: int
    matched_signals: list[str] = field(default_factory=list)
    guidance: list[str] = field(default_factory=list)
    candidate_test_ideas: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "title": self.title,
            "source": self.source,
            "summary": self.summary,
            "exploit_shape": self.exploit_shape,
            "score": self.score,
            "matched_signals": self.matched_signals,
            "guidance": self.guidance,
            "candidate_test_ideas": self.candidate_test_ideas,
            "references": self.references,
        }

    def to_prompt_dict(
        self,
        *,
        max_summary_chars: int,
        max_signal_chars: int,
        max_idea_chars: int,
    ) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "title": self.title,
            "source": self.source,
            "summary": _truncate_text(self.summary, max_summary_chars),
            "exploit_shape": _truncate_text(self.exploit_shape, max_summary_chars),
            "matched_signals": [_truncate_text(item, max_signal_chars) for item in self.matched_signals[:3]],
            "candidate_test_ideas": [_truncate_text(item, max_idea_chars) for item in self.candidate_test_ideas[:2]],
            "references": self.references[:2],
        }


@dataclass(slots=True)
class RetrievalContext:
    store: str
    matches: list[RetrievedPattern] = field(default_factory=list)
    kind: str = "local_curated"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "store": self.store,
            "matches": [match.to_dict() for match in self.matches],
        }

    def to_prompt_payload(
        self,
        *,
        max_matches: int,
        max_total_chars: int,
        max_summary_chars: int,
        max_signal_chars: int,
        max_idea_chars: int,
    ) -> dict[str, Any]:
        payload = {
            "kind": self.kind,
            "store": self.store,
            "matches": [
                match.to_prompt_dict(
                    max_summary_chars=max_summary_chars,
                    max_signal_chars=max_signal_chars,
                    max_idea_chars=max_idea_chars,
                )
                for match in self.matches[:max_matches]
            ],
        }
        while payload["matches"] and len(json.dumps(payload, sort_keys=True)) > max_total_chars:
            payload["matches"] = payload["matches"][:-1]
        return payload


DEFAULT_PATTERNS: tuple[CuratedPattern, ...] = (
    CuratedPattern(
        pattern_id="reentrancy-state-update-after-call",
        title="Reentrancy via state update after external interaction",
        source="local-curated-v1: SWC-107 / CWE-841",
        summary="External interaction occurs before critical accounting or authorization state is finalized, enabling callback-driven reentry.",
        exploit_shape="Attacker-controlled execution reenters before state writes complete and observes stale balances or permissions.",
        rule_ids=("reentrancy-eth", "reentrancy-no-eth", "reentrancy-benign"),
        frameworks=("foundry", "hardhat"),
        severities=("high", "medium"),
        risk_tags=("reentrancy", "external-call", "callback", "state-update-ordering"),
        signal_terms=("reenter", "callback", "withdraw", "transfer", "accounting", "debt"),
        guidance=(
            "Treat retrieved patterns as historical analogies, not proof of exploitability in this repo.",
            "Look for checks-effects-interactions violations around the reported location.",
        ),
        candidate_test_ideas=(
            "Build an attacker-controlled receiver that reenters before the accounting write.",
            "Assert that balances or debt can be manipulated across the callback boundary.",
        ),
        references=("SWC-107", "CWE-841"),
    ),
    CuratedPattern(
        pattern_id="external-callback-ordering",
        title="Callback-capable external call before invariant restoration",
        source="local-curated-v1: ordering-heuristic",
        summary="A callback-capable external call appears before invariants are restored, which often amplifies exploitable control-flow complexity.",
        exploit_shape="External call or hook interrupts the expected state-transition ordering and exposes stale assumptions to attacker-controlled code.",
        frameworks=("foundry", "hardhat"),
        risk_tags=("external-call", "callback", "state-update-ordering"),
        signal_terms=("external", "callback", "transfer", "hook", "state", "accounting"),
        guidance=("Validate whether the callee can invoke user-controlled code before invariant restoration.",),
        candidate_test_ideas=("Exercise the callback path and assert state invariants before and after the external interaction.",),
        references=("checks-effects-interactions",),
    ),
    CuratedPattern(
        pattern_id="unchecked-call-result",
        title="Unchecked external call result",
        source="local-curated-v1: SWC-104 / CWE-252",
        summary="Execution continues after an external call or token transfer without validating the returned success value.",
        exploit_shape="The contract assumes success, leaving accounting or control flow inconsistent when the external action silently fails.",
        rule_ids=("unchecked-transfer", "unchecked-lowlevel", "unchecked-send"),
        frameworks=("foundry", "hardhat"),
        risk_tags=("unchecked-return", "external-call"),
        signal_terms=("unchecked", "return", "success", "bool", "transfer", "call"),
        candidate_test_ideas=("Force the downstream transfer or low-level call to fail and assert that the caller still commits state.",),
        references=("SWC-104", "CWE-252"),
    ),
    CuratedPattern(
        pattern_id="missing-access-control",
        title="Missing or bypassable access control",
        source="local-curated-v1: authorization-baseline",
        summary="A privileged entrypoint lacks strong caller validation or contains an authorization bypass path.",
        exploit_shape="Untrusted callers reach administrative functionality without satisfying ownership or role constraints.",
        frameworks=("foundry", "hardhat"),
        risk_tags=("access-control", "admin", "ownership"),
        signal_terms=("owner", "admin", "authorization", "access", "onlyowner", "role"),
        candidate_test_ideas=("Call the privileged function from an untrusted account and assert the state change still succeeds.",),
        references=("access-control",),
    ),
)


def retrieve_patterns(
    finding: NormalizedFinding,
    context_pack: StructuredContextPack,
    *,
    report: Mapping[str, Any] | None = None,
    settings: RetrievalSettings | None = None,
) -> RetrievalContext | None:
    resolved = settings or RetrievalSettings()
    if not resolved.enabled or resolved.max_matches <= 0:
        return None

    rule_id = finding.rule_id.strip().lower()
    framework = context_pack.framework.strip().lower()
    severity = finding.severity.strip().lower()
    validation_state = _validation_state(report)
    terms = _collect_terms(finding, context_pack, report)
    risk_tags = _collect_risk_tags(finding, context_pack, terms)

    matches: list[RetrievedPattern] = []
    for pattern in DEFAULT_PATTERNS:
        score, reasons = _score_pattern(
            pattern,
            rule_id=rule_id,
            framework=framework,
            severity=severity,
            validation_state=validation_state,
            terms=terms,
            risk_tags=risk_tags,
        )
        if score <= 0:
            continue
        matches.append(
            RetrievedPattern(
                pattern_id=pattern.pattern_id,
                title=pattern.title,
                source=pattern.source,
                summary=pattern.summary,
                exploit_shape=pattern.exploit_shape,
                score=score,
                matched_signals=reasons,
                guidance=list(pattern.guidance),
                candidate_test_ideas=list(pattern.candidate_test_ideas),
                references=list(pattern.references),
            )
        )

    if not matches:
        return None

    matches.sort(key=lambda item: (-item.score, item.pattern_id))
    return RetrievalContext(store=_DEFAULT_STORE, matches=matches[: resolved.max_matches])


def _score_pattern(
    pattern: CuratedPattern,
    *,
    rule_id: str,
    framework: str,
    severity: str,
    validation_state: str | None,
    terms: set[str],
    risk_tags: set[str],
) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    strong_match = False

    pattern_rule_ids = {value.lower() for value in pattern.rule_ids}
    if rule_id and rule_id in pattern_rule_ids:
        score += 8
        strong_match = True
        reasons.append(f"rule_id:{rule_id}")

    pattern_frameworks = {value.lower() for value in pattern.frameworks}
    if framework and framework in pattern_frameworks:
        score += 2
        reasons.append(f"framework:{framework}")

    pattern_severities = {value.lower() for value in pattern.severities}
    if severity and severity in pattern_severities:
        score += 2
        reasons.append(f"severity:{severity}")

    overlapping_tags = sorted(risk_tags & {value.lower() for value in pattern.risk_tags})
    if overlapping_tags:
        strong_match = True
        for tag in overlapping_tags[:3]:
            score += 2
            reasons.append(f"risk_tag:{tag}")

    overlapping_terms = sorted(terms & {value.lower() for value in pattern.signal_terms})
    if overlapping_terms:
        strong_match = True
        for term in overlapping_terms[:4]:
            score += 1
            reasons.append(f"term:{term}")

    pattern_validation_states = {value.lower() for value in pattern.validation_states}
    if validation_state and validation_state in pattern_validation_states:
        strong_match = True
        score += 1
        reasons.append(f"validation:{validation_state}")

    if not strong_match:
        return 0, []
    return score, reasons


def _collect_terms(
    finding: NormalizedFinding,
    context_pack: StructuredContextPack,
    report: Mapping[str, Any] | None,
) -> set[str]:
    terms: set[str] = set()
    values = [
        finding.rule_id,
        finding.title,
        finding.description,
        finding.severity,
        finding.confidence,
        context_pack.framework,
        context_pack.focal_contract,
        context_pack.source_path,
        context_pack.contract_summary,
        context_pack.finding_focus,
        context_pack.risky_external_calls,
        context_pack.storage_sensitive_state,
        context_pack.excerpts,
        finding.metadata,
    ]
    if report:
        values.extend(
            [
                report.get("provider_reasoning"),
                report.get("validation"),
                report.get("structure_context"),
                report.get("deterministic_evidence"),
            ]
        )
    for value in values:
        terms.update(_tokenize(value))
    return terms


def _collect_risk_tags(
    finding: NormalizedFinding,
    context_pack: StructuredContextPack,
    terms: set[str],
) -> set[str]:
    tags: set[str] = set()
    focus = context_pack.finding_focus or {}
    if isinstance(focus, Mapping):
        for item in focus.get("risk_tags") or []:
            if isinstance(item, str) and item.strip():
                tags.add(item.strip().lower())

    rule_id = finding.rule_id.lower()
    if "reentrancy" in rule_id or "reentrancy" in terms:
        tags.add("reentrancy")
    if context_pack.risky_external_calls or {"external", "call", "transfer", "hook"} & terms:
        tags.add("external-call")
    if any(str(item.get("call_type") or "").lower() == "callback" for item in context_pack.risky_external_calls) or "callback" in terms:
        tags.add("callback")
    if context_pack.storage_sensitive_state or {"state", "accounting", "debt", "balance"} & terms:
        tags.add("state-update-ordering")
    if {"unchecked", "return", "success"} & terms:
        tags.add("unchecked-return")
    if {"owner", "admin", "authorization", "access", "onlyowner", "role"} & terms:
        tags.add("access-control")
    return tags


def _validation_state(report: Mapping[str, Any] | None) -> str | None:
    if not report:
        return None
    validation = report.get("validation")
    if not isinstance(validation, Mapping):
        return None
    value = str(validation.get("state") or "").strip().lower()
    return value or None


def _tokenize(value: object) -> set[str]:
    if value is None or value == "":
        return set()
    if isinstance(value, Mapping):
        terms: set[str] = set()
        for item in value.values():
            terms.update(_tokenize(item))
        return terms
    if isinstance(value, (list, tuple, set)):
        terms: set[str] = set()
        for item in value:
            terms.update(_tokenize(item))
        return terms
    return set(_TOKEN_RE.findall(str(value).lower()))


def _truncate_text(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    return value[: max_chars - 3].rstrip() + "..."