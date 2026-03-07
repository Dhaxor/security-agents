from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol

from .context import StructuredContextPack
from .models.findings import NormalizedFinding
from .retrieval import RetrievalContext
from .reports import (
    ConfidenceScore,
    ExploitHypothesis,
    ExploitabilityAssessment,
    ProviderReasoningResult,
)
from .schemas import ProviderSelection

_PROVIDER_ALIASES = {
    "anthropic": "anthropic",
    "claude": "anthropic",
    "openai": "openai",
    "gpt": "openai",
}
_ANTHROPIC_MODEL_PREFIXES = ("claude-",)
_OPENAI_MODEL_PREFIXES = ("gpt-", "chatgpt-", "o1", "o3", "o4")
_DEFAULT_TIMEOUT_SECONDS = 30
_DEFAULT_MAX_OUTPUT_TOKENS = 1200


@dataclass(frozen=True)
class PromptAssemblyBudget:
    max_total_chars: int = 6400
    max_retrieval_total_chars: int = 1200
    max_retrieval_matches: int = 2
    max_retrieval_summary_chars: int = 220
    max_retrieval_signal_chars: int = 120
    max_retrieval_idea_chars: int = 180
    max_locations: int = 4
    max_imports: int = 6
    max_related_contracts: int = 6
    max_functions: int = 6
    max_external_calls: int = 6
    max_state_variables: int = 6
    max_excerpts: int = 3
    max_description_chars: int = 900
    max_metadata_chars: int = 600
    max_contract_summary_chars: int = 280
    max_function_summary_chars: int = 180
    max_excerpt_chars: int = 260


@dataclass(slots=True)
class ReasoningPrompt:
    system_prompt: str
    user_prompt: str
    input_payload: dict[str, Any]
    response_contract: dict[str, Any]
    estimated_chars: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "system_prompt": self.system_prompt,
            "user_prompt": self.user_prompt,
            "input_payload": self.input_payload,
            "response_contract": self.response_contract,
            "estimated_chars": self.estimated_chars,
        }


@dataclass(slots=True)
class ReasoningResult:
    provider: ProviderSelection
    provider_reasoning: ProviderReasoningResult
    prompt: ReasoningPrompt
    request_status: str = "success"
    request_error: str | None = None
    raw_response: dict[str, Any] | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider.to_dict(),
            "provider_reasoning": self.provider_reasoning.to_dict(),
            "prompt": self.prompt.to_dict(),
            "request_status": self.request_status,
            "request_error": self.request_error,
            "raw_response": self.raw_response,
            "warnings": self.warnings,
        }


class LLMTransport(Protocol):
    def post_json(
        self,
        *,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
        timeout_seconds: int,
    ) -> dict[str, Any]: ...


class UrlLibTransport:
    def post_json(
        self,
        *,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
        timeout_seconds: int,
    ) -> dict[str, Any]:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={**headers, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:  # pragma: no cover - exercised through provider fallback tests
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code} from provider: {detail}") from exc

        decoded = json.loads(body)
        if not isinstance(decoded, dict):
            raise ValueError("Provider response must decode to a JSON object.")
        return decoded


def canonical_provider_name(provider_name: str) -> str:
    normalized = provider_name.strip().lower()
    if normalized not in _PROVIDER_ALIASES:
        raise ValueError("Provider must be one of: anthropic/claude or openai/gpt.")
    return _PROVIDER_ALIASES[normalized]


def infer_provider_name_from_model(model_name: str) -> str | None:
    model = model_name.strip().lower()
    if model.startswith(_ANTHROPIC_MODEL_PREFIXES):
        return "anthropic"
    if model.startswith(_OPENAI_MODEL_PREFIXES):
        return "openai"
    return None


def default_api_key_source(provider_name: str) -> str:
    provider = canonical_provider_name(provider_name)
    if provider == "anthropic":
        return "env:ANTHROPIC_API_KEY"
    return "env:OPENAI_API_KEY"


def normalize_provider_selection(selection: ProviderSelection) -> ProviderSelection:
    model = selection.model.strip()
    if not model:
        raise ValueError("Model identifier is required.")

    provider_name = selection.name.strip() if selection.name else ""
    provider = canonical_provider_name(provider_name) if provider_name else infer_provider_name_from_model(model) or "openai"
    if provider == "anthropic" and not model.lower().startswith(_ANTHROPIC_MODEL_PREFIXES):
        raise ValueError("Anthropic provider requires a Claude-family model identifier.")
    if provider == "openai" and not model.lower().startswith(_OPENAI_MODEL_PREFIXES):
        raise ValueError("OpenAI provider requires a GPT- or OpenAI reasoning-family model identifier.")

    api_key_source = selection.api_key_source.strip() if selection.api_key_source else default_api_key_source(provider)
    return ProviderSelection(name=provider, model=model, api_key_source=api_key_source)


def build_reasoning_prompt(
    finding: NormalizedFinding,
    context_pack: StructuredContextPack,
    *,
    budget: PromptAssemblyBudget | None = None,
    retrieval_context: RetrievalContext | None = None,
) -> ReasoningPrompt:
    assembly_budget = budget or PromptAssemblyBudget()
    payload = _assemble_prompt_input(finding, context_pack, assembly_budget, retrieval_context)
    response_contract = {
        "summary": "Short exploit-oriented assessment grounded in the supplied evidence and context.",
        "exploitability": {
            "verdict": "plausible",
            "rationale": "Why the finding appears exploitable or why context is still insufficient.",
        },
        "exploit_hypotheses": [
            {
                "title": "Concise exploit path title",
                "narrative": "Why the issue looks exploitable from the supplied evidence.",
                "preconditions": ["Required runtime condition or assumption."],
                "impact": "Potential impact if the hypothesis is correct.",
                "supporting_signals": ["Specific signal from the finding or context bundle."],
                "gaps": ["Important uncertainty that still needs validation."],
            }
        ],
        "confidence": {
            "label": "low",
            "score": 0.25,
            "rationale": "Why the current confidence level is appropriate.",
        },
        "assumptions": ["Assumption needed for the exploit path to hold."],
        "caveats": ["Uncertainty or blocker that limits certainty."],
        "evidence_references": ["Specific evidence pointer from the bounded context bundle."],
        "remediation_notes": ["Actionable mitigation suggestion."],
    }
    system_prompt = (
        "You are investigating one normalized smart-contract security finding as a potential exploit path. Use only the "
        "supplied deterministic evidence and bounded structure-aware context. If a retrieval_context block is present, "
        "treat it as attributed historical analogy only, not as proof about the current repository. Keep confirmed "
        "evidence separate from hypotheses, do not invent missing code paths, and return JSON only using the requested contract."
    )
    user_prompt = (
        "Return a single JSON object matching this contract:\n"
        f"{json.dumps(response_contract, indent=2, sort_keys=True)}\n\n"
        "Investigate this normalized finding, bounded structure-aware context, and optional retrieval sidecar:\n"
        f"{json.dumps(payload, indent=2, sort_keys=True)}"
    )
    estimated_chars = len(system_prompt) + len(user_prompt)
    return ReasoningPrompt(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        input_payload=payload,
        response_contract=response_contract,
        estimated_chars=estimated_chars,
    )


def parse_provider_reasoning_output(
    raw_content: str | dict[str, Any],
    finding: NormalizedFinding,
) -> ProviderReasoningResult:
    payload = raw_content if isinstance(raw_content, dict) else json.loads(raw_content)
    if not isinstance(payload, dict):
        raise ValueError("Reasoning payload must be a JSON object.")

    exploitability = payload.get("exploitability") or {}
    exploitability_data = exploitability if isinstance(exploitability, dict) else {}
    confidence = payload.get("confidence") or {}
    confidence_data = confidence if isinstance(confidence, dict) else {}
    supporting_factors = _string_list(confidence_data.get("supporting_factors"))
    dampening_factors = _string_list(confidence_data.get("dampening_factors"))
    hypotheses: list[ExploitHypothesis] = []
    for item in payload.get("exploit_hypotheses") or []:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "").strip()
        narrative = str(item.get("narrative") or "").strip()
        if not title and not narrative:
            continue
        hypotheses.append(
            ExploitHypothesis(
                title=title or "Untitled hypothesis",
                narrative=narrative,
                preconditions=_string_list(item.get("preconditions")),
                impact=str(item.get("impact") or ""),
                supporting_signals=_string_list(item.get("supporting_signals")),
                gaps=_string_list(item.get("gaps")),
            )
        )

    verdict = str(exploitability_data.get("verdict") or _legacy_exploitability_verdict(payload, hypotheses))
    rationale = str(exploitability_data.get("rationale") or payload.get("summary") or "No exploitability rationale was returned.")

    return ProviderReasoningResult(
        finding_reference=ProviderReasoningResult.pending(finding).finding_reference,
        summary=str(payload.get("summary") or "No reasoning summary was returned."),
        exploitability=ExploitabilityAssessment(verdict=verdict, rationale=rationale),
        exploit_hypotheses=hypotheses,
        confidence=ConfidenceScore(
            label=str(confidence_data.get("label") or "unscored"),
            score=_float_or_none(confidence_data.get("score")),
            rationale=str(confidence_data.get("rationale") or "No confidence rationale was returned."),
        ),
        assumptions=_dedupe(_string_list(payload.get("assumptions"))),
        caveats=_dedupe(_string_list(payload.get("caveats")) + _string_list(payload.get("unresolved_questions")) + dampening_factors),
        evidence_references=_dedupe(_string_list(payload.get("evidence_references")) + supporting_factors),
        remediation_notes=_dedupe(_string_list(payload.get("remediation_notes")) + _string_list(payload.get("remediation_hints"))),
    )


def build_reasoning_provider(
    selection: ProviderSelection,
    *,
    transport: LLMTransport | None = None,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> "BaseReasoningProvider":
    normalized = normalize_provider_selection(selection)
    provider_class = AnthropicReasoningProvider if normalized.name == "anthropic" else OpenAIReasoningProvider
    return provider_class(normalized, transport=transport, timeout_seconds=timeout_seconds)


def reason_about_finding(
    selection: ProviderSelection,
    finding: NormalizedFinding,
    context_pack: StructuredContextPack,
    *,
    transport: LLMTransport | None = None,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    budget: PromptAssemblyBudget | None = None,
    retrieval_context: RetrievalContext | None = None,
) -> ReasoningResult:
    provider = build_reasoning_provider(selection, transport=transport, timeout_seconds=timeout_seconds)
    return provider.reason_about_finding(finding, context_pack, budget=budget, retrieval_context=retrieval_context)


class BaseReasoningProvider:
    endpoint: str

    def __init__(
        self,
        selection: ProviderSelection,
        *,
        transport: LLMTransport | None = None,
        timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.selection = selection
        self._transport = transport or UrlLibTransport()
        self._timeout_seconds = timeout_seconds

    def reason_about_finding(
        self,
        finding: NormalizedFinding,
        context_pack: StructuredContextPack,
        *,
        budget: PromptAssemblyBudget | None = None,
        retrieval_context: RetrievalContext | None = None,
    ) -> ReasoningResult:
        prompt = build_reasoning_prompt(finding, context_pack, budget=budget, retrieval_context=retrieval_context)
        try:
            response = self._transport.post_json(
                url=self.endpoint,
                headers=self._headers(),
                payload=self._request_payload(prompt),
                timeout_seconds=self._timeout_seconds,
            )
        except Exception as exc:
            return ReasoningResult(
                provider=self.selection,
                provider_reasoning=ProviderReasoningResult.pending(finding),
                prompt=prompt,
                request_status="request_failed",
                request_error=str(exc),
                warnings=[str(exc)],
            )

        try:
            provider_reasoning = parse_provider_reasoning_output(self._response_text(response), finding)
        except Exception as exc:
            return ReasoningResult(
                provider=self.selection,
                provider_reasoning=ProviderReasoningResult.pending(finding),
                prompt=prompt,
                request_status="invalid_response",
                request_error=str(exc),
                raw_response=response,
                warnings=[str(exc)],
            )
        return ReasoningResult(
            provider=self.selection,
            provider_reasoning=provider_reasoning,
            prompt=prompt,
            raw_response=response,
        )

    def _headers(self) -> dict[str, str]:
        raise NotImplementedError

    def _request_payload(self, prompt: ReasoningPrompt) -> dict[str, Any]:
        raise NotImplementedError

    def _response_text(self, response: dict[str, Any]) -> str:
        raise NotImplementedError


class AnthropicReasoningProvider(BaseReasoningProvider):
    endpoint = "https://api.anthropic.com/v1/messages"

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": _resolve_api_key(self.selection.api_key_source),
            "anthropic-version": "2023-06-01",
        }

    def _request_payload(self, prompt: ReasoningPrompt) -> dict[str, Any]:
        return {
            "model": self.selection.model,
            "max_tokens": _DEFAULT_MAX_OUTPUT_TOKENS,
            "temperature": 0,
            "system": prompt.system_prompt,
            "messages": [{"role": "user", "content": prompt.user_prompt}],
        }

    def _response_text(self, response: dict[str, Any]) -> str:
        return _flatten_text_blocks(response.get("content"))


class OpenAIReasoningProvider(BaseReasoningProvider):
    endpoint = "https://api.openai.com/v1/chat/completions"

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {_resolve_api_key(self.selection.api_key_source)}"}

    def _request_payload(self, prompt: ReasoningPrompt) -> dict[str, Any]:
        return {
            "model": self.selection.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": prompt.system_prompt},
                {"role": "user", "content": prompt.user_prompt},
            ],
        }

    def _response_text(self, response: dict[str, Any]) -> str:
        choices = response.get("choices") or []
        if not choices or not isinstance(choices[0], dict):
            raise ValueError("OpenAI response did not include any choices.")
        message = choices[0].get("message") or {}
        if not isinstance(message, dict):
            raise ValueError("OpenAI response message was not an object.")
        return _flatten_text_blocks(message.get("content"))


def _assemble_prompt_input(
    finding: NormalizedFinding,
    context_pack: StructuredContextPack,
    budget: PromptAssemblyBudget,
    retrieval_context: RetrievalContext | None,
) -> dict[str, Any]:
    payload = {
        "finding": {
            "fingerprint": finding.fingerprint,
            "source": finding.source,
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "description": _truncate_text(finding.description, budget.max_description_chars),
            "locations": [location.to_dict() for location in finding.locations[: budget.max_locations]],
            "metadata": _truncate_json_value(finding.metadata, budget.max_metadata_chars),
        },
        "context": {
            "project_root": context_pack.project_root,
            "framework": context_pack.framework,
            "focal_contract": context_pack.focal_contract,
            "source_path": context_pack.source_path,
            "contract_summary": _truncate_text(context_pack.contract_summary, budget.max_contract_summary_chars),
            "finding_focus": context_pack.finding_focus,
            "imports": list(context_pack.imports[: budget.max_imports]),
            "inheritance": list(context_pack.inheritance),
            "related_contracts": [dict(item) for item in context_pack.related_contracts[: budget.max_related_contracts]],
            "function_summaries": [
                _truncate_json_value(dict(item), budget.max_function_summary_chars)
                for item in context_pack.function_summaries[: budget.max_functions]
            ],
            "modifier_usage": list(context_pack.modifier_usage),
            "risky_external_calls": [
                _truncate_json_value(dict(item), budget.max_function_summary_chars)
                for item in context_pack.risky_external_calls[: budget.max_external_calls]
            ],
            "storage_sensitive_state": [
                _truncate_json_value(dict(item), budget.max_function_summary_chars)
                for item in context_pack.storage_sensitive_state[: budget.max_state_variables]
            ],
            "excerpts": [
                _truncate_json_value(dict(item), budget.max_excerpt_chars)
                for item in context_pack.excerpts[: budget.max_excerpts]
            ],
            "estimated_tokens": context_pack.estimated_tokens,
        },
    }
    if retrieval_context is not None:
        retrieval_payload = retrieval_context.to_prompt_payload(
            max_matches=budget.max_retrieval_matches,
            max_total_chars=budget.max_retrieval_total_chars,
            max_summary_chars=budget.max_retrieval_summary_chars,
            max_signal_chars=budget.max_retrieval_signal_chars,
            max_idea_chars=budget.max_retrieval_idea_chars,
        )
        if retrieval_payload.get("matches"):
            payload["retrieval_context"] = retrieval_payload
    return _trim_prompt_payload(payload, budget.max_total_chars)


def _trim_prompt_payload(payload: dict[str, Any], max_total_chars: int) -> dict[str, Any]:
    trimmed = json.loads(json.dumps(payload))
    while len(json.dumps(trimmed, sort_keys=True)) > max_total_chars:
        context = trimmed.get("context") or {}
        for key in (
            "excerpts",
            "risky_external_calls",
            "function_summaries",
            "storage_sensitive_state",
            "related_contracts",
            "imports",
            "inheritance",
            "modifier_usage",
        ):
            if _shrink_list_field(context, key):
                break
        else:
            retrieval_context = trimmed.get("retrieval_context") or {}
            if _shrink_retrieval_matches(retrieval_context):
                if not retrieval_context.get("matches"):
                    trimmed.pop("retrieval_context", None)
                continue

            metadata = trimmed["finding"].get("metadata") or {}
            if metadata:
                trimmed["finding"]["metadata"] = {}
                continue

            description = trimmed["finding"].get("description") or ""
            if len(description) > 160:
                trimmed["finding"]["description"] = _truncate_text(description, len(description) - 120)
                continue

            contract_summary = context.get("contract_summary") or ""
            if len(contract_summary) > 120:
                context["contract_summary"] = _truncate_text(contract_summary, len(contract_summary) - 80)
                continue
            break
    return trimmed


def _resolve_api_key(source: str) -> str:
    descriptor = source.strip()
    if not descriptor.startswith("env:"):
        raise ValueError("Only env:VAR API key descriptors are supported by the shared provider abstraction.")
    env_var = descriptor.partition(":")[2]
    value = os.getenv(env_var)
    if not value:
        raise ValueError(f"Environment variable is not set for API key source: {env_var}")
    return value


def _flatten_text_blocks(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
                continue
            if not isinstance(item, dict):
                continue
            text = item.get("text")
            if isinstance(text, str):
                parts.append(text)
        if parts:
            return "\n".join(parts)
    raise ValueError("Provider response did not include any textual content to parse.")


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _shrink_list_field(container: dict[str, Any], key: str) -> bool:
    items = container.get(key)
    if not isinstance(items, list) or not items:
        return False
    container[key] = items[:-1]
    return True


def _shrink_retrieval_matches(container: dict[str, Any]) -> bool:
    return _shrink_list_field(container, "matches")


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def _legacy_exploitability_verdict(
    payload: dict[str, Any],
    hypotheses: list[ExploitHypothesis],
) -> str:
    status = str(payload.get("status") or "").strip().lower()
    if status in {"provider_error", "invalid_response", "insufficient_context"}:
        return "insufficient_context"
    if status in {"unlikely", "not_exploitable"}:
        return "unlikely"
    if hypotheses:
        return "plausible"
    return "inconclusive"


def _float_or_none(value: object) -> float | None:
    if value in {None, ""}:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _truncate_json_value(value: Any, max_chars: int) -> Any:
    if isinstance(value, str):
        return _truncate_text(value, max_chars)
    if isinstance(value, list):
        return [_truncate_json_value(item, max_chars) for item in value]
    if isinstance(value, tuple):
        return [_truncate_json_value(item, max_chars) for item in value]
    if isinstance(value, dict):
        return {str(key): _truncate_json_value(item, max_chars) for key, item in value.items()}
    return value


def _truncate_text(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    return value[: max_chars - 3].rstrip() + "..."