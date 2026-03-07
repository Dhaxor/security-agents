from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from security_agent.config import resolve_config
from security_agent.context import ContextBudget, StructuredContextPack
from security_agent.llm import (
    PromptAssemblyBudget,
    build_reasoning_prompt,
    normalize_provider_selection,
    reason_about_finding,
)
from security_agent.models.findings import FindingLocation, NormalizedFinding
from security_agent.retrieval import RetrievalContext, RetrievedPattern
from security_agent.schemas import ProviderSelection


def build_context_pack(*, excerpt_multiplier: int = 1) -> StructuredContextPack:
    return StructuredContextPack(
        project_root="sample-project",
        framework="foundry",
        focal_contract="Vault",
        source_path="src/Vault.sol",
        contract_summary=(
            "Vault holds user assets, coordinates outbound transfers, and updates debt accounting after external calls. "
            * excerpt_multiplier
        ),
        finding_focus={
            "contract_name": "Vault",
            "function_name": "withdraw",
            "reason": "Inspect reentrancy around outbound token transfers.",
        },
        imports=("openzeppelin/access/Ownable.sol", "openzeppelin/token/ERC20/utils/SafeERC20.sol"),
        inheritance=("Ownable",),
        related_contracts=(
            {"name": "StrategyVault", "relationship": "finding-related"},
            {"name": "VaultBase", "relationship": "base"},
        ),
        function_summaries=(
            {
                "name": "withdraw",
                "signature": "withdraw(uint256 amount)",
                "summary": "Transfers funds before decrementing totalDebt. " * excerpt_multiplier,
            },
            {
                "name": "setFee",
                "signature": "setFee(uint16 newFeeBps)",
                "summary": "Updates governance fee settings.",
            },
        ),
        modifier_usage=("onlyOwner", "whenNotPaused"),
        risky_external_calls=(
            {
                "function": "withdraw",
                "target": "token",
                "call_type": "interface",
                "expression": "token.safeTransfer(strategy, amount)",
                "summary": "External token transfer before accounting.",
            },
            {
                "function": "withdraw",
                "target": "strategy",
                "call_type": "callback",
                "expression": "strategy.onWithdraw(amount)",
                "summary": "Potential callback-controlled execution.",
            },
        ),
        storage_sensitive_state=(
            {"name": "totalDebt", "type_name": "uint256", "storage_sensitive": True},
            {"name": "paused", "type_name": "bool", "storage_sensitive": True},
        ),
        excerpts=(
            {
                "path": "src/Vault.sol",
                "reason": "withdraw performs an external transfer before totalDebt is updated",
                "start_line": 38,
                "end_line": 47,
                "content": ("token.safeTransfer(strategy, amount);\ntotalDebt -= amount;\n" * excerpt_multiplier),
            },
            {
                "path": "src/Vault.sol",
                "reason": "strategy callback can reenter withdraw",
                "start_line": 52,
                "end_line": 57,
                "content": ("strategy.onWithdraw(amount);\nrequire(!paused);\n" * excerpt_multiplier),
            },
        ),
        budget=ContextBudget(),
        estimated_tokens=240,
    )


def build_finding(*, description_multiplier: int = 1) -> NormalizedFinding:
    return NormalizedFinding(
        fingerprint="finding-1",
        source="slither",
        rule_id="reentrancy-eth",
        title="Reentrancy in withdraw",
        severity="high",
        confidence="medium",
        description=(
            "withdraw performs an external token transfer before totalDebt accounting is updated. "
            * description_multiplier
        ),
        locations=[FindingLocation(file_path="src/Vault.sol", lines=[42])],
        metadata={
            "impact_raw": "High",
            "confidence_raw": "Medium",
            "notes": "callback-controlled receiver can observe stale accounting state. " * description_multiplier,
        },
    )


class StubTransport:
    def __init__(self, *, response: dict | None = None, error: Exception | None = None) -> None:
        self.response = response or {}
        self.error = error
        self.calls: list[dict[str, object]] = []

    def post_json(
        self,
        *,
        url: str,
        headers: dict[str, str],
        payload: dict[str, object],
        timeout_seconds: int,
    ) -> dict[str, object]:
        self.calls.append(
            {
                "url": url,
                "headers": headers,
                "payload": payload,
                "timeout_seconds": timeout_seconds,
            }
        )
        if self.error:
            raise self.error
        return self.response


class LLMTests(unittest.TestCase):
    def test_normalize_provider_selection_supports_aliases(self) -> None:
        selection = normalize_provider_selection(
            ProviderSelection(name="claude", model="claude-3-7-sonnet-latest", api_key_source="")
        )

        self.assertEqual(selection.name, "anthropic")
        self.assertEqual(selection.api_key_source, "env:ANTHROPIC_API_KEY")

    def test_resolve_config_infers_provider_from_model(self) -> None:
        args = SimpleNamespace(
            target=None,
            config=None,
            framework=None,
            provider=None,
            model="claude-3-7-sonnet-latest",
            api_key_source=None,
            output_format="json",
            retrieval_enabled=None,
            retrieval_limit=None,
        )

        with patch("security_agent.config.Path.cwd", return_value=ROOT):
            config = resolve_config(args)

        self.assertEqual(config.provider.name, "anthropic")
        self.assertEqual(config.provider.api_key_source, "env:ANTHROPIC_API_KEY")

    def test_resolve_config_reads_retrieval_settings_from_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / "security-agent.toml"
            config_path.write_text(
                '\n'.join([f'target_path = "{ROOT.as_posix()}"', '[retrieval]', 'enabled = true', 'max_matches = 1']),
                encoding="utf-8",
            )
            args = SimpleNamespace(
                target=None,
                config=str(config_path),
                framework=None,
                provider=None,
                model=None,
                api_key_source=None,
                output_format="json",
                retrieval_enabled=None,
                retrieval_limit=None,
            )

            with patch("security_agent.config.Path.cwd", return_value=ROOT):
                config = resolve_config(args)

        self.assertTrue(config.retrieval.enabled)
        self.assertEqual(config.retrieval.max_matches, 1)

    def test_build_reasoning_prompt_enforces_budget(self) -> None:
        prompt = build_reasoning_prompt(
            build_finding(description_multiplier=8),
            build_context_pack(excerpt_multiplier=8),
            budget=PromptAssemblyBudget(max_total_chars=1800, max_excerpt_chars=120, max_function_summary_chars=100),
        )

        self.assertLessEqual(len(str(prompt.input_payload)), 1800)
        self.assertLessEqual(prompt.estimated_chars, 4000)
        self.assertLessEqual(len(prompt.input_payload["context"]["excerpts"]), 2)

    def test_build_reasoning_prompt_binds_retrieval_context(self) -> None:
        retrieval_context = RetrievalContext(
            store="local-curated-v1",
            matches=[
                RetrievedPattern(
                    pattern_id="reentrancy-state-update-after-call",
                    title="Reentrancy via state update after external interaction",
                    source="local-curated-v1: SWC-107 / CWE-841",
                    summary="External interaction occurs before accounting updates and can expose stale state to callbacks. " * 3,
                    exploit_shape="Callbacks reenter before state writes complete.",
                    score=17,
                    matched_signals=["rule_id:reentrancy-eth", "risk_tag:callback", "term:withdraw"],
                    candidate_test_ideas=["Trigger a callback before debt accounting is updated."],
                    references=["SWC-107"],
                ),
                RetrievedPattern(
                    pattern_id="external-callback-ordering",
                    title="Callback-capable external call before invariant restoration",
                    source="local-curated-v1: ordering-heuristic",
                    summary="Generic ordering issue.",
                    exploit_shape="Generic callback shape.",
                    score=10,
                ),
            ],
        )

        prompt = build_reasoning_prompt(
            build_finding(description_multiplier=2),
            build_context_pack(excerpt_multiplier=2),
            budget=PromptAssemblyBudget(
                max_total_chars=3600,
                max_retrieval_total_chars=900,
                max_retrieval_matches=1,
                max_retrieval_summary_chars=80,
                max_retrieval_signal_chars=24,
                max_retrieval_idea_chars=48,
            ),
            retrieval_context=retrieval_context,
        )

        retrieval_payload = prompt.input_payload["retrieval_context"]
        self.assertEqual(retrieval_payload["store"], "local-curated-v1")
        self.assertEqual(len(retrieval_payload["matches"]), 1)
        self.assertEqual(retrieval_payload["matches"][0]["pattern_id"], "reentrancy-state-update-after-call")
        self.assertLessEqual(len(retrieval_payload["matches"][0]["summary"]), 80)

    def test_openai_reasoning_adapter_parses_shared_shape(self) -> None:
        transport = StubTransport(
            response={
                "choices": [
                    {
                        "message": {
                            "content": '{"summary":"External execution can observe stale debt accounting.","exploitability":{"verdict":"plausible","rationale":"The ordering and callback surface indicate a realistic exploit path."},"exploit_hypotheses":[{"title":"Reenter before debt update","narrative":"A callback can reenter while totalDebt still reflects the old value.","preconditions":["Receiver can execute code during transfer."],"impact":"Assets may be over-withdrawn."}],"confidence":{"label":"high","score":0.87,"rationale":"The deterministic finding matches the bounded context excerpt."},"assumptions":["Receiver code can run during the transfer."],"evidence_references":["Excerpt: transfer before debt update."],"remediation_notes":["Update totalDebt before the transfer."]}'
                        }
                    }
                ]
            }
        )

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-openai-key"}, clear=False):
            result = reason_about_finding(
                ProviderSelection(name="openai", model="gpt-4.1-mini", api_key_source="env:OPENAI_API_KEY"),
                build_finding(),
                build_context_pack(),
                transport=transport,
            )

        self.assertEqual(result.provider_reasoning.exploitability.verdict, "plausible")
        self.assertEqual(result.provider_reasoning.exploit_hypotheses[0].title, "Reenter before debt update")
        self.assertEqual(result.provider_reasoning.confidence.label, "high")
        self.assertIn("Excerpt: transfer before debt update.", result.provider_reasoning.evidence_references)
        self.assertTrue(transport.calls[0]["url"].endswith("/v1/chat/completions"))

    def test_anthropic_reasoning_adapter_parses_shared_shape(self) -> None:
        transport = StubTransport(
            response={
                "content": [
                    {
                        "type": "text",
                        "text": '{"status":"ready","summary":"The provided context suggests callback-controlled reentrancy risk.","exploit_hypotheses":[{"title":"Callback drains vault","narrative":"Token receiver code can reenter before accounting writes complete.","supporting_signals":["Excerpt shows transfer before state write."]}],"confidence":{"label":"medium","score":0.66,"rationale":"The structural context is suggestive but still needs execution validation."},"remediation_hints":["Apply checks-effects-interactions ordering."],"unresolved_questions":["Does the token hook invoke receiver callbacks?"]}'
                    }
                ]
            }
        )

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-anthropic-key"}, clear=False):
            result = reason_about_finding(
                ProviderSelection(name="anthropic", model="claude-3-7-sonnet-latest", api_key_source="env:ANTHROPIC_API_KEY"),
                build_finding(),
                build_context_pack(),
                transport=transport,
            )

        self.assertEqual(result.provider_reasoning.exploitability.verdict, "plausible")
        self.assertEqual(result.provider_reasoning.exploit_hypotheses[0].title, "Callback drains vault")
        self.assertEqual(result.provider_reasoning.confidence.score, 0.66)
        self.assertIn("Does the token hook invoke receiver callbacks?", result.provider_reasoning.caveats)
        self.assertTrue(transport.calls[0]["url"].endswith("/v1/messages"))

    def test_provider_error_returns_safe_structured_fallback(self) -> None:
        transport = StubTransport(error=RuntimeError("provider timed out"))

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-openai-key"}, clear=False):
            result = reason_about_finding(
                ProviderSelection(name="openai", model="gpt-4.1-mini", api_key_source="env:OPENAI_API_KEY"),
                build_finding(),
                build_context_pack(),
                transport=transport,
            )

        self.assertEqual(result.request_status, "request_failed")
        self.assertEqual(result.request_error, "provider timed out")
        self.assertEqual(result.provider_reasoning.summary, "Provider reasoning has not been generated.")
        self.assertEqual(result.provider_reasoning.caveats, [])

    def test_invalid_provider_payload_returns_invalid_response_shape(self) -> None:
        transport = StubTransport(response={"choices": [{"message": {"content": "not-json"}}]})

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-openai-key"}, clear=False):
            result = reason_about_finding(
                ProviderSelection(name="openai", model="gpt-4.1-mini", api_key_source="env:OPENAI_API_KEY"),
                build_finding(),
                build_context_pack(),
                transport=transport,
            )

        self.assertEqual(result.request_status, "invalid_response")
        self.assertIn("Expecting value", result.request_error or "")
        self.assertEqual(result.provider_reasoning.summary, "Provider reasoning has not been generated.")
        self.assertEqual(result.provider_reasoning.caveats, [])


if __name__ == "__main__":
    unittest.main()