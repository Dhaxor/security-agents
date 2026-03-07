from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from security_agent.context import ContextBudget, StructuredContextPack
from security_agent.models.findings import FindingLocation, NormalizedFinding
from security_agent.reports import (
    ConfidenceScore,
    ExploitHypothesis,
    ExploitabilityAssessment,
    FindingReference,
    ProviderReasoningResult,
    ValidationState,
    build_finding_report,
    render_report_text,
)


def build_context_pack() -> StructuredContextPack:
    return StructuredContextPack(
        project_root="sample-project",
        framework="foundry",
        focal_contract="Vault",
        source_path="src/Vault.sol",
        contract_summary="Vault holds assets and updates debt after outbound transfers.",
        finding_focus={
            "contract_name": "Vault",
            "function_name": "withdraw",
            "reason": "Inspect transfer ordering around debt accounting.",
        },
        imports=("openzeppelin/access/Ownable.sol",),
        inheritance=("Ownable",),
        related_contracts=({"name": "StrategyVault", "relationship": "finding-related"},),
        function_summaries=(
            {"name": "withdraw", "signature": "withdraw(uint256 amount)", "summary": "Transfers assets out."},
        ),
        modifier_usage=("onlyOwner",),
        risky_external_calls=(
            {"function": "withdraw", "target": "token", "call_type": "interface"},
        ),
        storage_sensitive_state=(
            {"name": "totalDebt", "type_name": "uint256", "storage_sensitive": True},
        ),
        excerpts=(
            {"path": "src/Vault.sol", "reason": "external call before accounting", "start_line": 38},
        ),
        budget=ContextBudget(),
        estimated_tokens=192,
    )


def build_finding() -> NormalizedFinding:
    return NormalizedFinding(
        fingerprint="finding-1",
        source="slither",
        rule_id="reentrancy-eth",
        title="Reentrancy in withdraw",
        severity="high",
        confidence="medium",
        description="withdraw performs an external call before debt accounting is updated.",
        locations=[FindingLocation(file_path="src/Vault.sol", lines=[42])],
        metadata={"impact_raw": "High", "confidence_raw": "Medium"},
    )


class ReportTests(unittest.TestCase):
    def test_build_finding_report_serializes_expected_sections(self) -> None:
        finding = build_finding()
        report = build_finding_report(
            finding,
            context_pack=build_context_pack(),
            provider_reasoning=ProviderReasoningResult(
                finding_reference=FindingReference.from_finding(finding),
                summary="The ordering permits a callback before the accounting write.",
                exploitability=ExploitabilityAssessment(
                    verdict="likely_exploitable",
                    rationale="The external call precedes the debt write, which makes callback reentry plausible.",
                ),
                exploit_hypotheses=[
                    ExploitHypothesis(
                        title="Callback reentry drains funds",
                        narrative="A malicious receiver can reenter while the vault still reports the old debt.",
                        preconditions=["Outbound transfer reaches attacker-controlled code."],
                        impact="Assets may be over-withdrawn.",
                        supporting_signals=["The excerpt places the transfer before totalDebt -= amount."],
                    )
                ],
                confidence=ConfidenceScore(
                    label="high",
                    score=0.88,
                    rationale="Deterministic evidence and focused context align on a known exploit pattern.",
                ),
                assumptions=["Outbound transfer reaches attacker-controlled code."],
                caveats=["No runtime reproduction yet."],
                evidence_references=["Excerpt shows token transfer before totalDebt -= amount."],
                remediation_notes=["Move debt accounting before the external transfer."],
            ),
            validation=ValidationState(
                state="not_run",
                summary="Framework execution is intentionally deferred for this wave.",
                evidence=["No generated tests or runner outputs are attached."],
            ),
        )

        payload = report.to_dict()
        self.assertEqual(payload["finding_id"], "finding-1")
        self.assertEqual(payload["deterministic_evidence"]["rule_id"], "reentrancy-eth")
        self.assertEqual(payload["structure_context"]["focal_function"], "withdraw")
        self.assertEqual(payload["provider_reasoning"]["exploit_hypotheses"][0]["title"], "Callback reentry drains funds")
        self.assertEqual(payload["provider_reasoning"]["confidence"]["label"], "high")
        self.assertEqual(payload["provider_reasoning"]["exploitability"]["verdict"], "likely_exploitable")
        self.assertEqual(payload["assessment"]["verdict"], "high_confidence")
        self.assertEqual(
            set(payload["provider_reasoning"]),
            {
                "finding_reference",
                "summary",
                "exploitability",
                "exploit_hypotheses",
                "confidence",
                "assumptions",
                "caveats",
                "evidence_references",
                "remediation_notes",
            },
        )
        self.assertEqual(
            set(payload["provider_reasoning"]["finding_reference"]),
            {"fingerprint", "rule_id", "title", "severity", "analyzer_confidence"},
        )
        self.assertEqual(set(payload["provider_reasoning"]["exploitability"]), {"verdict", "rationale"})
        self.assertEqual(set(payload["provider_reasoning"]["confidence"]), {"label", "score", "rationale"})
        self.assertEqual(
            set(payload["provider_reasoning"]["exploit_hypotheses"][0]),
            {"title", "narrative", "preconditions", "impact", "supporting_signals", "gaps"},
        )
        self.assertNotIn("provider", payload["provider_reasoning"])
        self.assertNotIn("prompt", payload["provider_reasoning"])
        self.assertNotIn("raw_response", payload["provider_reasoning"])
        self.assertNotIn("warnings", payload["provider_reasoning"])
        self.assertNotIn("status", payload["provider_reasoning"])
        self.assertEqual(payload["validation"]["state"], "not_run")

    def test_render_report_text_separates_reasoning_and_validation(self) -> None:
        report = build_finding_report(build_finding(), context_pack=build_context_pack())

        rendered = render_report_text(report)

        self.assertIn("[deterministic evidence]", rendered)
        self.assertIn("[structure-aware context]", rendered)
        self.assertIn("[assessment]", rendered)
        self.assertIn("[provider reasoning]", rendered)
        self.assertIn("[exploit hypotheses]", rendered)
        self.assertIn("[confidence scoring]", rendered)
        self.assertIn("[assumptions and caveats]", rendered)
        self.assertIn("[validation state]", rendered)
        self.assertIn("verdict: suspicious", rendered)
        self.assertIn("exploitability_verdict: insufficient_context", rendered)
        self.assertIn("state: not_run", rendered)


if __name__ == "__main__":
    unittest.main()