from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from security_agent.context import ContextBudget, StructuredContextPack
from security_agent.models.findings import FindingLocation, NormalizedFinding
from security_agent.reports import build_finding_report
from security_agent.retrieval import RetrievalSettings, retrieve_patterns


def build_context_pack(*, external_calls: bool = True, reentrancy_hints: bool = True) -> StructuredContextPack:
    return StructuredContextPack(
        project_root="sample-project",
        framework="foundry",
        focal_contract="Vault" if reentrancy_hints else "Notes",
        source_path="src/Vault.sol" if reentrancy_hints else "src/Note.sol",
        contract_summary=(
            "Vault transfers funds before accounting is restored."
            if reentrancy_hints
            else "Repository note used for neutral context coverage."
        ),
        finding_focus=(
            {"contract_name": "Vault", "function_name": "withdraw", "risk_tags": ["reentrancy"]}
            if reentrancy_hints
            else {"contract_name": "Notes", "function_name": "annotate", "risk_tags": []}
        ),
        imports=(),
        inheritance=(),
        related_contracts=(),
        function_summaries=(),
        modifier_usage=(),
        risky_external_calls=(({"function": "withdraw", "target": "receiver", "call_type": "callback"},) if external_calls else ()),
        storage_sensitive_state=(({"name": "totalDebt", "type_name": "uint256", "storage_sensitive": True},) if external_calls else ()),
        excerpts=(
            ({"path": "src/Vault.sol", "reason": "callback before accounting update", "start_line": 42},)
            if external_calls
            else ()
        ),
        budget=ContextBudget(),
        estimated_tokens=144,
    )


class RetrievalTests(unittest.TestCase):
    def test_retrieve_patterns_ranks_exact_rule_match_first(self) -> None:
        finding = NormalizedFinding(
            fingerprint="finding-1",
            source="slither",
            rule_id="reentrancy-eth",
            title="Reentrancy in withdraw",
            severity="high",
            confidence="medium",
            description="withdraw performs an external transfer before debt accounting is updated and a callback can reenter.",
            locations=[FindingLocation(file_path="src/Vault.sol", lines=[42])],
        )
        context_pack = build_context_pack()
        report = build_finding_report(finding, context_pack=context_pack).to_dict()

        retrieval = retrieve_patterns(
            finding,
            context_pack,
            report=report,
            settings=RetrievalSettings(enabled=True, max_matches=2),
        )

        self.assertIsNotNone(retrieval)
        assert retrieval is not None
        self.assertEqual(retrieval.matches[0].pattern_id, "reentrancy-state-update-after-call")
        self.assertGreaterEqual(len(retrieval.matches), 2)
        self.assertGreater(retrieval.matches[0].score, retrieval.matches[1].score)
        self.assertIn("rule_id:reentrancy-eth", retrieval.matches[0].matched_signals)

    def test_retrieve_patterns_returns_none_when_disabled(self) -> None:
        finding = NormalizedFinding(
            fingerprint="finding-1",
            source="slither",
            rule_id="reentrancy-eth",
            title="Reentrancy in withdraw",
            severity="high",
            confidence="medium",
            description="External call before accounting update.",
            locations=[FindingLocation(file_path="src/Vault.sol", lines=[42])],
        )

        retrieval = retrieve_patterns(
            finding,
            build_context_pack(),
            settings=RetrievalSettings(enabled=False, max_matches=2),
        )

        self.assertIsNone(retrieval)

    def test_retrieve_patterns_returns_none_for_no_match(self) -> None:
        finding = NormalizedFinding(
            fingerprint="finding-1",
            source="slither",
            rule_id="custom-invariant",
            title="Invariant note",
            severity="low",
            confidence="low",
            description="Style-only observation without exploitability cues.",
            locations=[FindingLocation(file_path="src/Note.sol", lines=[12])],
        )

        retrieval = retrieve_patterns(
            finding,
            build_context_pack(external_calls=False, reentrancy_hints=False),
            settings=RetrievalSettings(enabled=True, max_matches=2),
        )

        self.assertIsNone(retrieval)


if __name__ == "__main__":
    unittest.main()