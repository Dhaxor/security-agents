from __future__ import annotations

import unittest
from pathlib import Path

from security_agent.cli import _build_investigation_context_pack
from security_agent.context import build_finding_context_from_source
from security_agent.ingestion import ingest_repository
from security_agent.models.findings import FindingLocation, NormalizedFinding

ROOT = Path(__file__).resolve().parents[1]


class SourceAwareContextTests(unittest.TestCase):
    def test_source_aware_context_extracts_function_and_state_details(self) -> None:
        manifest = ingest_repository(ROOT / "tests/fixtures/foundry_reentrancy")
        finding = NormalizedFinding(
            fingerprint="vault-withdraw-reentrancy",
            source="slither",
            rule_id="reentrancy-eth",
            title="Reentrancy in withdraw",
            severity="high",
            confidence="medium",
            description="withdraw makes an external call before clearing balances.",
            locations=[FindingLocation(file_path="src/Vault.sol", lines=[13])],
        )

        pack = build_finding_context_from_source(manifest, finding)

        assert pack is not None
        self.assertEqual(pack.focal_contract, "Vault")
        self.assertEqual(pack.finding_focus["function_name"], "withdraw")
        self.assertIn("deposit()", [item["signature"] for item in pack.function_summaries])
        self.assertIn("withdraw()", [item["signature"] for item in pack.function_summaries])
        self.assertIn("balances", [item["name"] for item in pack.storage_sensitive_state])
        self.assertEqual(pack.risky_external_calls[0]["target"], "msg.sender")
        self.assertIn("call", pack.risky_external_calls[0]["expression"])
        self.assertTrue(any("Primary deterministic analyzer location" in item["reason"] for item in pack.excerpts))

    def test_cli_context_builder_prefers_source_aware_context(self) -> None:
        manifest = ingest_repository(ROOT / "tests/fixtures/foundry_reentrancy")
        finding = NormalizedFinding(
            fingerprint="vault-withdraw-reentrancy",
            source="slither",
            rule_id="reentrancy-eth",
            title="Reentrancy in withdraw",
            severity="high",
            confidence="medium",
            description="withdraw makes an external call before clearing balances.",
            locations=[FindingLocation(file_path="src/Vault.sol", lines=[13])],
        )

        pack = _build_investigation_context_pack(manifest, finding)

        self.assertEqual(pack.focal_contract, "Vault")
        self.assertTrue(pack.function_summaries)
        self.assertEqual(pack.function_summaries[0]["name"], "withdraw")
        self.assertTrue(pack.estimated_tokens > 0)


if __name__ == "__main__":
    unittest.main()