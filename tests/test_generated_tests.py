from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from security_agent.context import ContextBudget, StructuredContextPack
from security_agent.generated_tests import execute_generated_test, generate_candidate_test
from security_agent.ingestion import ingest_repository
from security_agent.models.findings import FindingLocation, NormalizedFinding
from security_agent.reports import (
    ConfidenceScore,
    ExploitHypothesis,
    ExploitabilityAssessment,
    FindingReference,
    ProviderReasoningResult,
    build_finding_report,
)


def build_context_pack(
    framework: str,
    source_path: str,
    focal_contract: str,
    *,
    focus_function_name: str = "withdraw",
    focus_signature: str | None = None,
    focus_modifiers: tuple[str, ...] = (),
    modifier_usage: tuple[str, ...] = (),
    storage_targets: tuple[tuple[str, str], ...] = (("totalDebt", "uint256"),),
    imports: tuple[str, ...] = (),
    related_contracts: tuple[dict[str, str], ...] = (),
    supporting_function_summaries: tuple[dict[str, object], ...] = (),
) -> StructuredContextPack:
    default_supporting_summaries = supporting_function_summaries or (
        {
            "name": "deposit",
            "signature": "deposit()",
            "visibility": "external",
            "state_mutability": "payable",
            "summary": "deposit() seeds contract state for later withdrawals.",
            "modifiers": (),
            "reads": (),
            "writes": tuple(name for name, _ in storage_targets),
            "external_call_count": 0,
        },
    )
    return StructuredContextPack(
        project_root="sample-project",
        framework=framework,
        focal_contract=focal_contract,
        source_path=source_path,
        contract_summary=f"{focal_contract} exposes an externally callable withdrawal path.",
        finding_focus={"contract_name": focal_contract, "function_name": focus_function_name},
        imports=imports,
        inheritance=(),
        related_contracts=related_contracts,
        function_summaries=(*default_supporting_summaries,
            {
                "name": focus_function_name,
                "signature": focus_signature or f"{focus_function_name}()",
                "visibility": "external",
                "state_mutability": "nonpayable",
                "summary": f"{focus_function_name} reaches a suspicious external interaction.",
                "modifiers": focus_modifiers,
                "reads": tuple(name for name, _ in storage_targets),
                "writes": tuple(name for name, _ in storage_targets),
                "external_call_count": 1,
            },),
        modifier_usage=modifier_usage or focus_modifiers,
        risky_external_calls=(
            {
                "function": focus_function_name,
                "target": "receiver",
                "call_type": "call",
                "expression": 'receiver.call{value: amount}("")',
            },
        ),
        storage_sensitive_state=tuple(
            {"name": name, "type_name": type_name, "storage_sensitive": True}
            for name, type_name in storage_targets
        ),
        excerpts=({"path": source_path, "reason": "external call before accounting", "start_line": 42},),
        budget=ContextBudget(),
        estimated_tokens=160,
    )


def build_report(
    framework: str,
    source_path: str,
    focal_contract: str,
    *,
    rule_id: str = "reentrancy-eth",
    title: str = "Reentrancy in withdraw",
    description: str = "withdraw performs an external call before debt accounting is updated.",
    hypothesis_title: str = "Reenter before debt update",
    hypothesis_narrative: str = "A malicious receiver can reenter before the accounting write occurs.",
    focus_function_name: str = "withdraw",
    focus_signature: str | None = None,
    focus_modifiers: tuple[str, ...] = (),
    modifier_usage: tuple[str, ...] = (),
    storage_targets: tuple[tuple[str, str], ...] = (("totalDebt", "uint256"),),
    imports: tuple[str, ...] = (),
    related_contracts: tuple[dict[str, str], ...] = (),
    supporting_function_summaries: tuple[dict[str, object], ...] = (),
):
    finding = NormalizedFinding(
        fingerprint=f"{framework}-finding-1",
        source="slither",
        rule_id=rule_id,
        title=title,
        severity="high",
        confidence="medium",
        description=description,
        locations=[FindingLocation(file_path=source_path, lines=[42])],
    )
    return build_finding_report(
        finding,
        context_pack=build_context_pack(
            framework,
            source_path,
            focal_contract,
            focus_function_name=focus_function_name,
            focus_signature=focus_signature,
            focus_modifiers=focus_modifiers,
            modifier_usage=modifier_usage,
            storage_targets=storage_targets,
            imports=imports,
            related_contracts=related_contracts,
            supporting_function_summaries=supporting_function_summaries,
        ),
        provider_reasoning=ProviderReasoningResult(
            finding_reference=FindingReference.from_finding(finding),
            summary="Callback-controlled execution may observe stale accounting.",
            exploitability=ExploitabilityAssessment(
                verdict="plausible",
                rationale="The ordering indicates a classic reentrancy window.",
            ),
            exploit_hypotheses=[
                ExploitHypothesis(
                    title=hypothesis_title,
                    narrative=hypothesis_narrative,
                    preconditions=["The attacker must be able to trigger the withdrawal path with non-zero balance."],
                    impact="The attacker drains more value than intended before state is restored.",
                )
            ],
            confidence=ConfidenceScore(label="high", score=0.86, rationale="The signal is strong."),
            evidence_references=[f"{source_path}:42"],
        ),
    )


class GeneratedTestArtifactTests(unittest.TestCase):
    def test_foundry_generation_writes_candidate_contract_and_metadata(self) -> None:
        manifest = ingest_repository(ROOT / "examples/foundry-sample")
        report = build_report("foundry", "src/Vault.sol", "Vault")

        with tempfile.TemporaryDirectory() as tmp_dir:
            artifact = generate_candidate_test(manifest, report, output_dir=tmp_dir)

            self.assertEqual(artifact.framework, "foundry")
            self.assertEqual(artifact.selected_mode, "exploit")
            self.assertEqual(artifact.strategy, "reentrancy_validation_candidate")
            self.assertEqual(artifact.validation_plan.scenario, "multi_transaction_reentrancy")
            self.assertTrue(artifact.validation_plan.requires_attacker_harness)
            self.assertEqual(artifact.validation_plan.entry_signature, "withdraw()")
            self.assertIn("attacker-receiver", artifact.validation_plan.actor_roles)
            self.assertIn("deposit()", "\n".join(artifact.validation_plan.setup_steps))
            self.assertIn("fuzz", artifact.validation_plan.modes)
            self.assertIn("sequence-variants", artifact.validation_plan.modes)
            self.assertIn("balance-accounting", artifact.validation_plan.domain_signals)
            self.assertTrue(artifact.validation_plan.sequence_variants)
            self.assertTrue(artifact.validation_plan.fuzz_inputs)
            self.assertTrue(artifact.validation_plan.symbolic_adapters)
            self.assertTrue(Path(artifact.test_path).is_file())
            self.assertTrue(Path(artifact.report_path).is_file())
            self.assertTrue(Path(artifact.metadata_path).is_file())
            contract_text = Path(artifact.test_path).read_text(encoding="utf-8")
            self.assertIn("pragma solidity", contract_text)
            self.assertIn("report_path", contract_text)
            self.assertIn("AttackerHarness", contract_text)
            self.assertIn("testExploitSequence", contract_text)
            self.assertIn("testInvariantCandidate", contract_text)
            self.assertIn("testFuzzCandidate", contract_text)
            self.assertIn("function _boundCandidateAmount", contract_text)
            self.assertIn("function _candidateInvariantHashes", contract_text)
            self.assertIn("function _candidateEntryCalldata", contract_text)
            self.assertIn("function _candidateSetupCalldatas", contract_text)
            self.assertIn('require(boundedAmount > 0, "expected bounded fuzz amount")', contract_text)
            self.assertIn('require(invariantHashes.length > 0, "expected invariant candidates")', contract_text)
            self.assertIn("attack sequence", contract_text)
            self.assertIn("entrypoint: withdraw()", contract_text)
            self.assertIn("sequence variants", contract_text)
            self.assertIn("optional symbolic adapters", contract_text)
            metadata = json.loads(Path(artifact.metadata_path).read_text(encoding="utf-8"))
            self.assertEqual(metadata["provenance"]["finding_reference"]["fingerprint"], "foundry-finding-1")
            self.assertEqual(metadata["provenance"]["assessment_verdict"], "high_confidence")
            self.assertEqual(metadata["validation_plan"]["scenario"], "multi_transaction_reentrancy")
            self.assertEqual(metadata["selected_mode"], "exploit")
            self.assertIn("fuzz", metadata["validation_plan"]["modes"])
            self.assertEqual(metadata["runner_hint"]["command"][:3], ["forge", "test", "--match-path"])
            self.assertEqual(metadata["runner_hint"]["command"][-2:], ["--match-test", "testExploitSequenceReentrancyInWithdraw"])

    def test_generation_records_retrieval_attribution_in_metadata(self) -> None:
        manifest = ingest_repository(ROOT / "examples/foundry-sample")
        report = build_report("foundry", "src/Vault.sol", "Vault")
        retrieval = {
            "kind": "local_curated",
            "store": "local-curated-v1",
            "matches": [
                {
                    "pattern_id": "reentrancy-state-update-after-call",
                    "source": "local-curated-v1: SWC-107 / CWE-841",
                    "summary": "External interaction occurs before accounting updates.",
                    "candidate_test_ideas": [
                        "Build an attacker-controlled receiver that reenters before the accounting write."
                    ],
                    "guidance": ["Treat retrieved patterns as historical analogies, not proof."],
                    "references": ["SWC-107"],
                }
            ],
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            artifact = generate_candidate_test(manifest, report, output_dir=tmp_dir, retrieval=retrieval)

            metadata = json.loads(Path(artifact.metadata_path).read_text(encoding="utf-8"))
            self.assertEqual(metadata["provenance"]["retrieval"]["store"], "local-curated-v1")
            self.assertEqual(
                metadata["provenance"]["retrieval"]["matches"][0]["pattern_id"],
                "reentrancy-state-update-after-call",
            )
            self.assertIn(
                "Build an attacker-controlled receiver that reenters before the accounting write.",
                metadata["validation_plan"]["attack_steps"],
            )

    @patch("security_agent.generated_tests.subprocess.run")
    def test_foundry_execution_updates_report_and_metadata(self, mock_run) -> None:
        manifest = ingest_repository(ROOT / "examples/foundry-sample")
        report = build_report("foundry", "src/Vault.sol", "Vault")
        mock_run.return_value = SimpleNamespace(returncode=0, stdout="Ran 1 test", stderr="")

        with tempfile.TemporaryDirectory() as tmp_dir:
            artifact = generate_candidate_test(manifest, report, output_dir=tmp_dir)
            executed_artifact, executed_report = execute_generated_test(artifact, report=report)

            self.assertEqual(executed_artifact.execution.state, "reproduced")
            self.assertEqual(executed_report["validation"]["state"], "reproduced")
            self.assertEqual(executed_report["assessment"]["verdict"], "verified")
            self.assertTrue(Path(executed_artifact.execution.result_path).is_file())
            self.assertTrue(Path(executed_artifact.execution.stdout_path).is_file())
            metadata = json.loads(Path(executed_artifact.metadata_path).read_text(encoding="utf-8"))
            self.assertEqual(metadata["execution"]["state"], "reproduced")
            updated_report = json.loads(Path(executed_artifact.report_path).read_text(encoding="utf-8"))
            self.assertEqual(updated_report["validation"]["state"], "reproduced")
            self.assertIn("execution_result_path:", "\n".join(updated_report["validation"]["evidence"]))
            self.assertIn("selected_mode: exploit", "\n".join(updated_report["validation"]["evidence"]))

    def test_hardhat_generation_writes_candidate_script_and_metadata(self) -> None:
        manifest = ingest_repository(ROOT / "examples/hardhat-sample")
        report = build_report("hardhat", "contracts/Vault.sol", "Vault")

        with tempfile.TemporaryDirectory() as tmp_dir:
            artifact = generate_candidate_test(manifest, report, output_dir=tmp_dir)

            self.assertEqual(artifact.framework, "hardhat")
            self.assertEqual(artifact.selected_mode, "exploit")
            self.assertEqual(artifact.validation_plan.scenario, "multi_transaction_reentrancy")
            self.assertTrue(Path(artifact.test_path).is_file())
            script_text = Path(artifact.test_path).read_text(encoding="utf-8")
            self.assertIn("describe(", script_text)
            self.assertIn('const assert = require("assert").strict;', script_text)
            self.assertIn("const validationPlan =", script_text)
            self.assertIn("const sequenceVariants =", script_text)
            self.assertIn("function normalizeFuzzAmount", script_text)
            self.assertIn("function candidateInvariantChecks", script_text)
            self.assertIn("function buildCandidateEntryCall", script_text)
            self.assertIn("function buildCandidateSetupCalls", script_text)
            self.assertIn("const fuzzSeeds = buildCandidateFuzzSeeds();", script_text)
            self.assertIn("const invariantChecks = candidateInvariantChecks();", script_text)
            self.assertIn("runExploitSequence", script_text)
            self.assertIn("tracks invariant candidate behavior", script_text)
            self.assertIn("explores bounded fuzz inputs", script_text)
            self.assertIn("covers candidate multi-transaction sequence variants", script_text)
            self.assertIn("assert.ok(true", script_text)
            metadata = json.loads(Path(artifact.metadata_path).read_text(encoding="utf-8"))
            self.assertEqual(metadata["language"], "javascript")
            self.assertEqual(metadata["runner_hint"]["command"][:3], ["npx", "hardhat", "test"])
            self.assertEqual(metadata["runner_hint"]["command"][4], "--grep")
            self.assertEqual(metadata["runner_hint"]["command"][5], "runs exploit candidate sequence for Reentrancy in withdraw")

    def test_foundry_invariant_mode_targets_invariant_function(self) -> None:
        manifest = ingest_repository(ROOT / "examples/foundry-sample")
        report = build_report("foundry", "src/Vault.sol", "Vault")

        with tempfile.TemporaryDirectory() as tmp_dir:
            artifact = generate_candidate_test(manifest, report, output_dir=tmp_dir, selected_mode="invariant")

            self.assertEqual(artifact.selected_mode, "invariant")
            self.assertTrue(artifact.output_directory.endswith("/invariant") or artifact.output_directory.endswith("\\invariant"))
            self.assertEqual(artifact.runner_hint.command[-2:], ["--match-test", "testInvariantCandidateReentrancyInWithdraw"])
            contract_text = Path(artifact.test_path).read_text(encoding="utf-8")
            self.assertIn("bytes32[] memory invariantHashes = _candidateInvariantHashes();", contract_text)

    def test_hardhat_fuzz_mode_targets_fuzz_case(self) -> None:
        manifest = ingest_repository(ROOT / "examples/hardhat-sample")
        report = build_report("hardhat", "contracts/Vault.sol", "Vault")

        with tempfile.TemporaryDirectory() as tmp_dir:
            artifact = generate_candidate_test(manifest, report, output_dir=tmp_dir, selected_mode="fuzz")

            self.assertEqual(artifact.selected_mode, "fuzz")
            self.assertEqual(artifact.runner_hint.command[:3], ["npx", "hardhat", "test"])
            self.assertEqual(artifact.runner_hint.command[4], "--grep")
            self.assertEqual(artifact.runner_hint.command[5], "explores bounded fuzz inputs for Reentrancy in withdraw")
            script_text = Path(artifact.test_path).read_text(encoding="utf-8")
            self.assertIn("for (const seed of fuzzSeeds)", script_text)

    def test_parameterized_signatures_produce_concrete_call_hints(self) -> None:
        manifest = ingest_repository(ROOT / "examples/foundry-sample")
        report = build_report(
            "foundry",
            "src/Vault.sol",
            "Vault",
            focus_signature="withdraw(uint256 amount, address recipient)",
            supporting_function_summaries=(
                {
                    "name": "deposit",
                    "signature": "deposit(uint256 assets)",
                    "visibility": "external",
                    "state_mutability": "payable",
                    "summary": "deposit(uint256 assets) seeds contract state for later withdrawals.",
                    "modifiers": (),
                    "reads": (),
                    "writes": ("totalDebt",),
                    "external_call_count": 0,
                },
            ),
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            artifact = generate_candidate_test(manifest, report, output_dir=tmp_dir)

            self.assertEqual(artifact.validation_plan.entry_call["canonical_signature"], "withdraw(uint256,address)")
            self.assertEqual([item["name"] for item in artifact.validation_plan.entry_call["args"]], ["amount", "recipient"])
            self.assertEqual(artifact.validation_plan.setup_calls[0]["canonical_signature"], "deposit(uint256)")
            contract_text = Path(artifact.test_path).read_text(encoding="utf-8")
            self.assertIn('abi.encodeWithSignature("withdraw(uint256,address)"', contract_text)
            self.assertIn('abi.encodeWithSignature("deposit(uint256)"', contract_text)

    def test_non_reentrancy_findings_get_strategy_specific_validation_plan(self) -> None:
        manifest = ingest_repository(ROOT / "examples/hardhat-sample")
        report = build_report(
            "hardhat",
            "contracts/Admin.sol",
            "Admin",
            rule_id="access-control",
            title="Missing access control",
            description="setOwner can be reached without enforcing caller authorization.",
            hypothesis_title="Unauthorized caller reaches admin path",
            hypothesis_narrative="An untrusted account can invoke the privileged function without the intended role check.",
            focus_function_name="setOwner",
            focus_signature="setOwner(address newOwner)",
            focus_modifiers=("onlyOwner",),
            modifier_usage=("onlyOwner",),
            storage_targets=(("owner", "address"),),
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            artifact = generate_candidate_test(manifest, report, output_dir=tmp_dir)

            self.assertEqual(artifact.validation_plan.scenario, "unauthorized_access_validation")
            self.assertFalse(artifact.validation_plan.requires_attacker_harness)
            self.assertTrue(artifact.validation_plan.multi_transaction)
            self.assertEqual(artifact.validation_plan.entry_signature, "setOwner(address newOwner)")
            self.assertIn("privileged-admin", artifact.validation_plan.actor_roles)
            self.assertIn("authorization", artifact.validation_plan.domain_signals)
            self.assertIn("untrusted account", "\n".join(artifact.validation_plan.attack_steps))

    def test_differential_targets_and_symbolic_availability_are_recorded(self) -> None:
        manifest = ingest_repository(ROOT / "examples/foundry-sample")
        report = build_report(
            "foundry",
            "src/Vault.sol",
            "Vault",
            imports=("./VaultReference.sol",),
            related_contracts=({"name": "VaultLegacy"},),
        )

        with patch("security_agent.generated_tests.shutil.which", side_effect=lambda name: "/usr/bin/halmos" if name == "halmos" else None):
            with tempfile.TemporaryDirectory() as tmp_dir:
                artifact = generate_candidate_test(manifest, report, output_dir=tmp_dir)

        self.assertIn("VaultReference", artifact.validation_plan.differential_targets)
        self.assertIn("differential", artifact.validation_plan.modes)
        self.assertTrue(any(item["name"] == "halmos" and item["available"] for item in artifact.validation_plan.symbolic_adapters))

    @patch("security_agent.generated_tests.subprocess.run")
    def test_hardhat_execution_failure_maps_to_not_reproduced(self, mock_run) -> None:
        manifest = ingest_repository(ROOT / "examples/hardhat-sample")
        report = build_report("hardhat", "contracts/Vault.sol", "Vault")
        mock_run.return_value = SimpleNamespace(returncode=1, stdout="  1 failing", stderr="AssertionError: expected true to equal false")

        with tempfile.TemporaryDirectory() as tmp_dir:
            artifact = generate_candidate_test(manifest, report, output_dir=tmp_dir)
            executed_artifact, executed_report = execute_generated_test(artifact, report=report)

            self.assertEqual(executed_artifact.execution.state, "not_reproduced")
            self.assertEqual(executed_report["validation"]["state"], "not_reproduced")
            self.assertEqual(executed_report["assessment"]["verdict"], "not_reproduced")
            self.assertEqual(executed_artifact.execution.return_code, 1)

    @patch("security_agent.generated_tests.subprocess.run")
    def test_hardhat_zero_tests_run_maps_to_inconclusive(self, mock_run) -> None:
        manifest = ingest_repository(ROOT / "examples/hardhat-sample")
        report = build_report("hardhat", "contracts/Vault.sol", "Vault")
        mock_run.return_value = SimpleNamespace(returncode=0, stdout="\n  0 passing (1ms)\n", stderr="")

        with tempfile.TemporaryDirectory() as tmp_dir:
            artifact = generate_candidate_test(manifest, report, output_dir=tmp_dir)
            executed_artifact, executed_report = execute_generated_test(artifact, report=report)

            self.assertEqual(executed_artifact.execution.state, "inconclusive")
            self.assertEqual(executed_report["validation"]["state"], "inconclusive")
            self.assertEqual(executed_report["assessment"]["verdict"], "inconclusive")

    @patch("security_agent.generated_tests.subprocess.run", side_effect=FileNotFoundError(2, "No such file or directory", "forge"))
    def test_missing_runner_is_recorded_as_environment_limitation(self, _mock_run) -> None:
        manifest = ingest_repository(ROOT / "examples/foundry-sample")
        report = build_report("foundry", "src/Vault.sol", "Vault")

        with tempfile.TemporaryDirectory() as tmp_dir:
            artifact = generate_candidate_test(manifest, report, output_dir=tmp_dir)
            executed_artifact, executed_report = execute_generated_test(artifact, report=report)

            self.assertEqual(executed_artifact.execution.state, "inconclusive")
            self.assertIsNotNone(executed_artifact.execution.environment_limitation)
            self.assertEqual(executed_report["validation"]["state"], "inconclusive")
            self.assertEqual(executed_report["assessment"]["verdict"], "inconclusive")
            self.assertIn("environment_limitation:", "\n".join(executed_report["validation"]["evidence"]))


if __name__ == "__main__":
    unittest.main()