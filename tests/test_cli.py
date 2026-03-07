from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

sys.path.insert(0, str(ROOT / "src"))

from security_agent.cli import _render_text, _result_for_explain, _result_for_generate_tests, _result_for_scan
from security_agent.context import ContextBudget, StructuredContextPack
from security_agent.generated_tests import ExecutionResult
from security_agent.llm import ReasoningPrompt, ReasoningResult
from security_agent.models.findings import FindingLocation, NormalizedFinding
from security_agent.config import ResolvedConfig
from security_agent.retrieval import RetrievalSettings
from security_agent.reports import (
    ConfidenceScore,
    ExploitHypothesis,
    ExploitabilityAssessment,
    FindingReference,
    ProviderReasoningResult,
    ValidationState,
    build_finding_report,
)
from security_agent.schemas import CommandResult, ProviderSelection


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "security_agent", *args],
        cwd=ROOT,
        env=ENV,
        text=True,
        capture_output=True,
        check=False,
    )


class CLITests(unittest.TestCase):
    MISSING_SLITHER_ERROR = "[Errno 2] No such file or directory: 'slither'"

    def test_help_lists_commands(self) -> None:
        result = run_cli("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("scan", result.stdout)
        self.assertIn("investigate", result.stdout)
        self.assertIn("generate-tests", result.stdout)

    def test_scan_autodetects_foundry(self) -> None:
        result = run_cli("scan", "--target", "examples/foundry-sample", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["manifest"]["framework"], "foundry")
        self.assertIn("src/Counter.sol", payload["manifest"]["source_files"])
        self.assertEqual(payload["data"]["analysis"]["slither"]["tool"], "slither")

    def test_scan_autodetects_hardhat(self) -> None:
        result = run_cli("scan", "--target", "examples/hardhat-sample", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["manifest"]["framework"], "hardhat")
        self.assertIn("contracts/Counter.sol", payload["manifest"]["source_files"])
        self.assertIsInstance(payload["data"]["findings"], list)

    @patch("security_agent.cli.run_slither", side_effect=FileNotFoundError(MISSING_SLITHER_ERROR))
    def test_scan_missing_slither_uses_stable_unavailable_payload(self, _mock_run_slither) -> None:
        result = _result_for_scan(
            ResolvedConfig(
                target_path=ROOT / "examples/foundry-sample",
                framework_override=None,
                provider=ProviderSelection(
                    name="openai",
                    model="gpt-4.1-mini",
                    api_key_source="env:OPENAI_API_KEY",
                ),
                output_format="json",
                config_path=None,
            )
        )

        slither = result.data["analysis"]["slither"]
        self.assertEqual(
            set(slither),
            {
                "tool",
                "command",
                "target_path",
                "return_code",
                "success",
                "error",
                "stdout",
                "stderr",
                "raw_output",
                "findings",
                "status",
            },
        )
        self.assertEqual(slither["tool"], "slither")
        self.assertEqual(slither["command"], [])
        self.assertTrue(str(slither["target_path"]).endswith("examples/foundry-sample"))
        self.assertIsNone(slither["return_code"])
        self.assertFalse(slither["success"])
        self.assertEqual(slither["status"], "unavailable")
        self.assertEqual(slither["stdout"], "")
        self.assertEqual(slither["stderr"], "")
        self.assertIsNone(slither["raw_output"])
        self.assertEqual(slither["findings"], [])
        self.assertEqual(slither["error"], self.MISSING_SLITHER_ERROR)
        self.assertEqual(result.data["findings"], [])
        self.assertIn(
            "Slither is not installed or not on PATH; scan output contains only ingestion metadata.",
            result.warnings,
        )

    def test_config_file_sets_provider_and_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / "security-agent.toml"
            config_path.write_text(
                "\n".join(
                    [
                        f'target_path = "{(ROOT / "examples/hardhat-sample").as_posix()}"',
                        'framework = "hardhat"',
                        '[provider]',
                        'name = "anthropic"',
                        'model = "claude-3-7-sonnet-latest"',
                    ]
                ),
                encoding="utf-8",
            )
            result = run_cli("scan", "--config", str(config_path), "--format", "json")

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["provider"]["name"], "anthropic")
        self.assertEqual(payload["manifest"]["framework"], "hardhat")

    def test_generate_tests_help_lists_output_dir_option(self) -> None:
        result = run_cli("generate-tests", "--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--output-dir", result.stdout)
        self.assertIn("--finding-id", result.stdout)
        self.assertIn("--mode", result.stdout)

    def test_explain_help_lists_retrieval_options(self) -> None:
        result = run_cli("explain", "--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--enable-retrieval", result.stdout)
        self.assertIn("--retrieval-limit", result.stdout)

    @patch("security_agent.cli.reason_about_finding")
    @patch("security_agent.cli.run_slither")
    def test_explain_builds_report_and_reasoning_wrapper(self, mock_run_slither, mock_reason_about_finding) -> None:
        finding = NormalizedFinding(
            fingerprint="finding-1",
            source="slither",
            rule_id="reentrancy-eth",
            title="Reentrancy in withdraw",
            severity="high",
            confidence="medium",
            description="withdraw performs an external call before debt accounting is updated.",
            locations=[FindingLocation(file_path="src/Vault.sol", lines=[42])],
        )
        mock_run_slither.return_value = SimpleNamespace(findings=[finding])
        mock_reason_about_finding.return_value = ReasoningResult(
            provider=ProviderSelection(name="openai", model="gpt-4.1-mini", api_key_source="env:OPENAI_API_KEY"),
            provider_reasoning=ProviderReasoningResult(
                finding_reference=FindingReference.from_finding(finding),
                summary="Callback-controlled execution may observe stale accounting.",
                exploitability=ExploitabilityAssessment(
                    verdict="plausible",
                    rationale="The deterministic finding indicates a classic ordering issue.",
                ),
                exploit_hypotheses=[
                    ExploitHypothesis(
                        title="Reenter before debt update",
                        narrative="A malicious callback can reenter before totalDebt is updated.",
                    )
                ],
                confidence=ConfidenceScore(label="high", score=0.86, rationale="The signal is strong."),
                evidence_references=["src/Vault.sol:42"],
            ),
            prompt=ReasoningPrompt(
                system_prompt="system",
                user_prompt="user",
                input_payload={"finding": {"fingerprint": "finding-1"}},
                response_contract={"summary": "..."},
                estimated_chars=128,
            ),
        )

        result = _result_for_explain(
            SimpleNamespace(finding_id=None),
            ResolvedConfig(
                target_path=ROOT / "examples/foundry-sample",
                framework_override=None,
                provider=ProviderSelection(
                    name="openai",
                    model="gpt-4.1-mini",
                    api_key_source="env:OPENAI_API_KEY",
                ),
                output_format="json",
                config_path=None,
            ),
        )

        self.assertEqual(result.data["finding_id"], "finding-1")
        self.assertEqual(result.command, "investigate")
        self.assertEqual(result.data["report"]["provider_reasoning"]["summary"], "Callback-controlled execution may observe stale accounting.")
        self.assertEqual(result.data["report"]["assessment"]["verdict"], "high_confidence")
        self.assertEqual(result.data["reasoning_result"]["request_status"], "success")
        self.assertEqual(result.data["reasoning_result"]["provider_reasoning"]["exploitability"]["verdict"], "plausible")
        self.assertEqual(mock_reason_about_finding.call_args.args[0].name, "openai")
        self.assertEqual(mock_reason_about_finding.call_args.args[1].fingerprint, "finding-1")
        self.assertEqual(mock_reason_about_finding.call_args.args[2].focal_contract, "Vault")

    @patch("security_agent.cli.reason_about_finding")
    @patch("security_agent.cli.run_slither")
    def test_explain_attaches_retrieval_sidecar_when_enabled(self, mock_run_slither, mock_reason_about_finding) -> None:
        finding = NormalizedFinding(
            fingerprint="finding-1",
            source="slither",
            rule_id="reentrancy-eth",
            title="Reentrancy in withdraw",
            severity="high",
            confidence="medium",
            description="withdraw performs an external call before debt accounting is updated.",
            locations=[FindingLocation(file_path="src/Vault.sol", lines=[42])],
        )
        mock_run_slither.return_value = SimpleNamespace(findings=[finding])
        mock_reason_about_finding.return_value = ReasoningResult(
            provider=ProviderSelection(name="openai", model="gpt-4.1-mini", api_key_source="env:OPENAI_API_KEY"),
            provider_reasoning=ProviderReasoningResult.pending(finding),
            prompt=ReasoningPrompt(
                system_prompt="system",
                user_prompt="user",
                input_payload={},
                response_contract={},
                estimated_chars=0,
            ),
        )

        result = _result_for_explain(
            SimpleNamespace(finding_id=None),
            ResolvedConfig(
                target_path=ROOT / "examples/foundry-sample",
                framework_override=None,
                provider=ProviderSelection(
                    name="openai",
                    model="gpt-4.1-mini",
                    api_key_source="env:OPENAI_API_KEY",
                ),
                output_format="json",
                config_path=None,
                retrieval=RetrievalSettings(enabled=True, max_matches=1),
            ),
        )

        self.assertIn("retrieval", result.data)
        self.assertEqual(result.data["retrieval"]["matches"][0]["pattern_id"], "reentrancy-state-update-after-call")
        self.assertNotIn("retrieval", result.data["report"])
        self.assertIsNotNone(mock_reason_about_finding.call_args.kwargs["retrieval_context"])

    @patch("security_agent.cli.reason_about_finding")
    @patch("security_agent.cli.run_slither")
    def test_explain_warns_when_defaulting_to_first_finding(self, mock_run_slither, mock_reason_about_finding) -> None:
        findings = [
            NormalizedFinding(
                fingerprint="finding-1",
                source="slither",
                rule_id="reentrancy-eth",
                title="Reentrancy in withdraw",
                severity="high",
                confidence="medium",
                description="First finding.",
                locations=[FindingLocation(file_path="src/Vault.sol", lines=[42])],
            ),
            NormalizedFinding(
                fingerprint="finding-2",
                source="slither",
                rule_id="unchecked-transfer",
                title="Unchecked transfer",
                severity="low",
                confidence="high",
                description="Second finding.",
                locations=[FindingLocation(file_path="src/Vault.sol", lines=[55])],
            ),
        ]
        mock_run_slither.return_value = SimpleNamespace(findings=findings)
        mock_reason_about_finding.return_value = ReasoningResult(
            provider=ProviderSelection(name="openai", model="gpt-4.1-mini", api_key_source="env:OPENAI_API_KEY"),
            provider_reasoning=ProviderReasoningResult.pending(findings[0]),
            prompt=ReasoningPrompt(
                system_prompt="system",
                user_prompt="user",
                input_payload={},
                response_contract={},
                estimated_chars=0,
            ),
            request_status="request_failed",
            request_error="missing API key",
        )

        result = _result_for_explain(
            SimpleNamespace(finding_id=None),
            ResolvedConfig(
                target_path=ROOT / "examples/foundry-sample",
                framework_override=None,
                provider=ProviderSelection(
                    name="openai",
                    model="gpt-4.1-mini",
                    api_key_source="env:OPENAI_API_KEY",
                ),
                output_format="json",
                config_path=None,
            ),
        )

        self.assertIn("defaulted to the first normalized finding", result.warnings[0])
        self.assertIn("request_failed", result.warnings[1])
        self.assertEqual(result.data["reasoning_result"]["request_error"], "missing API key")

    @patch("security_agent.cli.reason_about_finding")
    @patch("security_agent.cli.run_slither")
    def test_explain_omits_retrieval_payload_when_no_match(self, mock_run_slither, mock_reason_about_finding) -> None:
        finding = NormalizedFinding(
            fingerprint="finding-1",
            source="slither",
            rule_id="custom-invariant",
            title="Invariant note",
            severity="low",
            confidence="low",
            description="Style-only observation without exploitability signals.",
            locations=[FindingLocation(file_path="src/Note.sol", lines=[12])],
        )
        mock_run_slither.return_value = SimpleNamespace(findings=[finding])
        mock_reason_about_finding.return_value = ReasoningResult(
            provider=ProviderSelection(name="openai", model="gpt-4.1-mini", api_key_source="env:OPENAI_API_KEY"),
            provider_reasoning=ProviderReasoningResult.pending(finding),
            prompt=ReasoningPrompt(
                system_prompt="system",
                user_prompt="user",
                input_payload={},
                response_contract={},
                estimated_chars=0,
            ),
        )

        result = _result_for_explain(
            SimpleNamespace(finding_id=None),
            ResolvedConfig(
                target_path=ROOT / "examples/foundry-sample",
                framework_override=None,
                provider=ProviderSelection(
                    name="openai",
                    model="gpt-4.1-mini",
                    api_key_source="env:OPENAI_API_KEY",
                ),
                output_format="json",
                config_path=None,
                retrieval=RetrievalSettings(enabled=True, max_matches=2),
            ),
        )

        self.assertNotIn("retrieval", result.data)
        self.assertIsNone(mock_reason_about_finding.call_args.kwargs["retrieval_context"])

    @patch("security_agent.cli.run_slither")
    def test_explain_rejects_unknown_finding_id(self, mock_run_slither) -> None:
        mock_run_slither.return_value = SimpleNamespace(
            findings=[
                NormalizedFinding(
                    fingerprint="finding-1",
                    source="slither",
                    rule_id="reentrancy-eth",
                    title="Reentrancy in withdraw",
                    severity="high",
                    confidence="medium",
                    description="Only finding.",
                    locations=[FindingLocation(file_path="src/Vault.sol", lines=[42])],
                )
            ]
        )

        with self.assertRaisesRegex(ValueError, "Available finding ids: finding-1"):
            _result_for_explain(
                SimpleNamespace(finding_id="missing-finding"),
                ResolvedConfig(
                    target_path=ROOT / "examples/foundry-sample",
                    framework_override=None,
                    provider=ProviderSelection(
                        name="openai",
                        model="gpt-4.1-mini",
                        api_key_source="env:OPENAI_API_KEY",
                    ),
                    output_format="json",
                    config_path=None,
                ),
            )

    @patch("security_agent.cli.execute_generated_test")
    @patch("security_agent.cli.reason_about_finding")
    @patch("security_agent.cli.run_slither")
    def test_generate_tests_emits_candidate_artifact_and_report(
        self,
        mock_run_slither,
        mock_reason_about_finding,
        mock_execute_generated_test,
    ) -> None:
        finding = NormalizedFinding(
            fingerprint="finding-1",
            source="slither",
            rule_id="reentrancy-eth",
            title="Reentrancy in withdraw",
            severity="high",
            confidence="medium",
            description="withdraw performs an external call before debt accounting is updated.",
            locations=[FindingLocation(file_path="src/Vault.sol", lines=[42])],
        )
        mock_run_slither.return_value = SimpleNamespace(findings=[finding])
        mock_reason_about_finding.return_value = ReasoningResult(
            provider=ProviderSelection(name="openai", model="gpt-4.1-mini", api_key_source="env:OPENAI_API_KEY"),
            provider_reasoning=ProviderReasoningResult(
                finding_reference=FindingReference.from_finding(finding),
                summary="Callback-controlled execution may observe stale accounting.",
                exploitability=ExploitabilityAssessment(
                    verdict="plausible",
                    rationale="The deterministic finding indicates a classic ordering issue.",
                ),
                exploit_hypotheses=[
                    ExploitHypothesis(
                        title="Reenter before debt update",
                        narrative="A malicious callback can reenter before totalDebt is updated.",
                    )
                ],
                confidence=ConfidenceScore(label="high", score=0.86, rationale="The signal is strong."),
                evidence_references=["src/Vault.sol:42"],
            ),
            prompt=ReasoningPrompt(
                system_prompt="system",
                user_prompt="user",
                input_payload={"finding": {"fingerprint": "finding-1"}},
                response_contract={"summary": "..."},
                estimated_chars=128,
            ),
        )

        def fake_execute(artifact, *, report):
            artifact.execution = ExecutionResult(
                state="reproduced",
                summary="Foundry runner completed successfully.",
                command=list(artifact.runner_hint.command),
                working_directory=artifact.runner_hint.working_directory,
                return_code=0,
                result_path=str(Path(artifact.output_directory) / "execution-result.json"),
                stdout_path=str(Path(artifact.output_directory) / "runner.stdout.log"),
                stderr_path=str(Path(artifact.output_directory) / "runner.stderr.log"),
            )
            updated_report = report.to_dict()
            updated_report["validation"] = {
                "state": "reproduced",
                "summary": "Foundry runner completed successfully.",
                "evidence": [f"artifact_id: {artifact.artifact_id}"],
            }
            return artifact, updated_report

        mock_execute_generated_test.side_effect = fake_execute

        with tempfile.TemporaryDirectory() as tmp_dir:
            result = _result_for_generate_tests(
                SimpleNamespace(finding_id=None, output_dir=tmp_dir),
                ResolvedConfig(
                    target_path=ROOT / "examples/foundry-sample",
                    framework_override=None,
                    provider=ProviderSelection(
                        name="openai",
                        model="gpt-4.1-mini",
                        api_key_source="env:OPENAI_API_KEY",
                    ),
                    output_format="json",
                    config_path=None,
                ),
            )

            artifact = result.data["generated_tests"][0]
            self.assertEqual(result.data["finding_id"], "finding-1")
            self.assertEqual(result.data["report"]["provider_reasoning"]["summary"], "Callback-controlled execution may observe stale accounting.")
            self.assertEqual(result.data["report"]["validation"]["state"], "reproduced")
            self.assertEqual(result.data["report"]["assessment"]["verdict"], "verified")
            self.assertEqual(artifact["framework"], "foundry")
            self.assertEqual(artifact["strategy"], "reentrancy_validation_candidate")
            self.assertTrue(Path(artifact["test_path"]).is_file())
            self.assertTrue(Path(artifact["report_path"]).is_file())
            self.assertTrue(Path(artifact["metadata_path"]).is_file())
            self.assertIn("forge", artifact["runner_hint"]["command"][0])
            self.assertEqual(artifact["execution"]["state"], "reproduced")
            self.assertIn("report_path", Path(artifact["test_path"]).read_text(encoding="utf-8"))

    @patch("security_agent.cli.execute_generated_test")
    @patch("security_agent.cli.reason_about_finding")
    @patch("security_agent.cli.run_slither")
    def test_generate_tests_respects_selected_mode(
        self,
        mock_run_slither,
        mock_reason_about_finding,
        mock_execute_generated_test,
    ) -> None:
        finding = NormalizedFinding(
            fingerprint="finding-1",
            source="slither",
            rule_id="reentrancy-eth",
            title="Reentrancy in withdraw",
            severity="high",
            confidence="medium",
            description="withdraw performs an external call before debt accounting is updated.",
            locations=[FindingLocation(file_path="src/Vault.sol", lines=[42])],
        )
        mock_run_slither.return_value = SimpleNamespace(findings=[finding])
        mock_reason_about_finding.return_value = ReasoningResult(
            provider=ProviderSelection(name="openai", model="gpt-4.1-mini", api_key_source="env:OPENAI_API_KEY"),
            provider_reasoning=ProviderReasoningResult.pending(finding),
            prompt=ReasoningPrompt(
                system_prompt="system",
                user_prompt="user",
                input_payload={},
                response_contract={},
                estimated_chars=0,
            ),
        )

        def fake_execute(artifact, *, report):
            artifact.execution = ExecutionResult(
                state="reproduced",
                summary="Foundry runner completed successfully.",
                command=list(artifact.runner_hint.command),
                working_directory=artifact.runner_hint.working_directory,
                return_code=0,
                result_path=str(Path(artifact.output_directory) / "execution-result.json"),
                stdout_path=str(Path(artifact.output_directory) / "runner.stdout.log"),
                stderr_path=str(Path(artifact.output_directory) / "runner.stderr.log"),
            )
            updated_report = report.to_dict()
            updated_report["validation"] = {
                "state": "reproduced",
                "summary": artifact.execution.summary,
                "evidence": [f"selected_mode: {artifact.selected_mode}"],
            }
            return artifact, updated_report

        mock_execute_generated_test.side_effect = fake_execute

        with tempfile.TemporaryDirectory() as tmp_dir:
            result = _result_for_generate_tests(
                SimpleNamespace(finding_id=None, output_dir=tmp_dir, mode="fuzz"),
                ResolvedConfig(
                    target_path=ROOT / "examples/foundry-sample",
                    framework_override=None,
                    provider=ProviderSelection(
                        name="openai",
                        model="gpt-4.1-mini",
                        api_key_source="env:OPENAI_API_KEY",
                    ),
                    output_format="json",
                    config_path=None,
                ),
            )

        artifact = result.data["generated_tests"][0]
        self.assertEqual(result.data["mode"], "fuzz")
        self.assertEqual(artifact["selected_mode"], "fuzz")
        self.assertEqual(artifact["runner_hint"]["command"][-2:], ["--match-test", "testFuzzCandidateReentrancyInWithdraw"])

    @patch("security_agent.cli.execute_generated_test")
    @patch("security_agent.cli.reason_about_finding")
    @patch("security_agent.cli.run_slither")
    def test_generate_tests_surfaces_runner_environment_limitations(
        self,
        mock_run_slither,
        mock_reason_about_finding,
        mock_execute_generated_test,
    ) -> None:
        finding = NormalizedFinding(
            fingerprint="finding-1",
            source="slither",
            rule_id="reentrancy-eth",
            title="Reentrancy in withdraw",
            severity="high",
            confidence="medium",
            description="withdraw performs an external call before debt accounting is updated.",
            locations=[FindingLocation(file_path="src/Vault.sol", lines=[42])],
        )
        mock_run_slither.return_value = SimpleNamespace(findings=[finding])
        mock_reason_about_finding.return_value = ReasoningResult(
            provider=ProviderSelection(name="openai", model="gpt-4.1-mini", api_key_source="env:OPENAI_API_KEY"),
            provider_reasoning=ProviderReasoningResult.pending(finding),
            prompt=ReasoningPrompt(
                system_prompt="system",
                user_prompt="user",
                input_payload={},
                response_contract={},
                estimated_chars=0,
            ),
        )

        def fake_execute(artifact, *, report):
            artifact.execution = ExecutionResult(
                state="inconclusive",
                summary="Foundry runner is unavailable in this environment; validation could not be executed.",
                command=list(artifact.runner_hint.command),
                working_directory=artifact.runner_hint.working_directory,
                return_code=None,
                result_path=str(Path(artifact.output_directory) / "execution-result.json"),
                stdout_path=str(Path(artifact.output_directory) / "runner.stdout.log"),
                stderr_path=str(Path(artifact.output_directory) / "runner.stderr.log"),
                environment_limitation="[Errno 2] No such file or directory: 'forge'",
            )
            updated_report = report.to_dict()
            updated_report["validation"] = {
                "state": "inconclusive",
                "summary": artifact.execution.summary,
                "evidence": ["environment_limitation: [Errno 2] No such file or directory: 'forge'"],
            }
            return artifact, updated_report

        mock_execute_generated_test.side_effect = fake_execute

        with tempfile.TemporaryDirectory() as tmp_dir:
            result = _result_for_generate_tests(
                SimpleNamespace(finding_id=None, output_dir=tmp_dir),
                ResolvedConfig(
                    target_path=ROOT / "examples/foundry-sample",
                    framework_override=None,
                    provider=ProviderSelection(
                        name="openai",
                        model="gpt-4.1-mini",
                        api_key_source="env:OPENAI_API_KEY",
                    ),
                    output_format="json",
                    config_path=None,
                ),
            )

        self.assertEqual(result.data["report"]["validation"]["state"], "inconclusive")
        self.assertEqual(result.data["report"]["assessment"]["verdict"], "inconclusive")
        self.assertIn("Runner environment limitation:", result.warnings[-1])

    def test_render_text_includes_structured_report_sections(self) -> None:
        finding = NormalizedFinding(
            fingerprint="finding-1",
            source="slither",
            rule_id="reentrancy-eth",
            title="Reentrancy in withdraw",
            severity="high",
            confidence="medium",
            description="withdraw performs an external call before debt accounting is updated.",
            locations=[FindingLocation(file_path="src/Vault.sol", lines=[42])],
        )
        context_pack = StructuredContextPack(
            project_root="sample-project",
            framework="foundry",
            focal_contract="Vault",
            source_path="src/Vault.sol",
            contract_summary="Vault holds assets and performs external transfers.",
            finding_focus={"contract_name": "Vault", "function_name": "withdraw"},
            imports=("openzeppelin/access/Ownable.sol",),
            inheritance=("Ownable",),
            related_contracts=({"name": "StrategyVault", "relationship": "finding-related"},),
            function_summaries=(),
            modifier_usage=(),
            risky_external_calls=(
                {"function": "withdraw", "target": "token", "call_type": "interface"},
            ),
            storage_sensitive_state=(
                {"name": "totalDebt", "type_name": "uint256", "storage_sensitive": True},
            ),
            excerpts=(
                {"path": "src/Vault.sol", "reason": "external call before state update", "start_line": 38},
            ),
            budget=ContextBudget(),
            estimated_tokens=144,
        )
        report = build_finding_report(
            finding,
            context_pack=context_pack,
            provider_reasoning=ProviderReasoningResult(
                finding_reference=FindingReference.from_finding(finding),
                summary="Callback-controlled execution may observe stale accounting.",
                exploitability=ExploitabilityAssessment(
                    verdict="plausible",
                    rationale="The deterministic finding and context excerpt point to a classic ordering issue.",
                ),
                exploit_hypotheses=[
                    ExploitHypothesis(
                        title="Reenter before debt update",
                        narrative="A malicious callback can reenter while totalDebt still reflects the old balance.",
                        preconditions=["The transfer target can trigger a callback."],
                        impact="The vault can release more assets than intended.",
                    )
                ],
                confidence=ConfidenceScore(
                    label="high",
                    score=0.86,
                    rationale="The deterministic finding and context excerpt point to a classic ordering issue.",
                ),
                assumptions=["The transfer target can trigger a callback."],
                evidence_references=["src/Vault.sol:42"],
                remediation_notes=["Update debt before performing the outbound transfer."],
            ),
            validation=ValidationState(state="not_run", summary="Execution is out of scope for this task."),
        )

        rendered = _render_text(
            CommandResult(
                command="explain",
                status="ok",
                provider=ProviderSelection(
                    name="openai",
                    model="gpt-4.1-mini",
                    api_key_source="env:OPENAI_API_KEY",
                ),
                data={"report": report.to_dict()},
            )
        )

        self.assertIn("[deterministic evidence]", rendered)
        self.assertIn("[structure-aware context]", rendered)
        self.assertIn("[assessment]", rendered)
        self.assertIn("[provider reasoning]", rendered)
        self.assertIn("[exploit hypotheses]", rendered)
        self.assertIn("[confidence scoring]", rendered)
        self.assertIn("[assumptions and caveats]", rendered)
        self.assertIn("[validation state]", rendered)


if __name__ == "__main__":
    unittest.main()