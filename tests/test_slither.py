from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from security_agent.analyzers.slither import (
    build_slither_command,
    normalize_slither_output,
    resolve_target_path,
    run_slither,
)
from security_agent.models.project import ProjectManifest


SAMPLE_OUTPUT = {
    "success": True,
    "error": None,
    "results": {
        "detectors": [
            {
                "check": "reentrancy-eth",
                "impact": "High",
                "confidence": "Medium",
                "description": "Reentrancy in Vault.withdraw()",
                "elements": [
                    {
                        "type": "function",
                        "name": "withdraw",
                        "source_mapping": {
                            "filename_relative": "src/Vault.sol",
                            "lines": [12, 13, 14],
                            "start": 120,
                            "length": 45,
                            "starting_column": 5,
                            "ending_column": 7,
                        },
                    }
                ],
            },
            {
                "check": "reentrancy-eth",
                "impact": "High",
                "confidence": "Medium",
                "description": "Duplicate presentation of the same issue",
                "elements": [
                    {
                        "type": "function",
                        "name": "withdraw",
                        "source_mapping": {
                            "filename_relative": "src/Vault.sol",
                            "lines": [12, 13, 14],
                            "start": 120,
                            "length": 45,
                            "starting_column": 5,
                            "ending_column": 7,
                        },
                    }
                ],
            },
            {
                "check": "unchecked-transfer",
                "impact": "Low",
                "confidence": "High",
                "description": "Unchecked token transfer return value",
                "elements": [
                    {
                        "type": "function",
                        "name": "sweep",
                        "source_mapping": {"filename_relative": "src/Vault.sol", "lines": [22]},
                    }
                ],
            },
        ]
    },
}


class SlitherNormalizationTests(unittest.TestCase):
    def test_normalize_and_deduplicate_findings(self) -> None:
        findings = normalize_slither_output(SAMPLE_OUTPUT)

        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].source, "slither")
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].confidence, "medium")
        self.assertEqual(findings[0].locations[0].file_path, "src/Vault.sol")
        self.assertEqual(findings[1].rule_id, "unchecked-transfer")

    def test_build_command_and_resolve_target(self) -> None:
        manifest = ProjectManifest(
            framework="foundry",
            root_path="tests/fixtures/foundry_reentrancy",
            config_files=["foundry.toml"],
            source_directories=["src"],
            test_directories=["test"],
            script_directories=["script"],
            dependency_directories=[],
            include_paths=[],
            source_files=["src/Vault.sol"],
            test_files=[],
            script_files=[],
        )
        target = resolve_target_path(manifest)
        command = build_slither_command(manifest, json_output_path="out.json", extra_args=("--exclude-dependencies",))

        self.assertTrue(target.is_absolute())
        self.assertEqual(command[-1], "--exclude-dependencies")
        self.assertEqual(command[2:4], ["--json", "out.json"])

    @patch("security_agent.analyzers.slither.subprocess.run")
    def test_run_slither_captures_raw_output(self, mock_run) -> None:
        def fake_run(command, **kwargs):
            output_path = Path(command[command.index("--json") + 1])
            self.assertFalse(output_path.exists())
            output_path.write_text(__import__("json").dumps(SAMPLE_OUTPUT))
            return subprocess.CompletedProcess(command, 0, stdout="scan ok", stderr="")

        mock_run.side_effect = fake_run
        result = run_slither("tests/fixtures/foundry_reentrancy")

        self.assertEqual(result.return_code, 0)
        self.assertEqual(result.stdout, "scan ok")
        self.assertEqual(len(result.findings), 2)
        self.assertTrue(result.target_path.replace("\\", "/").endswith("tests/fixtures/foundry_reentrancy"))
        self.assertEqual(result.to_dict()["status"], "ok")


if __name__ == "__main__":
    unittest.main()