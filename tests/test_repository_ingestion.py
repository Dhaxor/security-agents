from __future__ import annotations

from pathlib import Path
import unittest

from security_agent.frameworks import build_manifest
from security_agent.ingestion import detect_framework, ingest_repository


FIXTURES = Path(__file__).parent / "fixtures"


class RepositoryIngestionTests(unittest.TestCase):
    def test_frameworks_build_manifest_compatibility_helper(self) -> None:
        foundry_manifest = build_manifest(FIXTURES / "foundry_sample")
        hardhat_manifest = build_manifest(FIXTURES / "hardhat_sample", "hardhat")

        self.assertEqual(foundry_manifest.framework, "foundry")
        self.assertIn("src/Counter.sol", foundry_manifest.source_files)
        self.assertEqual(hardhat_manifest.framework, "hardhat")
        self.assertIn("contracts/Counter.sol", hardhat_manifest.source_files)

    def test_foundry_manifest(self) -> None:
        repo_path = FIXTURES / "foundry_sample"
        manifest = ingest_repository(repo_path)

        self.assertEqual(detect_framework(repo_path), "foundry")
        self.assertEqual(manifest.framework, "foundry")
        self.assertEqual(manifest.source_directories, ["src"])
        self.assertEqual(manifest.test_directories, ["test"])
        self.assertEqual(manifest.script_directories, ["script"])
        self.assertEqual(manifest.dependency_directories, ["lib"])
        self.assertIn("src/Counter.sol", manifest.source_files)
        self.assertIn("test/Counter.t.sol", manifest.test_files)
        self.assertIn("script/Deploy.s.sol", manifest.script_files)
        self.assertEqual(manifest.compiler.version, "0.8.24")
        self.assertEqual(manifest.compiler.optimizer_runs, 200)
        self.assertEqual(manifest.compiler.via_ir, False)
        self.assertEqual(manifest.remappings, ["forge-std/=lib/forge-std/src/"])

    def test_hardhat_manifest(self) -> None:
        repo_path = FIXTURES / "hardhat_sample"
        manifest = ingest_repository(repo_path)

        self.assertEqual(detect_framework(repo_path), "hardhat")
        self.assertEqual(manifest.framework, "hardhat")
        self.assertEqual(manifest.source_directories, ["contracts"])
        self.assertEqual(manifest.test_directories, ["test"])
        self.assertEqual(manifest.script_directories, ["scripts"])
        self.assertEqual(manifest.dependency_directories, ["node_modules"])
        self.assertIn("contracts/Counter.sol", manifest.source_files)
        self.assertIn("test/Counter.ts", manifest.test_files)
        self.assertIn("scripts/deploy.ts", manifest.script_files)
        self.assertEqual(manifest.compiler.version, "0.8.21")
        self.assertEqual(manifest.compiler.optimizer_runs, 300)
        self.assertEqual(manifest.compiler.via_ir, True)
        self.assertEqual(manifest.metadata["package_name"], "hardhat-sample")


if __name__ == "__main__":
    unittest.main()