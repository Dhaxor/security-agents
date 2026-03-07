from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from security_agent.context.structure_aware import (
    ContextBudget,
    FindingFocus,
    StructureAwareContextBuilder,
)
from security_agent.models.context import (
    CodeExcerpt,
    ContractSummary,
    ExternalCallSummary,
    FunctionSummary,
    SolidityStructureInventory,
    SourceLocation,
    StateVariableSummary,
)
from security_agent.models import ProjectManifest


def build_manifest() -> ProjectManifest:
    return ProjectManifest(
        framework="foundry",
        root_path="sample-project",
        config_files=["foundry.toml"],
        source_directories=["src"],
        test_directories=["test"],
        script_directories=["script"],
        dependency_directories=["lib"],
        include_paths=["lib"],
        source_files=["src/Vault.sol", "src/StrategyVault.sol"],
        test_files=[],
        script_files=[],
    )


def build_inventory() -> SolidityStructureInventory:
    withdraw_call = ExternalCallSummary(
        target="token",
        call_type="interface",
        expression="token.safeTransfer(strategy, amount)",
        summary="Transfers ERC20 tokens to the strategy contract.",
        risk_tags=("external-call", "reentrancy"),
        location=SourceLocation("src/Vault.sol", 42, 42),
    )
    vault = ContractSummary(
        name="Vault",
        kind="contract",
        source_path="src/Vault.sol",
        summary="Custodies tokens, updates debt accounting, and lets governance move funds.",
        imports=("openzeppelin/access/Ownable.sol", "openzeppelin/token/ERC20/utils/SafeERC20.sol"),
        bases=("Ownable",),
        modifiers=("onlyOwner", "whenNotPaused"),
        state_variables=(
            StateVariableSummary("totalDebt", "uint256", "internal", "Tracks deployed capital.", True),
            StateVariableSummary("paused", "bool", "public", "Blocks risky flows while set.", True),
            StateVariableSummary("feeBps", "uint16", "public", "Governance fee configuration."),
        ),
        functions=(
            FunctionSummary(
                name="withdraw",
                signature="withdraw(uint256 amount)",
                visibility="external",
                state_mutability="nonpayable",
                summary="Transfers assets out and decrements debt after external execution.",
                modifiers=("onlyOwner", "whenNotPaused"),
                external_calls=(withdraw_call,),
                reads=("paused", "totalDebt"),
                writes=("totalDebt",),
            ),
            FunctionSummary(
                name="setFee",
                signature="setFee(uint16 newFeeBps)",
                visibility="external",
                state_mutability="nonpayable",
                summary="Updates governance fee configuration.",
                modifiers=("onlyOwner",),
                writes=("feeBps",),
            ),
        ),
        excerpts=(
            CodeExcerpt(
                path="src/Vault.sol",
                start_line=38,
                end_line=47,
                reason="withdraw updates totalDebt after token transfer",
                tags=("external-call", "reentrancy"),
                content="token.safeTransfer(strategy, amount);\ntotalDebt -= amount;",
            ),
            CodeExcerpt(
                path="src/Vault.sol",
                start_line=51,
                end_line=55,
                reason="setFee governance update",
                tags=("config",),
                content="feeBps = newFeeBps;",
            ),
        ),
    )
    strategy = ContractSummary(
        name="StrategyVault",
        kind="contract",
        source_path="src/StrategyVault.sol",
        summary="Extends Vault with strategy-specific accounting.",
        bases=("Vault",),
    )
    return SolidityStructureInventory(contracts=(vault, strategy))


class StructureAwareContextBuilderTests(unittest.TestCase):
    def test_contract_context_includes_structure_and_excerpts(self) -> None:
        pack = StructureAwareContextBuilder().build_contract_context(
            build_manifest(), build_inventory(), "Vault"
        )
        self.assertEqual(pack.focal_contract, "Vault")
        self.assertIn("openzeppelin/access/Ownable.sol", pack.imports)
        self.assertEqual(pack.inheritance, ("Ownable",))
        self.assertEqual(pack.related_contracts[0]["name"], "Ownable")
        self.assertEqual(pack.related_contracts[1]["name"], "StrategyVault")
        self.assertEqual(pack.risky_external_calls[0]["function"], "withdraw")
        self.assertTrue(pack.storage_sensitive_state)
        self.assertEqual(pack.excerpts[0]["path"], "src/Vault.sol")
        self.assertGreater(pack.estimated_tokens, 0)

    def test_finding_context_prioritizes_focused_function_and_trims_to_budget(self) -> None:
        budget = ContextBudget(max_tokens=180, max_functions=2, max_excerpts=2, max_external_calls=2)
        focus = FindingFocus(
            contract_name="Vault",
            function_name="withdraw",
            reason="Review reentrancy around token transfer ordering.",
            risk_tags=("reentrancy",),
            related_contracts=("StrategyVault",),
        )
        pack = StructureAwareContextBuilder(budget=budget).build_finding_context(
            build_manifest(), build_inventory(), focus
        )
        self.assertEqual(pack.function_summaries[0]["name"], "withdraw")
        self.assertEqual(pack.excerpts[0]["reason"], "withdraw updates totalDebt after token transfer")
        self.assertLessEqual(pack.estimated_tokens, budget.max_tokens)
        self.assertLessEqual(len(pack.excerpts), budget.max_excerpts)


if __name__ == "__main__":
    unittest.main()