from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import ResolvedConfig, default_api_key_source, resolve_config
from .context import ContextBudget, StructuredContextPack, build_finding_context_from_source
from .generated_tests import execute_generated_test, generate_candidate_test
from .ingestion import ingest_repository
from .llm import infer_provider_name_from_model, normalize_provider_selection, reason_about_finding
from .retrieval import retrieve_patterns
from .reports import build_assessment_state, build_finding_report, render_reports_text
from .schemas import CommandResult, ProviderSelection
from .slither import SlitherScanResult, resolve_target_path, run_slither
from .models.findings import NormalizedFinding


def _unavailable_slither_data(target_path: str, error: FileNotFoundError) -> dict[str, object]:
    return {
        "tool": "slither",
        "command": [],
        "target_path": target_path,
        "return_code": None,
        "success": False,
        "error": str(error),
        "stdout": "",
        "stderr": "",
        "raw_output": None,
        "findings": [],
        "status": "unavailable",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-agent",
        description="Local-first Solidity security workflow for finding, investigating, and validating smart-contract vulnerabilities.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    command_specs = {
        "scan": {
            "help": "Inspect a target repository, normalize analyzer findings, and seed downstream investigation.",
            "aliases": [],
        },
        "investigate": {
            "help": "Turn one finding into bounded exploit hypotheses, confidence scoring, and an explicit assessment.",
            "aliases": ["explain"],
        },
        "generate-tests": {
            "help": "Generate and execute framework-aware exploit-validation candidates.",
            "aliases": [],
        },
    }

    for name, spec in command_specs.items():
        command = subparsers.add_parser(name, aliases=spec["aliases"], help=spec["help"])
        command.set_defaults(command_name=name)
        _add_common_options(command)
        if name in {"investigate", "generate-tests"}:
            command.add_argument("--finding-id", help="Optional finding identifier for downstream stages.")
        if name == "generate-tests":
            command.add_argument(
                "--output-dir",
                default="generated-tests",
                help="Output directory for generated tests and execution artifacts.",
            )
            command.add_argument(
                "--mode",
                choices=("exploit", "invariant", "fuzz"),
                default="exploit",
                help="Execution mode for the generated validation candidate.",
            )
    return parser


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--target", help="Target smart contract repository path.")
    parser.add_argument("--config", help="Path to a TOML config file.")
    parser.add_argument(
        "--framework",
        help="Framework override: auto (default), foundry, or hardhat.",
    )
    parser.add_argument("--provider", help="LLM provider name (for example: openai, anthropic).")
    parser.add_argument("--model", help="Model identifier for the selected provider.")
    parser.add_argument("--api-key-source", help="API key source descriptor such as env:OPENAI_API_KEY.")
    parser.add_argument(
        "--format",
        dest="output_format",
        help="Output format: text (default) or json.",
    )
    parser.set_defaults(retrieval_enabled=None)
    parser.add_argument(
        "--enable-retrieval",
        dest="retrieval_enabled",
        action="store_true",
        help="Attach local curated retrieval memory as an additive prompt sidecar.",
    )
    parser.add_argument(
        "--disable-retrieval",
        dest="retrieval_enabled",
        action="store_false",
        help="Disable retrieval memory even if it is enabled in config.",
    )
    parser.add_argument(
        "--retrieval-limit",
        help="Maximum number of retrieved patterns to attach when retrieval is enabled.",
    )


def _result_for_scan(config: ResolvedConfig) -> CommandResult:
    manifest = ingest_repository(config.target_path, config.framework_override)
    warnings: list[str] = []
    findings: list[dict[str, object]] = []
    slither_data: dict[str, object]
    try:
        scan_result = run_slither(manifest, cwd=manifest.root_path)
        findings = [finding.to_dict() for finding in scan_result.findings]
        slither_data = scan_result.to_dict()
        if scan_result.return_code != 0:
            warnings.append("Slither exited with a non-zero status; inspect stdout/stderr and raw output.")
        if (scan_result.raw_output or {}).get("error"):
            warnings.append("Slither reported an analysis error in its JSON payload.")
    except FileNotFoundError as exc:
        slither_data = _unavailable_slither_data(str(resolve_target_path(manifest)), exc)
        warnings.append("Slither is not installed or not on PATH; scan output contains only ingestion metadata.")
    return CommandResult(
        command="scan",
        status="ok",
        provider=config.provider,
        manifest=manifest,
        data={
            "findings": findings,
            "analysis": {"slither": slither_data},
            "summary": "Scan runs repository ingestion plus deterministic analysis so suspicious surfaces can flow into investigation and validation.",
        },
        warnings=warnings,
    )


def _result_for_investigate(args, config: ResolvedConfig) -> CommandResult:
    manifest = ingest_repository(config.target_path, config.framework_override)
    try:
        scan_result = run_slither(manifest, cwd=manifest.root_path)
    except FileNotFoundError as exc:
        raise ValueError(
            "Investigation requires normalized analyzer findings, but Slither is unavailable. Install Slither or run in an environment where it is on PATH."
        ) from exc

    finding, warnings = _select_investigation_finding(scan_result, getattr(args, "finding_id", None))
    context_pack = _build_investigation_context_pack(manifest, finding)
    seed_report = build_finding_report(finding, context_pack=context_pack)
    retrieval_context = retrieve_patterns(
        finding,
        context_pack,
        report=seed_report.to_dict(),
        settings=config.retrieval,
    )
    reasoning_result = reason_about_finding(
        config.provider,
        finding,
        context_pack,
        retrieval_context=retrieval_context,
    )
    report = build_finding_report(
        finding,
        context_pack=context_pack,
        provider_reasoning=reasoning_result.provider_reasoning,
    )
    if reasoning_result.request_status != "success":
        warnings.append(
            f"Provider reasoning request did not complete successfully ({reasoning_result.request_status}); inspect data.reasoning_result for details."
        )

    return CommandResult(
        command="investigate",
        status="ok",
        provider=config.provider,
        manifest=manifest,
        data={
            "finding_id": finding.fingerprint,
            "finding": finding.to_dict(),
            "report": report.to_dict(),
            "reasoning_result": reasoning_result.to_dict(),
            "summary": "Investigate turns one deterministic finding into bounded exploit hypotheses, confidence scoring, and a validation-ready assessment.",
            **({"retrieval": retrieval_context.to_dict()} if retrieval_context is not None else {}),
        },
        warnings=warnings,
    )


def _result_for_explain(args, config: ResolvedConfig) -> CommandResult:
    return _result_for_investigate(args, config)


def _select_investigation_finding(
    scan_result: SlitherScanResult,
    finding_id: str | None,
) -> tuple[NormalizedFinding, list[str]]:
    findings = scan_result.findings
    if not findings:
        raise ValueError("Investigation requires at least one normalized finding, but the analyzer returned none.")
    if finding_id:
        for finding in findings:
            if finding.fingerprint == finding_id:
                return finding, []
        available = ", ".join(finding.fingerprint for finding in findings[:5])
        raise ValueError(f"Finding id '{finding_id}' was not found. Available finding ids: {available}")
    warnings: list[str] = []
    if len(findings) > 1:
        warnings.append(
            f"No finding id was provided; investigation defaulted to the first normalized finding ({findings[0].fingerprint})."
        )
    return findings[0], warnings


def _select_explain_finding(
    scan_result: SlitherScanResult,
    finding_id: str | None,
) -> tuple[NormalizedFinding, list[str]]:
    return _select_investigation_finding(scan_result, finding_id)


def _build_investigation_context_pack(manifest, finding: NormalizedFinding) -> StructuredContextPack:
    source_aware_pack = build_finding_context_from_source(manifest, finding, budget=ContextBudget())
    if source_aware_pack is not None:
        return source_aware_pack

    return _build_minimal_investigation_context_pack(manifest, finding)


def _build_minimal_investigation_context_pack(manifest, finding: NormalizedFinding) -> StructuredContextPack:
    primary_location = finding.locations[0] if finding.locations else None
    source_path = primary_location.file_path if primary_location else (manifest.source_files[0] if manifest.source_files else "")
    focal_contract = Path(source_path).stem if source_path else "UnknownContract"
    lines = primary_location.lines if primary_location else []
    start_line = lines[0] if lines else 0
    end_line = lines[-1] if lines else start_line
    description = finding.description.strip() or finding.title
    reason = description.splitlines()[0] if description else finding.title
    risk_tags = tuple(part for part in finding.rule_id.replace("_", "-").split("-") if part)
    excerpts = ()
    if source_path:
        excerpts = (
            {
                "path": source_path,
                "start_line": start_line,
                "end_line": end_line,
                "reason": "Primary deterministic analyzer location for the selected finding.",
                "content": description,
            },
        )
    return StructuredContextPack(
        project_root=manifest.root_path,
        framework=manifest.framework,
        focal_contract=focal_contract,
        source_path=source_path,
        contract_summary=f"Finding-scoped investigation context for {finding.title}.",
        finding_focus={
            "contract_name": focal_contract,
            "reason": reason,
            "risk_tags": risk_tags,
        },
        imports=(),
        inheritance=(),
        related_contracts=(),
        function_summaries=(),
        modifier_usage=(),
        risky_external_calls=(),
        storage_sensitive_state=(),
        excerpts=excerpts,
        budget=ContextBudget(),
        estimated_tokens=max(1, len(json.dumps(finding.to_dict(), sort_keys=True)) // 4),
    )


def _build_explain_context_pack(manifest, finding: NormalizedFinding) -> StructuredContextPack:
    return _build_investigation_context_pack(manifest, finding)


def _result_for_generate_tests(args, config: ResolvedConfig) -> CommandResult:
    manifest = ingest_repository(config.target_path, config.framework_override)
    selected_mode = getattr(args, "mode", "exploit") or "exploit"
    try:
        scan_result = run_slither(manifest, cwd=manifest.root_path)
    except FileNotFoundError as exc:
        raise ValueError(
            "Generate-tests requires normalized analyzer findings, but Slither is unavailable. Install Slither or run in an environment where it is on PATH."
        ) from exc

    finding, warnings = _select_investigation_finding(scan_result, getattr(args, "finding_id", None))
    context_pack = _build_investigation_context_pack(manifest, finding)
    seed_report = build_finding_report(finding, context_pack=context_pack)
    retrieval_context = retrieve_patterns(
        finding,
        context_pack,
        report=seed_report.to_dict(),
        settings=config.retrieval,
    )
    reasoning_result = reason_about_finding(
        config.provider,
        finding,
        context_pack,
        retrieval_context=retrieval_context,
    )
    report = build_finding_report(
        finding,
        context_pack=context_pack,
        provider_reasoning=reasoning_result.provider_reasoning,
    )
    artifact = generate_candidate_test(
        manifest,
        report,
        output_dir=args.output_dir,
        selected_mode=selected_mode,
        retrieval=None if retrieval_context is None else retrieval_context.to_dict(),
    )
    artifact, executed_report = execute_generated_test(artifact, report=report)
    executed_report["assessment"] = build_assessment_state(
        executed_report.get("provider_reasoning"),
        executed_report.get("validation"),
    ).to_dict()
    if reasoning_result.request_status != "success":
        warnings.append(
            f"Provider reasoning request did not complete successfully ({reasoning_result.request_status}); generated test scaffolds are based on canonical report fields with degraded provider detail."
        )
    if artifact.execution and artifact.execution.environment_limitation:
        warnings.append(
            "Runner environment limitation: "
            f"{artifact.execution.environment_limitation}"
        )

    return CommandResult(
        command="generate-tests",
        status="ok",
        provider=config.provider,
        manifest=manifest,
        data={
            "finding_id": finding.fingerprint,
            "finding": finding.to_dict(),
            "report": executed_report,
            "reasoning_result": reasoning_result.to_dict(),
            "generated_tests": [artifact.to_dict()],
            "mode": artifact.selected_mode,
            "output_dir": args.output_dir,
            "summary": f"Generate-tests turns one investigated finding into a {artifact.selected_mode} validation candidate and executes it through the framework-specific runner.",
            **({"retrieval": retrieval_context.to_dict()} if retrieval_context is not None else {}),
        },
        warnings=warnings,
    )


def _render_text(result: CommandResult) -> str:
    target = getattr(result.manifest, "target_path", None) or getattr(result.manifest, "root_path", None)
    detection = getattr(result.manifest, "detection_source", None) or "ingestion"
    lines = [
        f"command: {result.command}",
        f"status: {result.status}",
        f"provider: {result.provider.name}",
        f"model: {result.provider.model}",
    ]
    if result.manifest is not None:
        lines.extend(
            [
                f"framework: {result.manifest.framework}",
                f"target: {target}",
                f"detection: {detection}",
            ]
        )
    if result.data.get("summary"):
        lines.append(f"summary: {result.data['summary']}")
    reports = result.data.get("reports") or result.data.get("report")
    if reports:
        lines.extend(["", render_reports_text(reports)])
    generated_tests = result.data.get("generated_tests") or []
    if generated_tests:
        lines.extend(["", "[generated tests]"])
        for item in generated_tests:
            if not isinstance(item, dict):
                continue
            lines.append(
                "  - "
                f"framework={item.get('framework', 'unknown')}; "
                f"path={item.get('test_path', 'unknown')}; "
                f"report={item.get('report_path', 'unknown')}; "
                f"execution={(item.get('execution') or {}).get('state', 'not_run')}"
            )
    retrieval = result.data.get("retrieval") or {}
    if isinstance(retrieval, dict) and retrieval.get("matches"):
        lines.extend(["", "[retrieval memory]", f"store: {retrieval.get('store', 'unknown')}"])
        for item in retrieval.get("matches") or []:
            if not isinstance(item, dict):
                continue
            lines.append(
                "  - "
                f"pattern_id={item.get('pattern_id', 'unknown')}; "
                f"source={item.get('source', 'unknown')}"
            )
    if result.warnings:
        lines.extend(f"warning: {warning}" for warning in result.warnings)
    if result.errors:
        lines.extend(f"error: {error}" for error in result.errors)
    return "\n".join(lines)


def _emit_result(result: CommandResult, output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(result.to_dict(), indent=2))
        return
    print(_render_text(result))


def _fallback_provider(args) -> ProviderSelection:
    model_name = getattr(args, "model", None) or "gpt-4.1-mini"
    provider_name = getattr(args, "provider", None) or infer_provider_name_from_model(model_name) or "openai"
    return normalize_provider_selection(
        ProviderSelection(
            name=provider_name,
            model=model_name,
            api_key_source=getattr(args, "api_key_source", None) or default_api_key_source(provider_name),
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command_name = getattr(args, "command_name", getattr(args, "command", None))

    try:
        config = resolve_config(args)
        if command_name == "scan":
            result = _result_for_scan(config)
        elif command_name == "investigate":
            result = _result_for_investigate(args, config)
        else:
            result = _result_for_generate_tests(args, config)
        _emit_result(result, config.output_format)
        return 0
    except (FileNotFoundError, ValueError) as exc:
        result = CommandResult(
            command=command_name or "unknown",
            status="error",
            provider=_fallback_provider(args),
            errors=[str(exc)],
        )
        _emit_result(result, getattr(args, "output_format", None) or "text")
        return 1