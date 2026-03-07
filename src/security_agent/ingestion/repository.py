from __future__ import annotations

import json
from pathlib import Path
import re
import tomllib
from typing import Any

from ..models.project import CompilerInfo, ProjectManifest

FOUNDRY_CONFIG = "foundry.toml"
HARDHAT_CONFIG_FILES = (
    "hardhat.config.ts",
    "hardhat.config.js",
    "hardhat.config.cts",
    "hardhat.config.cjs",
    "hardhat.config.mts",
    "hardhat.config.mjs",
)
SOURCE_SUFFIXES = {".sol"}
TEST_SUFFIXES = {".sol", ".js", ".ts", ".cjs", ".mjs"}
SCRIPT_SUFFIXES = TEST_SUFFIXES


class RepositoryIngestionError(ValueError):
    pass


def ingest_repository(repo_path: str | Path, framework: str | None = None) -> ProjectManifest:
    root = Path(repo_path).resolve()
    if not root.is_dir():
        raise RepositoryIngestionError(f"Repository path does not exist or is not a directory: {root}")

    detected_framework = (framework or detect_framework(root)).lower()
    if detected_framework == "foundry":
        return _ingest_foundry(root)
    if detected_framework == "hardhat":
        return _ingest_hardhat(root)
    raise RepositoryIngestionError(f"Unsupported framework override: {framework}")


def detect_framework(repo_path: str | Path) -> str:
    root = Path(repo_path).resolve()
    package_json = _load_package_json(root)
    foundry_score = 0
    hardhat_score = 0

    if (root / FOUNDRY_CONFIG).is_file():
        foundry_score += 3
    if _find_hardhat_config(root) is not None:
        hardhat_score += 3

    dependencies = _collect_package_dependencies(package_json)
    if "hardhat" in dependencies or "@nomicfoundation/hardhat-toolbox" in dependencies:
        hardhat_score += 2

    package_scripts = (package_json or {}).get("scripts", {})
    if any("hardhat" in str(command) for command in package_scripts.values()):
        hardhat_score += 1

    if (root / "lib").exists() or (root / "script").exists():
        foundry_score += 1

    if foundry_score == 0 and hardhat_score == 0:
        raise RepositoryIngestionError("Could not detect a Foundry or Hardhat project")
    if foundry_score == hardhat_score:
        raise RepositoryIngestionError(
            "Framework autodetect is ambiguous; pass an explicit override from the CLI"
        )
    return "foundry" if foundry_score > hardhat_score else "hardhat"


def _ingest_foundry(root: Path) -> ProjectManifest:
    config_path = root / FOUNDRY_CONFIG
    if not config_path.is_file():
        raise RepositoryIngestionError(f"Missing {FOUNDRY_CONFIG} in {root}")

    with config_path.open("rb") as handle:
        config = tomllib.load(handle)

    profile = ((config.get("profile") or {}).get("default") or {})
    source_directories = [_config_path(root, profile.get("src", "src"))]
    test_directories = [_config_path(root, profile.get("test", "test"))]
    script_directories = [_config_path(root, profile.get("script", "script"))]
    dependency_directories = [_config_path(root, path) for path in profile.get("libs", ["lib"])]
    include_paths = dependency_directories + [
        _config_path(root, path) for path in profile.get("include_paths", [])
    ]
    remappings = [str(value) for value in profile.get("remappings", [])]
    compiler_version = _to_optional_str(profile.get("solc"))

    return ProjectManifest(
        framework="foundry",
        root_path=str(root),
        config_files=[_relative_to_root(root, config_path)],
        source_directories=_relative_paths(root, source_directories),
        test_directories=_relative_paths(root, test_directories),
        script_directories=_relative_paths(root, script_directories),
        dependency_directories=_relative_paths(root, dependency_directories),
        include_paths=_relative_paths(root, include_paths),
        source_files=_collect_files(root, source_directories, SOURCE_SUFFIXES),
        test_files=_collect_files(root, test_directories, TEST_SUFFIXES),
        script_files=_collect_files(root, script_directories, SCRIPT_SUFFIXES),
        remappings=remappings,
        compiler=CompilerInfo(
            version=compiler_version,
            versions=[compiler_version] if compiler_version else [],
            auto_detect=_to_optional_bool(profile.get("auto_detect_solc")),
            optimizer_enabled=_to_optional_bool(profile.get("optimizer")),
            optimizer_runs=_to_optional_int(profile.get("optimizer_runs")),
            via_ir=_to_optional_bool(profile.get("via_ir")),
            evm_version=_to_optional_str(profile.get("evm_version")),
            details={"profile": "default"},
        ),
        metadata={
            "detected_by": [FOUNDRY_CONFIG],
            "profile": "default",
            "raw_profile": profile,
        },
    )


def _ingest_hardhat(root: Path) -> ProjectManifest:
    config_path = _find_hardhat_config(root)
    if config_path is None:
        raise RepositoryIngestionError(f"Missing hardhat.config.* in {root}")

    config_text = config_path.read_text(encoding="utf-8")
    package_json = _load_package_json(root)
    paths_text = _extract_object_literal(config_text, "paths")
    sources_path = _extract_string_property(paths_text, "sources") or "contracts"
    tests_path = _extract_string_property(paths_text, "tests") or "test"
    scripts_path = _extract_string_property(paths_text, "scripts") or "scripts"

    source_directories = [_config_path(root, sources_path)]
    test_directories = [_config_path(root, tests_path)]
    script_directories = [_config_path(root, scripts_path)]
    dependency_directories = [_config_path(root, "node_modules")]
    include_paths = dependency_directories.copy()
    compiler = _parse_hardhat_compiler(config_text)

    config_files = [_relative_to_root(root, config_path)]
    if (root / "package.json").is_file():
        config_files.append("package.json")

    return ProjectManifest(
        framework="hardhat",
        root_path=str(root),
        config_files=config_files,
        source_directories=_relative_paths(root, source_directories),
        test_directories=_relative_paths(root, test_directories),
        script_directories=_relative_paths(root, script_directories),
        dependency_directories=_relative_paths(root, dependency_directories),
        include_paths=_relative_paths(root, include_paths),
        source_files=_collect_files(root, source_directories, SOURCE_SUFFIXES),
        test_files=_collect_files(root, test_directories, TEST_SUFFIXES),
        script_files=_collect_files(root, script_directories, SCRIPT_SUFFIXES),
        compiler=compiler,
        metadata={
            "detected_by": [config_path.name],
            "package_name": (package_json or {}).get("name"),
            "package_manager": (package_json or {}).get("packageManager"),
        },
    )


def _find_hardhat_config(root: Path) -> Path | None:
    for name in HARDHAT_CONFIG_FILES:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def _parse_hardhat_compiler(config_text: str) -> CompilerInfo:
    solidity_text = _extract_object_literal(config_text, "solidity")
    if not solidity_text:
        version_match = re.search(r"solidity\s*:\s*['\"]([^'\"]+)['\"]", config_text)
        version = version_match.group(1) if version_match else None
        return CompilerInfo(version=version, versions=[version] if version else [])

    versions = list(dict.fromkeys(re.findall(r"version\s*:\s*['\"]([^'\"]+)['\"]", solidity_text)))
    version = versions[0] if versions else None
    optimizer_enabled = _regex_bool(solidity_text, r"enabled\s*:\s*(true|false)")
    optimizer_runs = _regex_int(solidity_text, r"runs\s*:\s*([0-9]+)")
    via_ir = _regex_bool(solidity_text, r"viaIR\s*:\s*(true|false)")
    if via_ir is None:
        via_ir = _regex_bool(solidity_text, r"viaIr\s*:\s*(true|false)")
    evm_version = _regex_string(solidity_text, r"evmVersion\s*:\s*['\"]([^'\"]+)['\"]")
    return CompilerInfo(
        version=version,
        versions=versions,
        optimizer_enabled=optimizer_enabled,
        optimizer_runs=optimizer_runs,
        via_ir=via_ir,
        evm_version=evm_version,
        details={"config_source": "hardhat.config.*", "raw": solidity_text},
    )


def _extract_object_literal(config_text: str, key: str) -> str | None:
    key_match = re.search(rf"{re.escape(key)}\s*:\s*\{{", config_text)
    if not key_match:
        return None
    start = config_text.find("{", key_match.start())
    depth = 0
    for index in range(start, len(config_text)):
        character = config_text[index]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return config_text[start : index + 1]
    return None


def _extract_string_property(config_text: str | None, key: str) -> str | None:
    if not config_text:
        return None
    match = re.search(rf"{re.escape(key)}\s*:\s*['\"]([^'\"]+)['\"]", config_text)
    return match.group(1) if match else None


def _load_package_json(root: Path) -> dict[str, Any] | None:
    package_path = root / "package.json"
    if not package_path.is_file():
        return None
    return json.loads(package_path.read_text(encoding="utf-8"))


def _collect_package_dependencies(package_json: dict[str, Any] | None) -> set[str]:
    if not package_json:
        return set()
    dependency_groups = (
        package_json.get("dependencies", {}),
        package_json.get("devDependencies", {}),
        package_json.get("peerDependencies", {}),
    )
    return {name for group in dependency_groups for name in group}


def _collect_files(root: Path, directories: list[Path], suffixes: set[str]) -> list[str]:
    discovered: list[str] = []
    for directory in directories:
        if directory.is_file() and directory.suffix in suffixes:
            discovered.append(_relative_to_root(root, directory))
            continue
        if not directory.is_dir():
            continue
        for candidate in sorted(directory.rglob("*")):
            if candidate.is_file() and candidate.suffix in suffixes:
                discovered.append(_relative_to_root(root, candidate))
    return list(dict.fromkeys(discovered))


def _config_path(root: Path, configured_path: str | Path) -> Path:
    raw_path = Path(str(configured_path))
    if raw_path.is_absolute():
        return raw_path
    return (root / raw_path).resolve()


def _relative_paths(root: Path, paths: list[Path]) -> list[str]:
    return list(dict.fromkeys(_relative_to_root(root, path) for path in paths))


def _relative_to_root(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _regex_bool(text: str, pattern: str) -> bool | None:
    match = re.search(pattern, text)
    if not match:
        return None
    return match.group(1).lower() == "true"


def _regex_int(text: str, pattern: str) -> int | None:
    match = re.search(pattern, text)
    return int(match.group(1)) if match else None


def _regex_string(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text)
    return match.group(1) if match else None


def _to_optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "false"}:
            return lowered == "true"
    return None


def _to_optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return int(value)


def _to_optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)