from __future__ import annotations

from pathlib import Path

from .ingestion import ingest_repository
from .models import ProjectManifest


FRAMEWORK_MARKERS = {
    "foundry": ["foundry.toml"],
    "hardhat": [
        "hardhat.config.ts",
        "hardhat.config.js",
        "hardhat.config.cjs",
        "hardhat.config.mjs",
    ],
}


def normalize_framework(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"", "auto"}:
        return None
    if normalized not in FRAMEWORK_MARKERS:
        raise ValueError("Framework must be one of: auto, foundry, hardhat.")
    return normalized


def build_manifest(target_path: str | Path, framework_override: str | None = None) -> ProjectManifest:
    target_path = Path(target_path).resolve()
    if not target_path.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_path}")
    return ingest_repository(target_path, normalize_framework(framework_override))