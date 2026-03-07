from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .frameworks import normalize_framework
from .llm import default_api_key_source, infer_provider_name_from_model, normalize_provider_selection
from .retrieval import RetrievalSettings
from .schemas import ProviderSelection


DEFAULT_CONFIG_FILES = ("security-agent.toml", ".security-agent.toml")


@dataclass(slots=True)
class ResolvedConfig:
    target_path: Path
    framework_override: str | None
    provider: ProviderSelection
    output_format: str
    config_path: Path | None
    retrieval: RetrievalSettings = field(default_factory=RetrievalSettings)


def _resolve_config_path(explicit: str | None, cwd: Path) -> Path | None:
    if explicit:
        return Path(explicit).expanduser().resolve()
    for name in DEFAULT_CONFIG_FILES:
        candidate = cwd / name
        if candidate.exists():
            return candidate.resolve()
    return None


def _load_config(path: Path | None) -> dict:
    if path is None:
        return {}
    if not path.exists():
        raise FileNotFoundError(f"Config file does not exist: {path}")
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Config file must decode to a table/object.")
    return data


def _pick(*values: str | None, default: str | None = None) -> str | None:
    for value in values:
        if value not in {None, ""}:
            return value
    return default


def _resolve_bool(value: object, *, label: str) -> bool | None:
    if value in {None, ""}:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    raise ValueError(f"{label} must be a boolean value.")


def _resolve_int(value: object, *, label: str, minimum: int) -> int | None:
    if value in {None, ""}:
        return None
    try:
        resolved = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be an integer.") from exc
    if resolved < minimum:
        raise ValueError(f"{label} must be greater than or equal to {minimum}.")
    return resolved


def _resolve_target_path(
    cli_value: str | None,
    env_value: str | None,
    file_value: str | None,
    cwd: Path,
    config_path: Path | None,
) -> Path:
    if cli_value:
        return (cwd / cli_value).expanduser().resolve()
    if env_value:
        return (cwd / env_value).expanduser().resolve()
    if file_value:
        base_dir = config_path.parent if config_path else cwd
        return (base_dir / file_value).expanduser().resolve()
    return cwd.resolve()


def resolve_config(args) -> ResolvedConfig:
    cwd = Path.cwd()
    config_path = _resolve_config_path(getattr(args, "config", None), cwd)
    file_config = _load_config(config_path)
    provider_config = file_config.get("provider", {}) if isinstance(file_config.get("provider", {}), dict) else {}
    retrieval_config = file_config.get("retrieval", {}) if isinstance(file_config.get("retrieval", {}), dict) else {}

    target_path = _resolve_target_path(
        getattr(args, "target", None),
        os.getenv("SECURITY_AGENT_TARGET"),
        file_config.get("target_path"),
        cwd,
        config_path,
    )
    framework_override = normalize_framework(
        _pick(
            getattr(args, "framework", None),
            os.getenv("SECURITY_AGENT_FRAMEWORK"),
            file_config.get("framework"),
            default="auto",
        )
    )
    provider_name = _pick(
        getattr(args, "provider", None),
        os.getenv("SECURITY_AGENT_PROVIDER"),
        provider_config.get("name"),
    )
    model_name = _pick(
        getattr(args, "model", None),
        os.getenv("SECURITY_AGENT_MODEL"),
        provider_config.get("model"),
        default="gpt-4.1-mini",
    )
    provider_name = provider_name or infer_provider_name_from_model(model_name) or "openai"
    api_key_source = _pick(
        getattr(args, "api_key_source", None),
        os.getenv("SECURITY_AGENT_API_KEY_SOURCE"),
        provider_config.get("api_key_source"),
        default=default_api_key_source(provider_name),
    )
    output_format = _pick(
        getattr(args, "output_format", None),
        os.getenv("SECURITY_AGENT_OUTPUT_FORMAT"),
        file_config.get("output_format"),
        default="text",
    )
    if output_format not in {"text", "json"}:
        raise ValueError("Output format must be either 'text' or 'json'.")

    retrieval_enabled = _resolve_bool(
        _pick(
            getattr(args, "retrieval_enabled", None),
            os.getenv("SECURITY_AGENT_RETRIEVAL_ENABLED"),
            retrieval_config.get("enabled"),
            default="false",
        ),
        label="Retrieval enabled flag",
    )
    retrieval_max_matches = _resolve_int(
        _pick(
            getattr(args, "retrieval_limit", None),
            os.getenv("SECURITY_AGENT_RETRIEVAL_LIMIT"),
            retrieval_config.get("max_matches"),
            default="2",
        ),
        label="Retrieval match limit",
        minimum=0,
    )

    provider = normalize_provider_selection(
        ProviderSelection(
            name=provider_name,
            model=model_name,
            api_key_source=api_key_source,
        )
    )

    return ResolvedConfig(
        target_path=target_path,
        framework_override=framework_override,
        provider=provider,
        output_format=output_format,
        config_path=config_path,
        retrieval=RetrievalSettings(
            enabled=bool(retrieval_enabled),
            max_matches=retrieval_max_matches or 0,
        ),
    )