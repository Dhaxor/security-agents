from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..models.project import ProjectManifest
from ..models.findings import FindingLocation, NormalizedFinding

_IMPACT_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
}
_CONFIDENCE_MAP = {"high": "high", "medium": "medium", "low": "low"}


@dataclass(slots=True)
class SlitherScanResult:
    command: list[str]
    target_path: str
    return_code: int
    stdout: str
    stderr: str
    raw_output: dict[str, Any] | None
    findings: list[NormalizedFinding]

    def to_dict(self) -> dict[str, Any]:
        success = self.return_code == 0 and ((self.raw_output or {}).get("success") is not False)
        error = (self.raw_output or {}).get("error")
        return {
            "tool": "slither",
            "command": self.command,
            "target_path": self.target_path,
            "return_code": self.return_code,
            "success": success,
            "error": error,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "raw_output": self.raw_output,
            "findings": [finding.to_dict() for finding in self.findings],
            "status": "ok" if success and error is None else "error",
        }


def build_slither_command(
    manifest: ProjectManifest | str | Path,
    *,
    json_output_path: str | Path,
    slither_binary: str = "slither",
    extra_args: Sequence[str] = (),
) -> list[str]:
    return [
        slither_binary,
        str(resolve_target_path(manifest)),
        "--json",
        str(json_output_path),
        *extra_args,
    ]


def resolve_target_path(manifest: ProjectManifest | str | Path) -> Path:
    if isinstance(manifest, ProjectManifest):
        return Path(manifest.root_path).resolve()
    return Path(manifest).resolve()


def run_slither(
    manifest: ProjectManifest | str | Path,
    *,
    cwd: str | Path | None = None,
    slither_binary: str = "slither",
    extra_args: Sequence[str] = (),
) -> SlitherScanResult:
    with tempfile.TemporaryDirectory(prefix="slither-") as tmp_dir:
        json_output_path = Path(tmp_dir) / "results.json"
        command = build_slither_command(
            manifest,
            json_output_path=json_output_path,
            slither_binary=slither_binary,
            extra_args=extra_args,
        )
        completed = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            check=False,
        )
        raw_output = _load_json(json_output_path)
    return SlitherScanResult(
        command=command,
        target_path=str(resolve_target_path(manifest)),
        return_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        raw_output=raw_output,
        findings=normalize_slither_output(raw_output),
    )


def normalize_slither_output(raw_output: Mapping[str, Any] | None) -> list[NormalizedFinding]:
    detectors = (((raw_output or {}).get("results") or {}).get("detectors") or [])
    findings = [_normalize_detector(detector) for detector in detectors]
    return _deduplicate(findings)


def _normalize_detector(detector: Mapping[str, Any]) -> NormalizedFinding:
    rule_id = str(detector.get("check") or "unknown")
    locations = [
        location
        for element in detector.get("elements", [])
        if (location := _location_from_element(element)) is not None
    ]
    description = str(detector.get("description") or "").strip()
    dedupe_key = _make_dedupe_key(rule_id, locations, detector.get("elements", []))
    fingerprint = hashlib.sha256(f"slither|{dedupe_key}|{description}".encode("utf-8")).hexdigest()[:16]
    metadata = {
        "impact_raw": detector.get("impact"),
        "confidence_raw": detector.get("confidence"),
        "elements": len(detector.get("elements", [])),
    }
    if detector.get("additional_fields") is not None:
        metadata["additional_fields"] = detector["additional_fields"]
    return NormalizedFinding(
        fingerprint=fingerprint,
        source="slither",
        rule_id=rule_id,
        title=rule_id.replace("-", " ").replace("_", " ").title(),
        severity=_normalize_level(str(detector.get("impact") or ""), _IMPACT_MAP, default="unknown"),
        confidence=_normalize_level(
            str(detector.get("confidence") or ""), _CONFIDENCE_MAP, default="unknown"
        ),
        description=description,
        locations=locations,
        dedupe_key=dedupe_key,
        metadata=metadata,
    )


def _location_from_element(element: Mapping[str, Any]) -> FindingLocation | None:
    source_mapping = element.get("source_mapping") or {}
    file_path = (
        source_mapping.get("filename_relative")
        or source_mapping.get("filename_short")
        or source_mapping.get("filename_used")
        or source_mapping.get("filename_absolute")
    )
    if not file_path:
        return None
    return FindingLocation(
        file_path=str(file_path),
        lines=[int(line) for line in source_mapping.get("lines", []) if isinstance(line, int)],
        start=_as_int(source_mapping.get("start")),
        length=_as_int(source_mapping.get("length")),
        starting_column=_as_int(source_mapping.get("starting_column")),
        ending_column=_as_int(source_mapping.get("ending_column")),
    )


def _make_dedupe_key(
    rule_id: str,
    locations: list[FindingLocation],
    elements: Sequence[Mapping[str, Any]],
) -> str:
    primary = locations[0].to_dict() if locations else {}
    names = sorted({str(element.get("name") or "") for element in elements if element.get("name")})
    return json.dumps({"rule_id": rule_id, "primary": primary, "names": names}, sort_keys=True)


def _deduplicate(findings: Sequence[NormalizedFinding]) -> list[NormalizedFinding]:
    ordered = sorted(findings, key=lambda finding: (finding.rule_id, finding.dedupe_key, finding.description))
    seen: set[str] = set()
    deduped: list[NormalizedFinding] = []
    for finding in ordered:
        if finding.dedupe_key in seen:
            continue
        seen.add(finding.dedupe_key)
        deduped.append(finding)
    return deduped


def _normalize_level(value: str, mapping: Mapping[str, str], *, default: str) -> str:
    return mapping.get(value.strip().lower(), default)


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists() or path.stat().st_size == 0:
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _as_int(value: Any) -> int | None:
    return value if isinstance(value, int) else None