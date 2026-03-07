# Security Agent

Security Agent is a CLI-first Solidity security workflow for local repositories. The current implementation targets **Foundry** and **Hardhat** projects and combines deterministic analyzer output, bounded exploit-oriented reasoning, structured assessments, framework-aware validation candidate generation, and runner feedback from local framework execution.

This repository documents and implements the verified local pipeline described in the workspace spec. It is intentionally scoped to contributor-friendly, local-first analysis rather than a hosted service.

## Project Purpose and Current Scope

The project is building a local security-analysis CLI that can:

- detect whether a target Solidity repository uses Foundry or Hardhat,
- ingest the repository into a shared project manifest,
- run **Slither** and normalize its findings,
- build bounded, structure-aware context for a focal contract/finding,
- investigate suspicious findings to produce bounded exploit hypotheses and confidence scoring,
- generate framework-appropriate validation candidates, and
- execute those candidates to attach `validation` feedback and an explicit assessment verdict to the report.

Current scope is intentionally narrow and explicit:

- **Local CLI only** — no web app or hosted orchestration layer.
- **Solidity only** — Foundry and Hardhat are the supported frameworks.
- **Evidence first** — deterministic analyzer output and structured project context stay authoritative.
- **Hypotheses are not proof** — provider reasoning proposes exploit paths, but local validation decides whether a finding becomes verified.
- **Retrieval is optional** — the retrieval sidecar is additive and defaults off.
- **No auto-fix claims** — the tool helps find, investigate, validate, and document findings; it does not claim autonomous remediation.

## End-to-End Pipeline

1. **Repository ingestion** detects Foundry vs. Hardhat and builds a canonical `ProjectManifest` from the target repository.
2. **Structure-aware context building** narrows the scan to the relevant contract, functions, storage-sensitive state, risky external calls, and excerpts.
3. **Slither analysis** runs as the first deterministic signal source and normalizes findings into a shared schema.
4. **Report seeding** converts a selected finding plus context into a structured report shape with deterministic evidence.
5. **Investigation reasoning** uses the configured provider/model to attach bounded exploit hypotheses, exploitability judgment, and confidence scoring to the report.
6. **Optional retrieval sidecar** can attach attributed prior patterns as additive `retrieval_context` for investigation and validation candidate generation.
7. **Assessment derivation** labels the current state of the finding as `suspicious`, `hypothesis`, `high_confidence`, `verified`, `not_reproduced`, or `inconclusive` based on reasoning and validation status.
8. **Validation candidate generation** emits a framework-aware artifact, runner hint, and provenance metadata for the selected finding.
9. **Validation execution** runs the generated candidate with `forge test` or `npx hardhat test` and records a `validation` outcome such as `reproduced`, `not_reproduced`, or `inconclusive`.

## Architecture Overview

| Layer | Main modules | Responsibility |
| --- | --- | --- |
| CLI and config surface | `src/security_agent/cli.py`, `src/security_agent/config.py` | Defines `scan`, `investigate` (with backward-compatible `explain` alias), and `generate-tests`; resolves target path, provider selection, retrieval settings, and output format. |
| Repository ingestion | `src/security_agent/ingestion/repository.py`, `src/security_agent/models/project.py` | Detects Foundry/Hardhat, parses project layout/config, and produces the shared `ProjectManifest`. |
| Structure-aware context | `src/security_agent/context/structure_aware.py`, `src/security_agent/models/context.py` | Builds bounded context packs around a focal finding or contract instead of dumping the whole repository into prompts. |
| Deterministic analysis | `src/security_agent/analyzers/slither.py`, `src/security_agent/models/findings.py` | Runs Slither, captures raw execution details, and normalizes findings into a stable schema. |
| Reasoning and report assembly | `src/security_agent/llm.py`, `src/security_agent/reports.py` | Builds prompts, calls Anthropic/OpenAI-compatible providers, and persists report sections such as `provider_reasoning`, derived `assessment`, and `validation`. |
| Retrieval sidecar | `src/security_agent/retrieval.py` | Provides optional, bounded, source-attributed pattern matches from a local curated store. |
| Test generation and validation | `src/security_agent/generated_tests.py` | Generates Foundry/Hardhat candidate tests, stores metadata/provenance, and executes runner commands for validation feedback. |
| Regression coverage | `tests/` | Covers ingestion, CLI behavior, context building, Slither normalization, reports, retrieval, and generated test flows. |

## What Waves 1-3 Delivered

### Wave 1: Foundation and Deterministic Evidence

Wave 1 delivered the CLI skeleton, config surface, framework detection, Foundry/Hardhat repository ingestion, structure-aware context generation, and Slither normalization.

Practical result: the project can inspect supported repositories, build a canonical manifest, and expose normalized analyzer output through the CLI surface.

### Wave 2: Reasoning, Reports, and Validation Loop

Wave 2 delivered the provider abstraction, structured report generation, framework-aware candidate test generation, and validation execution feedback.

Practical result: the pipeline can move from deterministic findings to bounded exploit hypotheses, emit validation candidate artifacts, and record execution-backed `validation` outcomes.

### Wave 3: Optional Retrieval Memory

Wave 3 delivered an additive retrieval sidecar backed by a local curated pattern store.

Practical result: reasoning and test generation can include bounded, attributed prior vulnerability patterns without changing the core report boundary centered on deterministic evidence, `provider_reasoning`, and `validation`.

## Minimal Local Verification Guidance

Examples below assume you are running from the repository root.
The project currently targets **Python 3.11+**.

1. Confirm the CLI surface:
   - `PYTHONPATH=src python3 -m security_agent --help`
2. Confirm repository ingestion and scan wiring on the bundled examples:
   - `PYTHONPATH=src python3 -m security_agent scan --target examples/foundry-sample --format json`
   - `PYTHONPATH=src python3 -m security_agent scan --target examples/hardhat-sample --format json`
3. Investigate a normalized finding and inspect the derived assessment:
   - `PYTHONPATH=src python3 -m security_agent investigate --target examples/foundry-sample --format json`
4. Generate and execute a validation candidate:
   - `PYTHONPATH=src python3 -m security_agent generate-tests --target examples/foundry-sample --format json`

If `slither` is not installed, `scan` still returns ingestion metadata plus a stable warning payload. Broader `investigate`/`explain` and `generate-tests` flows require Slither-backed findings, and live provider/runner verification additionally depends on the external tools listed below.

## Running Security Agent End to End on Your Own Project

This section is the practical checklist for running the full local workflow against a real Solidity repository.

### What “full end-to-end” means here

For a target project, the intended live path is:

1. detect the framework (`foundry` or `hardhat`),
2. run **Slither** and normalize findings,
3. build bounded structure-aware context,
4. call the configured LLM provider for exploit-oriented reasoning,
5. generate a validation candidate,
6. execute that candidate with the project's native test runner, and
7. persist the resulting report, runner logs, and validation state.

### Prerequisites

#### 1. Python 3.11+

The project itself requires **Python 3.11 or newer**.

Recommended setup from the repository root:

- `python3.11 -m venv .venv`
- `. .venv/bin/activate`
- `python -m pip install --upgrade pip`
- `python -m pip install -e .`

After that, you can invoke the CLI as `security-agent ...` from the active virtualenv.

#### 2. Slither on `PATH`

`scan`, `investigate`, and `generate-tests` all rely on **Slither** for live analyzer-backed findings.

One simple installation path is:

- `python -m pip install slither-analyzer`

Then verify:

- `slither --version`

#### 3. A supported Solidity project

The target repository should be a local **Foundry** or **Hardhat** project.

Expected signals:

- **Foundry** project: has `foundry.toml`
- **Hardhat** project: has `hardhat.config.js` or equivalent config plus `package.json`

The contracts should already compile in their native toolchain before using Security Agent.

#### 4. Framework runner prerequisites

Security Agent generates and then executes framework-native validation candidates.

- **Foundry target**
  - `forge` must be installed and on `PATH`
  - verify with: `forge --version`

- **Hardhat target**
  - the target repo must have a **local Hardhat install**
  - the target repo should have its Node dependencies installed
  - verify with: `cd /path/to/project && npx hardhat --version`

If Hardhat fails because the Node version is too old, switch to a newer version with `nvm`, for example:

- `source "$HOME/.nvm/nvm.sh"`
- `nvm use 20`

#### 5. Provider credentials for live reasoning

For the **full** investigation path, configure a supported LLM provider key.

Examples:

- OpenAI: `export OPENAI_API_KEY=...`
- Anthropic: `export ANTHROPIC_API_KEY=...`

Without a provider key, the CLI still degrades gracefully, but `investigate` / `generate-tests` will record pending or failed provider reasoning instead of live exploit reasoning.

### Target project readiness checklist

Before running the CLI on a real contract repo, make sure:

- the repo root is the framework root,
- the contracts compile normally in the native toolchain,
- Hardhat projects already have dependencies installed,
- any environment variables required by the target project itself are already set,
- the project can tolerate generated candidate tests being written under `generated-tests/`, and
- you understand that exploit-oriented validation is most meaningful for callable/runtime findings, not purely informational findings like version or config warnings.

### Recommended first-time setup commands

From the Security Agent repo root:

1. Create and activate a virtualenv:
   - `python3.11 -m venv .venv`
   - `. .venv/bin/activate`
2. Install the CLI locally:
   - `python -m pip install --upgrade pip`
   - `python -m pip install -e .`
3. Install Slither if needed:
   - `python -m pip install slither-analyzer`
4. Verify the CLI surface:
   - `security-agent --help`

### End-to-end commands for your own project

Assume your target contract repo is at `/path/to/project`.

#### 1. Scan

- `security-agent scan --target /path/to/project --format json`

This should confirm ingestion plus normalized Slither-backed findings.

#### 2. Investigate one finding

Start without `--finding-id` to inspect what came back, then rerun with a selected finding:

- `security-agent investigate --target /path/to/project --format json`
- `security-agent investigate --target /path/to/project --finding-id <finding_id> --format json`

This produces the structured report with deterministic evidence, context, provider reasoning, and derived assessment.

#### 3. Generate and execute a validation candidate

Exploit mode:

- `security-agent generate-tests --target /path/to/project --finding-id <finding_id> --mode exploit --format json`

Invariant mode:

- `security-agent generate-tests --target /path/to/project --finding-id <finding_id> --mode invariant --format json`

Fuzz mode:

- `security-agent generate-tests --target /path/to/project --finding-id <finding_id> --mode fuzz --format json`

### Where output lands

Generated artifacts are written under a mode-specific directory like:

- `generated-tests/<framework>/<finding-id>/<mode>/`

Important files include:

- `report.json` — the updated finding report
- `generated-test.json` — artifact metadata and runner hint
- `execution-result.json` — summarized validation result
- `runner.stdout.log` — runner stdout
- `runner.stderr.log` — runner stderr
- the generated test file itself (`.t.sol` or `.test.js`)

### What success looks like

At a minimum, a healthy end-to-end run should show:

- `scan` returns normalized findings,
- `investigate` returns a report with deterministic evidence and provider reasoning,
- `generate-tests` writes a candidate artifact,
- the framework runner executes,
- the final report includes a `validation` section with a state such as:
  - `reproduced`
  - `not_reproduced`
  - `inconclusive`

### Common failure modes

- **`slither` missing**
  - `scan` will fall back to ingestion-only warnings instead of live findings.

- **Python too old**
  - use Python 3.11+; the package declares `requires-python = ">=3.11"`.

- **Hardhat installed but Node too old**
  - switch versions with `nvm use 20` and rerun.

- **`forge` missing for Foundry targets**
  - generated Foundry candidates cannot be executed without it.

- **No provider API key configured**
  - `investigate` / `generate-tests` can still run, but provider reasoning will be degraded or pending instead of live.

- **Informational or non-callable findings**
  - not every Slither finding maps cleanly to an exploit-style validation candidate.
  - findings like compiler-version or config warnings may end as `not_reproduced` or `inconclusive`, which is expected.

### Suggested GitHub-ready quickstart snippet

If you want contributors to try the project quickly, the smallest realistic sequence is:

1. `python3.11 -m venv .venv && . .venv/bin/activate`
2. `python -m pip install --upgrade pip && python -m pip install -e .`
3. `python -m pip install slither-analyzer`
4. `export OPENAI_API_KEY=...` (or `ANTHROPIC_API_KEY=...`)
5. `security-agent scan --target /path/to/project --format json`
6. `security-agent investigate --target /path/to/project --finding-id <finding_id> --format json`
7. `security-agent generate-tests --target /path/to/project --finding-id <finding_id> --mode exploit --format json`