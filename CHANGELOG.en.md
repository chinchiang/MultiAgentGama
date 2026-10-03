# Changelog

[正體中文（臺灣）](CHANGELOG.md) | English (US)

All notable changes to this project are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `--sarif <path>`: emit a SARIF 2.1.0 report for GitHub Code Scanning — confirmed white-box findings carry file/line locations (resolved from `line_number` or the symbol table), and confirmed black-box breaches are reported as error-level results
- Bilingual documentation and README overhaul: Mermaid pipeline architecture diagram, agent responsibility matrix, and a full configuration reference (`docs/configuration.md`); Traditional Chinese is primary with English mirrors (README.en.md, CHANGELOG.en.md, docs/configuration.en.md)

## [0.1.0] - 2026-10-03

Initial release.

### Added
- Dual-engine testing pipeline: heterogeneous multi-model white-box cross-review (Claude / Nemotron / ChatGPT / Gemini) with debate-style cross-verification (votes from non-author models, agreement-ratio computation, arbitration)
- Black-box testing: STRIDE / OWASP threat-model-driven dynamic attack tests (BOLA, Mass Assignment, Injection, etc.)
- Sandboxed execution: local subprocess and Docker containers (read-only mounts, no network by default, secret isolation via env-var allowlist, per-test re-runs after a batch timeout)
- Audit reports: Markdown and JSON (`--format md|json`) with execution provenance, `[SIMULATED]` disclosure, and evidence-gap reporting
- CLI: `--version`, `--format`, `live` / `hybrid` / `mock` modes, and quality-gate exit codes (0 / 1 / 2 / 3 / 4)
- Model fault tolerance: `fallback_model` support, graceful degradation on malformed model output (never fabricated), untested threats listed as "Threats Not Tested"
- Packaging and installation: `pip install .` registers the `vibeharness` command; version has a single source of truth in `core/__init__.py`

### Engineering
- 98 unit tests (including Docker container sandbox tests, run on CI Linux runners), ~93% code coverage
- ruff static checks with pre-commit integration
- CI matrix: ubuntu / windows × Python 3.10 / 3.13, with lint and coverage reporting
- MIT license
