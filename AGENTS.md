# AGENTS.md

Before changing code, read `CODING_STANDARDS.en.md` (the rules review applies; `CODING_STANDARDS.md` is the zh twin) and `CONTRIBUTING.md` (checks to run, steps for design references and dependencies, releases).

Pushing a `v*` tag publishes to PyPI, and PyPI versions are immutable: tag only when the user explicitly asks for that release.

## Agent skills

### Issue tracker

Issues are tracked in GitHub Issues for chinchiang/MultiAgentGama (via the `gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
