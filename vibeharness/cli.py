#!/usr/bin/env python3
import argparse
import logging
import sys
import os
import traceback

from vibeharness import __version__
from vibeharness.core.harness import VibeHarnessCommander, force_utf8_stdio
from vibeharness.core.llm_gateway import LLMGatewayError, ConfigError, DEFAULT_CONFIG_PATH
from vibeharness.core.sandbox import SandboxUnavailableError
from vibeharness.agents.blackbox.scenario_builder import validate_base_url
from vibeharness.core.baseline import load_baseline

# Exit codes reserved for harness/usage problems. Verdict codes (0/1/2/3/4) are documented in
# the README; these must never collide with them, or CI would misread a crashed run as a verdict.
USAGE_ERROR_EXIT_CODE = 5
# Ctrl-C: the conventional 128 + SIGINT, distinct from every verdict and usage code
INTERRUPTED_EXIT_CODE = 130


class _UsageErrorParser(argparse.ArgumentParser):
    """argparse exits 2 on usage errors by default, which collides with BLOCKED_CRITICAL_RISK."""

    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        sys.exit(USAGE_ERROR_EXIT_CODE)


force_utf8_stdio()


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S"
    )


_VERDICT_STATUSES = ("BLOCKED_CRITICAL_RISK", "NEEDS_FIXES", "INCONCLUSIVE", "READY_TO_SHIP")


def verdict_exit_code(overall_status: str) -> int:
    """Maps a quality-gate verdict to its CLI exit code.

    Unknown verdict strings fail closed with the INCONCLUSIVE code (3), never with
    READY_TO_SHIP (0) — an unrecognized verdict must not read as a clean bill of health.
    """
    if overall_status == "BLOCKED_CRITICAL_RISK":
        return 2
    if overall_status == "NEEDS_FIXES":
        return 1
    if overall_status == "READY_TO_SHIP":
        return 0
    # INCONCLUSIVE and any unrecognized status
    return 3


def _writable_location(path: str) -> bool:
    """True when `path` can be created or overwritten: its directory exists and is writable."""
    target = os.path.abspath(path)
    if os.path.isdir(target):
        return False
    if os.path.exists(target):
        return os.access(target, os.W_OK)
    return os.access(os.path.dirname(target) or os.curdir, os.W_OK)


def main():
    parser = _UsageErrorParser(
        description="[VibeHarness-MAS] Multi-Agent White-Box & Black-Box Testing Harness for Vibe Coding"
    )
    parser.add_argument(
        "--target", "-t",
        default="examples",
        help="Directory or file of the target codebase to audit and test (default: 'examples')"
    )
    parser.add_argument(
        "--base-url", "-u",
        default=None,
        help="Base URL of a running instance of the target for live HTTP black-box attacks "
             "(e.g. 'http://localhost:8000'). Without it, black-box tests import the target in-process; "
             "a default is never probed, so attacks cannot hit an unrelated local service"
    )
    parser.add_argument(
        "--output", "-o",
        default="vibe_harness_report.md",
        help="Output path for the generated Markdown audit report (default: 'vibe_harness_report.md')"
    )
    parser.add_argument(
        "--desc", "-d",
        default=None,
        help="High-level description of the system for Threat Modeling guidance"
    )
    parser.add_argument(
        "--config", "-c",
        default=DEFAULT_CONFIG_PATH,
        help="Path to agents and models configuration YAML (default: the repo's config/agents_config.yaml)"
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["live", "hybrid", "mock"],
        default=None,
        help="Override execution_mode from config: live (real APIs only, fail otherwise), hybrid, or mock"
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Override global.max_files: number of source files analyzed (the rest are reported as skipped)"
    )
    parser.add_argument(
        "--max-model-calls",
        type=int,
        default=None,
        help="Override global.max_model_calls: cost guard on live model invocations per run (0 = unlimited)"
    )
    parser.add_argument(
        "--include",
        action="append",
        metavar="GLOB",
        default=None,
        help="Only analyze source files whose path (relative to --target) or name matches this glob; "
             "repeatable. Overrides global.include from the config"
    )
    parser.add_argument(
        "--exclude",
        action="append",
        metavar="GLOB",
        default=None,
        help="Skip source files whose path or name matches this glob (e.g. 'tests/*', 'vendor/*'); "
             "repeatable. Overrides global.exclude from the config"
    )
    parser.add_argument(
        "--changed-since",
        metavar="GIT_REF",
        default=None,
        help="Only analyze files under --target that changed since this git ref (committed, staged, "
             "unstaged or untracked), e.g. 'origin/main' in a PR check; the target must be inside a git repo"
    )
    parser.add_argument(
        "--baseline",
        metavar="REPORT_JSON",
        default=None,
        help="A previous --format json report: findings, breaches and HIGH+ rule hits it already contains are "
             "listed but no longer decide the verdict / exit code, so CI reacts to new problems only "
             "(a .partial.json from a crashed run is refused)"
    )
    parser.add_argument(
        "--cache-dir",
        metavar="DIR",
        default=None,
        help="Cache usable live model answers in DIR (created if missing) and reuse them on later runs with the "
             "same model, settings and prompt; a cache hit makes no provider call and costs no budget. "
             "Overrides global.cache_dir. The directory holds raw model answers: treat it like the reports"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["md", "json"],
        default="md",
        help="Report format written to --output: Markdown (default) or machine-readable JSON"
    )
    parser.add_argument(
        "--sarif",
        metavar="PATH",
        default=None,
        help="Also write a SARIF 2.1.0 report to PATH for GitHub Code Scanning (upload via github/codeql-action)"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    target_path = os.path.abspath(args.target)
    if not os.path.exists(target_path):
        print(f"Error: Target path '{target_path}' does not exist.", file=sys.stderr)
        sys.exit(USAGE_ERROR_EXIT_CODE)

    if args.max_files is not None and args.max_files < 1:
        parser.error("--max-files must be at least 1")
    if args.max_model_calls is not None and args.max_model_calls < 0:
        parser.error("--max-model-calls must not be negative")
    if args.base_url is not None:
        try:
            args.base_url = validate_base_url(args.base_url)
        except ValueError as e:
            parser.error(f"--base-url: {e}")
    # Fail before any model call is paid for, not after the whole pipeline ran
    for flag, path in (("--output", args.output), ("--sarif", args.sarif)):
        if path is not None and not _writable_location(path):
            parser.error(f"{flag}: cannot write to '{path}' (directory missing or not writable)")
    try:
        commander = VibeHarnessCommander(config_path=args.config, execution_mode=args.mode)
        if args.max_files is not None:
            commander.max_files = args.max_files
        if args.max_model_calls is not None:
            commander.gateway.max_model_calls = args.max_model_calls or None
        if args.include is not None:
            commander.include_patterns = args.include
        if args.exclude is not None:
            commander.exclude_patterns = args.exclude
        if args.changed_since:
            commander.changed_since = args.changed_since
        if args.cache_dir:
            commander.gateway.set_cache_dir(args.cache_dir)
        if args.baseline:
            commander.baseline = load_baseline(args.baseline)
    except (ConfigError, ValueError, SandboxUnavailableError) as e:
        print(f"Error: harness configuration problem: {e}", file=sys.stderr)
        sys.exit(USAGE_ERROR_EXIT_CODE)
    try:
        summary = commander.run_full_pipeline(
            target_dir=target_path,
            system_description=args.desc,
            base_url=args.base_url,
            output_report_path=args.output,
            output_format=args.format,
            output_sarif_path=args.sarif
        )
    except LLMGatewayError as e:
        print(f"Error: live model invocation failed in strict 'live' mode: {e}", file=sys.stderr)
        sys.exit(4)
    except ValueError as e:
        # e.g. an unresolvable --changed-since ref: a usage problem found once the run started
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(USAGE_ERROR_EXIT_CODE)
    except KeyboardInterrupt:
        print("Interrupted; no full report was written (a .partial.json may exist next to --output; "
              "in-flight model calls may take a moment to stop).", file=sys.stderr)
        sys.exit(INTERRUPTED_EXIT_CODE)
    except Exception as e:
        # A crashed run must never fall through to exit code 1, which CI reads as NEEDS_FIXES
        traceback.print_exc(file=sys.stderr)
        print(f"Error: harness crashed unexpectedly: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(USAGE_ERROR_EXIT_CODE)

    # Return exit code based on Quality Gate
    if summary.overall_status not in _VERDICT_STATUSES:
        print(f"Error: unknown overall status '{summary.overall_status}'; failing closed.", file=sys.stderr)
    sys.exit(verdict_exit_code(summary.overall_status))


if __name__ == "__main__":
    main()
