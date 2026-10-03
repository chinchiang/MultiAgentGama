#!/usr/bin/env python3
import argparse
import logging
import sys
import os

from core import __version__
from core.harness import VibeHarnessCommander, force_utf8_stdio
from core.llm_gateway import LLMGatewayError, ConfigError, DEFAULT_CONFIG_PATH
from core.sandbox import SandboxUnavailableError

# Exit codes reserved for harness/usage problems. Verdict codes (0/1/2/3/4) are documented in
# the README; these must never collide with them, or CI would misread a crashed run as a verdict.
USAGE_ERROR_EXIT_CODE = 5


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
        default="http://localhost:8000",
        help="Base URL for dynamic black-box testing (default: 'http://localhost:8000')"
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

    try:
        commander = VibeHarnessCommander(config_path=args.config, execution_mode=args.mode)
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
    except Exception as e:
        # A crashed run must never fall through to exit code 1, which CI reads as NEEDS_FIXES
        print(f"Error: harness crashed unexpectedly: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(USAGE_ERROR_EXIT_CODE)

    # Return exit code based on Quality Gate
    if summary.overall_status not in _VERDICT_STATUSES:
        print(f"Error: unknown overall status '{summary.overall_status}'; failing closed.", file=sys.stderr)
    sys.exit(verdict_exit_code(summary.overall_status))


if __name__ == "__main__":
    main()
