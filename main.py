#!/usr/bin/env python3
import argparse
import logging
import sys
import os

from core import __version__
from core.harness import VibeHarnessCommander, force_utf8_stdio
from core.llm_gateway import LLMGatewayError, DEFAULT_CONFIG_PATH
from core.sandbox import SandboxUnavailableError


force_utf8_stdio()


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S"
    )


def main():
    parser = argparse.ArgumentParser(
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
        sys.exit(1)

    try:
        commander = VibeHarnessCommander(config_path=args.config, execution_mode=args.mode)
    except (ValueError, SandboxUnavailableError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
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

    # Return exit code based on Quality Gate
    if summary.overall_status == "BLOCKED_CRITICAL_RISK":
        sys.exit(2)
    elif summary.overall_status == "NEEDS_FIXES":
        sys.exit(1)
    elif summary.overall_status == "INCONCLUSIVE":
        sys.exit(3)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
