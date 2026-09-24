#!/usr/bin/env python3
import argparse
import logging
import sys
import os

from core.harness import VibeHarnessCommander


if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


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
        default="config/agents_config.yaml",
        help="Path to agents and models configuration YAML"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging"
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    target_path = os.path.abspath(args.target)
    if not os.path.exists(target_path):
        print(f"Error: Target path '{target_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    commander = VibeHarnessCommander(config_path=args.config)
    summary = commander.run_full_pipeline(
        target_dir=target_path,
        system_description=args.desc,
        base_url=args.base_url,
        output_report_path=args.output
    )

    # Return exit code based on Quality Gate
    if summary.overall_status == "BLOCKED_CRITICAL_RISK":
        sys.exit(2)
    elif summary.overall_status == "NEEDS_FIXES":
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
