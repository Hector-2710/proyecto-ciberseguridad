"""Miner CLI entry point.

Usage:
    python -m miner [--dry-run] [--only-repo REPO] [--skip-{codeql,syft,grype}]
    python __main__.py [--dry-run] ...    (from inside miner/ folder)
"""

from __future__ import annotations

import sys
from pathlib import Path

# When run as 'python __main__.py' from inside miner/, add project root
# to sys.path so that 'from miner.config import Config' resolves correctly.
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import argparse  # noqa: E402
import logging  # noqa: E402

try:
    # Running as a package: `python -m miner`
    from .config import Config  # type: ignore  # noqa: E402
    from .pipeline import MinerPipeline  # type: ignore  # noqa: E402
except ImportError:
    # Running as a script: `python miner/__main__.py`
    from miner.config import Config  # noqa: E402
    from miner.pipeline import MinerPipeline  # noqa: E402


def _setup_logging(verbose: bool = False) -> None:
    """Configure logging for the Miner pipeline.

    Args:
        verbose: If True, set level to DEBUG; otherwise INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
    )


def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser.

    Returns:
        Configured ArgumentParser.
    """
    parser = argparse.ArgumentParser(
        description="Miner: Vulnerability Extraction Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m miner --dry-run
  python -m miner --only-repo spring-boot
  python -m miner --skip-codeql --only-repo spring-framework
  python -m miner --verbose
        """,
    )
    parser.add_argument(
        "--repos-json",
        default="data/repos.json",
        help="Path to repository definitions JSON (default: data/repos.json)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without executing tools",
    )
    parser.add_argument(
        "--only-repo",
        metavar="REPO",
        help="Process only the specified repository by name",
    )
    parser.add_argument(
        "--skip-codeql",
        action="store_true",
        help="Skip CodeQL security analysis",
    )
    parser.add_argument(
        "--skip-syft",
        action="store_true",
        help="Skip Syft SBOM generation",
    )
    parser.add_argument(
        "--skip-grype",
        action="store_true",
        help="Skip Grype vulnerability detection",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Override output path for the unified dataset JSON",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Main entry point for the Miner CLI.

    Args:
        argv: Command-line arguments (uses sys.argv if None).

    Returns:
        Exit code (0 on success, 1 on error).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    _setup_logging(verbose=args.verbose)
    logger = logging.getLogger(__name__)

    try:
        config = Config(repos_json=args.repos_json)
    except FileNotFoundError as e:
        logger.error("Configuration error: %s", e)
        return 1

    logger.info("Miner v0.1.0 — %d repositories configured", len(config.repositories))

    pipeline = MinerPipeline(config)

    try:
        result = pipeline.run(
            only_repo=args.only_repo,
            skip_codeql=args.skip_codeql,
            skip_syft=args.skip_syft,
            skip_grype=args.skip_grype,
            dry_run=args.dry_run,
        )
    except KeyboardInterrupt:
        logger.warning("Pipeline interrupted by user.")
        return 130
    except Exception as e:
        logger.error("Pipeline failed: %s", e, exc_info=args.verbose)
        return 1

    # Save dataset
    if not args.dry_run and result.vulnerabilities:
        output_path = pipeline.aggregator.save()
        if output_path:
            logger.info("Dataset saved to %s", output_path)
    elif args.dry_run:
        logger.info("Dry-run complete. No files written.")

    print(f"\nDone. {result.total_vulnerabilities} vulnerabilities found "
          f"in {result.repos_processed} repositories "
          f"({result.repos_failed} failed).")

    return 0


if __name__ == "__main__":
    sys.exit(main())
