"""Pipeline orchestrator for the Miner component.

Coordinates the four analysis stages (clone, CodeQL, Syft, Grype)
across all configured repositories and produces a unified dataset.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from miner.aggregator import Aggregator
from miner.cloner import clone_repo
from miner.codeql_scanner import run_codeql_scan
from miner.config import Config
from miner.grype_scanner import GrypeScanner
from miner.models import PipelineResult, StepResult, Vulnerability
from miner.syft_scanner import SyftScanner

LOGGER = logging.getLogger(__name__)


class MinerPipeline:
    """Orchestrates the full vulnerability extraction pipeline.

    Processes each repository through four stages:
    1. Git clone (shallow)
    2. CodeQL security analysis
    3. Syft SBOM generation
    4. Grype dependency vulnerability detection

    The pipeline supports resumption — already-completed steps are
    detected and skipped automatically.

    Attributes:
        config: Pipeline configuration with repo definitions and paths.
        aggregator: Vulnerability and result collector.
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self.aggregator = Aggregator(config)

    def run(
        self,
        *,
        only_repo: str | None = None,
        skip_codeql: bool = False,
        skip_syft: bool = False,
        skip_grype: bool = False,
        dry_run: bool = False,
    ) -> PipelineResult:
        """Execute the full pipeline across all configured repositories.

        Args:
            only_repo: If set, process only this repository name.
            skip_codeql: Skip the CodeQL analysis stage.
            skip_syft: Skip the Syft SBOM generation stage.
            skip_grype: Skip the Grype vulnerability detection stage.
            dry_run: If True, log what would be done without executing.

        Returns:
            PipelineResult with all findings and execution summary.
        """
        repos = self.config.repositories

        if only_repo:
            repos = [r for r in repos if self.config.repo_name_from_path(r["path"]) == only_repo]
            if not repos:
                LOGGER.warning("Repository '%s' not found in configuration.", only_repo)
                return PipelineResult()

        LOGGER.info(
            "Miner pipeline starting: %d repos, codeql=%s, syft=%s, grype=%s, dry_run=%s",
            len(repos),
            not skip_codeql,
            not skip_syft,
            not skip_grype,
            dry_run,
        )

        started_at = datetime.now(timezone.utc).isoformat()

        for idx, repo in enumerate(repos, start=1):
            repo_name = self.config.repo_name_from_path(repo["path"])
            repo_path = self.config.repo_dir(repo_name)
            url = repo["url"]

            LOGGER.info("=" * 60)
            LOGGER.info("[%d/%d] Processing repository: %s", idx, len(repos), repo_name)

            # Stage 1: Clone (with error isolation)
            try:
                clone_result = self._stage_clone(url, repo_path, dry_run)
                self.aggregator.add_step_results([clone_result])
            except Exception as e:
                LOGGER.error("Unexpected error cloning %s: %s", repo_name, e)
                clone_result = StepResult(
                    repo_name=repo_name,
                    step_name="clone",
                    status="failed",
                    error_message=str(e),
                )
                self.aggregator.add_step_results([clone_result])

            if clone_result.status == "failed" and not dry_run:
                LOGGER.warning("Skipping remaining stages for %s (clone failed)", repo_name)
                continue

            # Stage 2: CodeQL (with error isolation)
            if not skip_codeql:
                try:
                    codeql_vulns, codeql_results = self._stage_codeql(
                        repo_path, repo_name, dry_run
                    )
                    self.aggregator.add_codeql_results(codeql_vulns)
                    self.aggregator.add_step_results(codeql_results)
                except Exception as e:
                    LOGGER.error("Unexpected error in CodeQL stage for %s: %s", repo_name, e)
                    self.aggregator.add_step_results([
                        StepResult(
                            repo_name=repo_name,
                            step_name="codeql",
                            status="failed",
                            error_message=str(e),
                        )
                    ])

            # Stage 3: Syft (with error isolation)
            if not skip_syft:
                try:
                    syft_result = self._stage_syft(repo_path, dry_run)
                    self.aggregator.add_step_results([syft_result])
                except Exception as e:
                    LOGGER.error("Unexpected error in Syft stage for %s: %s", repo_name, e)
                    self.aggregator.add_step_results([
                        StepResult(
                            repo_name=repo_name,
                            step_name="syft",
                            status="failed",
                            error_message=str(e),
                        )
                    ])

        # Stage 4: Grype (runs once on all SBOMs)
        if not skip_grype and not dry_run:
            grype_vulns, grype_results = self._stage_grype()
            self.aggregator.add_grype_results(grype_vulns)
            self.aggregator.add_step_results(grype_results)

        result = self.aggregator.build_dataset()
        result.started_at = started_at
        result.finalize()

        LOGGER.info("=" * 60)
        LOGGER.info("Pipeline complete. %d vulnerabilities found.", result.total_vulnerabilities)
        LOGGER.info("%s", self.aggregator.summary())

        return result

    def _stage_clone(self, url: str, repo_path: Path, dry_run: bool) -> StepResult:
        """Execute or simulate the clone stage.

        Args:
            url: Git remote URL.
            repo_path: Local target directory path.
            dry_run: If True, only log the action.

        Returns:
            StepResult for the clone stage.
        """
        repo_name = repo_path.name

        if dry_run:
            LOGGER.info("  [DRY-RUN] Would clone %s → %s", url, repo_path)
            return StepResult(
                repo_name=repo_name,
                step_name="clone",
                status="skipped",
            )

        return clone_repo(url, repo_path)

    def _stage_codeql(
        self, repo_path: Path, repo_name: str, dry_run: bool
    ) -> tuple[list[Vulnerability], list[StepResult]]:
        """Execute or simulate the CodeQL analysis stage.

        Args:
            repo_path: Absolute path to the cloned repository.
            repo_name: Repository name.
            dry_run: If True, only log the action.

        Returns:
            Tuple of (vulnerability list, step result list).
        """

        if dry_run:
            LOGGER.info("  [DRY-RUN] Would run CodeQL on %s", repo_name)
            return [], [
                StepResult(repo_name=repo_name, step_name="codeql", status="skipped")
            ]

        return run_codeql_scan(
            repo_path=repo_path,
            db_dir=self.config.codeql_db_dir,
            output_dir=self.config.codeql_output,
            repo_name=repo_name,
        )

    def _stage_syft(self, repo_path: Path, dry_run: bool) -> StepResult:
        """Execute or simulate the Syft SBOM stage for a single repo.

        Args:
            repo_path: Absolute path to the cloned repository.
            dry_run: If True, only log the action.

        Returns:
            StepResult for the Syft stage.
        """
        repo_name = repo_path.name

        if dry_run:
            LOGGER.info("  [DRY-RUN] Would run Syft on %s", repo_name)
            return StepResult(repo_name=repo_name, step_name="syft", status="skipped")

        # Check if SBOM already exists (resumability)
        expected_output = self.config.sbom_output / f"{repo_name}.json"
        if expected_output.exists():
            LOGGER.info("SBOM already exists for %s, skipping Syft.", repo_name)
            return StepResult(
                repo_name=repo_name,
                step_name="syft",
                status="skipped",
                output_path=str(expected_output.relative_to(self.config.project_root)),
            )

        scanner = SyftScanner(
            repos_path=str(repo_path.parent),
            output_path=str(self.config.sbom_output),
        )

        try:
            sbom_data = scanner.generate_sbom(str(repo_path.relative_to(scanner.project_root)))
            output_file = scanner.save_sbom(repo_name, sbom_data)
            return StepResult(
                repo_name=repo_name,
                step_name="syft",
                status="success",
                output_path=str(output_file),
            )
        except Exception as e:
            LOGGER.error("Syft failed for %s: %s", repo_name, e)
            return StepResult(
                repo_name=repo_name,
                step_name="syft",
                status="failed",
                error_message=str(e),
            )

    def _stage_grype(self) -> tuple[list[Vulnerability], list[StepResult]]:
        """Execute the Grype vulnerability detection stage on all SBOMs.

        Returns:
            Tuple of (vulnerability list, step result list).
        """
        if not self.config.sbom_output.exists() or not list(
            self.config.sbom_output.glob("*.json")
        ):
            LOGGER.warning("No SBOMs found for Grype analysis. Run Syft first.")
            return [], []

        scanner = GrypeScanner(
            sboms_dir=str(self.config.sbom_output),
            output_dir=str(self.config.vuln_output),
        )

        return scanner.run()
