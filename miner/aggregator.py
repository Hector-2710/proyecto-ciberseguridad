"""Vulnerability aggregation for the Miner pipeline.

Combines results from CodeQL, Syft, and Grype into a unified
structured dataset with deduplication and severity-based sorting.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from miner.config import Config
from miner.models import PipelineResult, StepResult, Vulnerability

LOGGER = logging.getLogger(__name__)

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "unknown": 4,
}


class Aggregator:
    """Collects and combines vulnerability findings from all pipeline tools.

    Attributes:
        vulnerabilities: Accumulated vulnerability records.
        step_results: Accumulated per-step execution results.
        config: Pipeline configuration reference.
    """

    def __init__(self, config: Config) -> None:
        self.vulnerabilities: list[Vulnerability] = []
        self.step_results: list[StepResult] = []
        self.config = config

    def add_codeql_results(self, vulns: list[Vulnerability]) -> None:
        """Add CodeQL findings to the aggregator.

        Args:
            vulns: List of Vulnerability objects from CodeQL scanning.
        """
        self.vulnerabilities.extend(vulns)

    def add_grype_results(self, vulns: list[Vulnerability]) -> None:
        """Add Grype dependency vulnerability findings.

        Args:
            vulns: List of Vulnerability objects from Grype analysis.
        """
        self.vulnerabilities.extend(vulns)

    def add_step_results(self, results: list[StepResult]) -> None:
        """Add step execution results for the pipeline summary.

        Args:
            results: List of StepResult objects.
        """
        self.step_results.extend(results)

    def build_dataset(self) -> PipelineResult:
        """Build the final pipeline result with sorted, deduplicated vulnerabilities.

        Returns:
            PipelineResult containing all findings and execution summary.
        """
        self._sort_by_severity()

        result = PipelineResult(
            vulnerabilities=self.vulnerabilities,
            step_results=self.step_results,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        result.finalize()

        LOGGER.info(
            "Dataset built: %d vulnerabilities, %d step results, %d repos processed",
            result.total_vulnerabilities,
            len(result.step_results),
            result.repos_processed,
        )

        return result

    def save(self, output_path: Path | None = None) -> str:
        """Save the unified dataset as a JSON file.

        Args:
            output_path: Destination path. Uses config default if None.

        Returns:
            Absolute path to the saved file.

        Raises:
            ValueError: If there are no vulnerabilities to save.
        """
        if not self.vulnerabilities:
            LOGGER.warning("No vulnerabilities to save.")
            return ""

        path = output_path or self.config.dataset_output
        path.parent.mkdir(parents=True, exist_ok=True)

        result = self.build_dataset()

        with open(path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False, default=str)

        LOGGER.info("Unified dataset saved to %s", path)
        return str(path.resolve())

    def _sort_by_severity(self) -> None:
        """Sort vulnerabilities by severity (critical first), then by repository name."""
        self.vulnerabilities.sort(
            key=lambda v: (
                _SEVERITY_ORDER.get(v.severity, 4),
                v.repository,
                v.vulnerability_id,
            )
        )

    def summary(self) -> str:
        """Generate a human-readable summary of collected vulnerabilities.

        Returns:
            Multi-line summary string.
        """
        if not self.vulnerabilities:
            return "No vulnerabilities found."

        by_severity: dict[str, int] = {}
        by_tool: dict[str, int] = {}
        by_repo: dict[str, int] = {}

        for v in self.vulnerabilities:
            by_severity[v.severity] = by_severity.get(v.severity, 0) + 1
            by_tool[v.source_tool] = by_tool.get(v.source_tool, 0) + 1
            by_repo[v.repository] = by_repo.get(v.repository, 0) + 1

        lines = [
            f"Total vulnerabilities: {len(self.vulnerabilities)}",
            "",
            "By Severity:",
        ]
        for sev in ["critical", "high", "medium", "low", "unknown"]:
            count = by_severity.get(sev, 0)
            if count:
                lines.append(f"  {sev}: {count}")

        lines.append("")
        lines.append("By Tool:")
        for tool, count in sorted(by_tool.items()):
            lines.append(f"  {tool}: {count}")

        lines.append("")
        lines.append("Top Repositories:")
        top_repos = sorted(by_repo.items(), key=lambda x: x[1], reverse=True)[:10]
        for repo, count in top_repos:
            lines.append(f"  {repo}: {count}")

        return "\n".join(lines)
