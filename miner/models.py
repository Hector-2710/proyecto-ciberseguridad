"""Data models for the Miner pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


@dataclass
class Vulnerability:
    """A single vulnerability finding from any analysis tool.

    Attributes:
        vulnerability_id: Unique identifier (CVE ID, CodeQL rule ID, or GHSA ID).
        type: Category of finding ("codeql", "dependency", or "sbom_anomaly").
        source_tool: Tool that produced this finding ("codeql", "grype", "syft").
        repository: Source repository name (e.g. "spring-boot").
        location: File path and line number where vulnerability was found.
        severity: Canonical severity level.
        description: Human-readable explanation of the vulnerability.
        cwe_id: Common Weakness Enumeration identifier, if available.
        package_name: Affected dependency name (for dependency vulnerabilities).
        installed_version: Currently installed version of the affected package.
        fixed_version: Version that resolves the vulnerability, if known.
        detected_at: ISO-8601 timestamp of detection.
    """

    vulnerability_id: str
    type: str
    source_tool: str
    repository: str
    location: str
    severity: str
    description: str
    cwe_id: str | None = None
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class StepResult:
    """Result of a single pipeline step for one repository.

    Attributes:
        repo_name: Name of the repository processed.
        step_name: Name of the pipeline step ("clone", "codeql", "syft", "grype").
        status: Outcome status ("success", "failed", "skipped").
        output_path: Path to generated output file, if applicable.
        error_message: Error description if the step failed.
    """

    repo_name: str
    step_name: str
    status: str
    output_path: str | None = None
    error_message: str | None = None


@dataclass
class PipelineResult:
    """Aggregated result of a full Miner pipeline run.

    Attributes:
        vulnerabilities: All vulnerability findings discovered.
        step_results: Per-repo, per-step execution results.
        repos_processed: Number of repositories successfully processed.
        repos_failed: Number of repositories that failed entirely.
        total_vulnerabilities: Total count of vulnerability findings.
        started_at: ISO-8601 timestamp of pipeline start.
        finished_at: ISO-8601 timestamp of pipeline completion.
    """

    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    step_results: list[StepResult] = field(default_factory=list)
    repos_processed: int = 0
    repos_failed: int = 0
    total_vulnerabilities: int = 0
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: str = ""

    def finalize(self) -> None:
        """Mark pipeline as complete and compute summary statistics."""
        self.finished_at = datetime.now(timezone.utc).isoformat()
        self.total_vulnerabilities = len(self.vulnerabilities)
        success_steps = [r for r in self.step_results if r.status == "success"]
        processed_repos = {r.repo_name for r in success_steps}
        failed_repos = {r.repo_name for r in self.step_results if r.status == "failed"}
        self.repos_processed = len(processed_repos - failed_repos)
        self.repos_failed = len(failed_repos)

    def to_dict(self) -> dict[str, Any]:
        """Convert entire result to a serializable dictionary."""
        return {
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "summary": {
                "step_results": [asdict(s) for s in self.step_results],
                "repos_processed": self.repos_processed,
                "repos_failed": self.repos_failed,
                "total_vulnerabilities": self.total_vulnerabilities,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
            },
        }
