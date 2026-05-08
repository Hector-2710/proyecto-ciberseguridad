"""Configuration management for the Miner pipeline.

Loads repository definitions and resolves all filesystem paths.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class Config:
    """Miner configuration loaded from repos.json.

    Attributes:
        project_root: Absolute path to the project root directory.
        repos_json: Path to the repository definitions JSON.
        repos_dir: Directory where repositories are cloned.
        results_dir: Root directory for all pipeline outputs.
        codeql_output: Directory for CodeQL SARIF results.
        sbom_output: Directory for Syft SBOM JSON files.
        vuln_output: Directory for Grype vulnerability reports.
        dataset_output: Path to the final unified dataset JSON.
        codeql_db_dir: Directory for temporary CodeQL databases.
        repositories: List of repository definitions (url, path).
    """

    def __init__(
        self,
        repos_json: str = "data/repos.json",
        repos_dir: str = "data/repos",
        results_dir: str = "data/results",
    ) -> None:
        self.project_root = Path(__file__).resolve().parent
        self.repos_json = self.project_root / repos_json
        self.repos_dir = self.project_root / repos_dir
        self.results_dir = self.project_root / results_dir

        self.codeql_output = self.results_dir / "codeql"
        self.sbom_output = self.results_dir / "sboms"
        self.vuln_output = self.results_dir / "vulnerabilities"
        self.dataset_output = self.results_dir / "miner_dataset.json"

        self.codeql_db_dir = self.project_root / "data" / "codeql-dbs"

        self.repositories: list[dict[str, str]] = self._load_repos()

    def _load_repos(self) -> list[dict[str, str]]:
        """Load repository definitions from the JSON configuration file.

        Returns:
            List of repository dicts with 'url' and 'path' keys.

        Raises:
            FileNotFoundError: If the repos.json file does not exist.
        """
        if not self.repos_json.exists():
            raise FileNotFoundError(f"Repository config not found: {self.repos_json}")

        with open(self.repos_json, encoding="utf-8") as f:
            data: dict[str, Any] = json.load(f)

        repos: list[dict[str, str]] = data.get("repositories", [])
        return repos

    def repo_name_from_path(self, repo_path: str) -> str:
        """Extract repository name from its filesystem path.

        Args:
            repo_path: Relative path string (e.g. "data/repos/spring-boot").

        Returns:
            Repository name (e.g. "spring-boot").
        """
        return Path(repo_path).name

    def repo_dir(self, repo_name: str) -> Path:
        """Get the absolute filesystem path for a repository.

        Args:
            repo_name: Repository name.

        Returns:
            Absolute Path to the repository directory.
        """
        return self.repos_dir / repo_name
