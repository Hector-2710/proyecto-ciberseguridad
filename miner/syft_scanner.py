"""SBOM generation using Syft for the Miner pipeline.

Refactored from scripts/generate_sboms.py — class-based, with dry-run support,
ANSI stripping, and JSON normalization.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from pathlib import Path

from models import StepResult

LOGGER = logging.getLogger(__name__)

SYFT_OUTPUT_FORMAT = "syft-json"
SBOM_FILE_SUFFIX = ".json"
SYFT_TIMEOUT_SECONDS = 300

_ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


class SyftScanner:
    """Generates Software Bill of Materials (SBOM) using Syft CLI.

    Scans a directory of cloned repositories and produces Syft-format
    JSON SBOM files for each.

    Attributes:
        repos_path: Directory containing cloned repositories.
        output_path: Directory where SBOM JSON files will be written.
        dry_run: If True, only logs what would be done without executing.
    """

    def __init__(self, repos_path: str | Path, output_path: str | Path) -> None:
        self.repos_path = Path(repos_path).expanduser().resolve()
        self.output_path = Path(output_path).expanduser().resolve()
        self.project_root = Path(__file__).resolve().parent
        self.dry_run: bool = False

    def discover_repositories(self) -> list[str]:
        """Find all repository directories to scan.

        Returns:
            Sorted list of relative paths to repository directories.

        Raises:
            FileNotFoundError: If the repos directory does not exist.
        """
        if not self.repos_path.exists():
            raise FileNotFoundError(f"Repositories directory not found: {self.repos_path}")
        if not self.repos_path.is_dir():
            raise NotADirectoryError(f"Not a directory: {self.repos_path}")

        repos = sorted(
            str(p.relative_to(self.project_root))
            for p in self.repos_path.iterdir()
            if p.is_dir()
        )

        if not repos:
            LOGGER.warning("No repositories found in %s", self.repos_path)

        return repos

    def generate_sbom(self, repo_path: str) -> str:
        """Run Syft against a single repository and return the SBOM JSON.

        Args:
            repo_path: Relative path to the repository from project root.

        Returns:
            Normalized JSON string of the SBOM.

        Raises:
            FileNotFoundError: If the repository path does not exist.
            NotADirectoryError: If the path is not a directory.
            ValueError: If the repository directory is empty.
            RuntimeError: If Syft fails or produces invalid JSON.
        """
        repo_dir = self.project_root / repo_path

        if not repo_dir.exists():
            raise FileNotFoundError(f"Repository does not exist: {repo_dir}")
        if not repo_dir.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {repo_dir}")
        if not any(repo_dir.iterdir()):
            raise ValueError(f"Repository is empty: {repo_dir}")

        syft_bin = self._resolve_syft()
        cmd = [syft_bin, f"dir:{repo_dir}", "-o", SYFT_OUTPUT_FORMAT]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SYFT_TIMEOUT_SECONDS,
            check=False,
        )

        if result.returncode != 0:
            detail = result.stderr.strip() or "Syft exited with an unknown error."
            raise RuntimeError(f"Failed to generate SBOM for {repo_dir.name}: {detail}")

        output = self._normalize_json(result.stdout)
        if not output.strip():
            raise RuntimeError(f"Syft returned empty output for {repo_dir.name}.")

        try:
            json.loads(output)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Syft returned invalid JSON for {repo_dir.name}.") from e

        return output

    def save_sbom(self, repo_name: str, sbom_data: str) -> Path:
        """Write SBOM data to a JSON file.

        Args:
            repo_name: Repository name for the output filename.
            sbom_data: SBOM JSON string.

        Returns:
            Path to the saved file.

        Raises:
            ValueError: If repo_name is empty.
        """
        if not repo_name:
            raise ValueError("Repository name cannot be empty.")

        self.output_path.mkdir(parents=True, exist_ok=True)
        output_file = self.output_path / f"{repo_name}{SBOM_FILE_SUFFIX}"
        output_file.write_text(sbom_data, encoding="utf-8")
        LOGGER.info("SBOM saved: %s", output_file.relative_to(self.project_root))
        return output_file

    def run(self) -> list[StepResult]:
        """Execute SBOM generation for all discovered repositories.

        Returns:
            List of StepResult objects, one per repository.
        """
        repos = self.discover_repositories()
        self.output_path.mkdir(parents=True, exist_ok=True)

        if not repos:
            return []

        results: list[StepResult] = []

        for idx, repo_path in enumerate(repos, start=1):
            repo_name = Path(repo_path).name
            LOGGER.info("[%d/%d] Processing %s", idx, len(repos), repo_path)

            if self.dry_run:
                output_file = self.output_path / f"{repo_name}{SBOM_FILE_SUFFIX}"
                LOGGER.info(
                    "[%d/%d] Dry-run: would generate %s",
                    idx,
                    len(repos),
                    output_file.relative_to(self.project_root),
                )
                results.append(
                    StepResult(
                        repo_name=repo_name,
                        step_name="syft",
                        status="skipped",
                        output_path=str(output_file),
                    )
                )
                continue

            try:
                sbom_data = self.generate_sbom(repo_path)
                output_path = self.save_sbom(repo_name, sbom_data)
                results.append(
                    StepResult(
                        repo_name=repo_name,
                        step_name="syft",
                        status="success",
                        output_path=str(output_path.relative_to(self.project_root)),
                    )
                )
            except KeyboardInterrupt:
                raise
            except Exception as e:
                LOGGER.error("[%d/%d] Error processing %s: %s", idx, len(repos), repo_path, e)
                results.append(
                    StepResult(
                        repo_name=repo_name,
                        step_name="syft",
                        status="failed",
                        error_message=str(e),
                    )
                )

        success_count = sum(1 for r in results if r.status == "success")
        LOGGER.info(
            "Syft summary: %d total, %d success, %d failed",
            len(results),
            success_count,
            len(results) - success_count,
        )

        return results

    def _resolve_syft(self) -> str:
        """Locate the Syft CLI binary.

        Returns:
            Path to the 'syft' executable.

        Raises:
            RuntimeError: If Syft is not installed.
        """
        syft_path = shutil.which("syft")
        if not syft_path:
            raise RuntimeError(
                "Syft CLI is not installed. "
                "Please install it (https://github.com/anchore/syft) "
                "or run inside the Dev Container."
            )
        return syft_path

    def _normalize_json(self, raw_output: str) -> str:
        """Strip ANSI codes and extract valid JSON from Syft output.

        Args:
            raw_output: Raw stdout from Syft CLI.

        Returns:
            Clean JSON string.

        Raises:
            RuntimeError: If the output cannot be normalized to valid JSON.
        """
        if not raw_output or not raw_output.strip():
            return ""

        cleaned = _ANSI_ESCAPE_PATTERN.sub("", raw_output).replace("\ufeff", "").strip()
        candidates = [cleaned]

        obj_start = cleaned.find("{")
        obj_end = cleaned.rfind("}")
        if obj_start != -1 and obj_end != -1 and obj_start < obj_end:
            candidates.append(cleaned[obj_start : obj_end + 1])

        arr_start = cleaned.find("[")
        arr_end = cleaned.rfind("]")
        if arr_start != -1 and arr_end != -1 and arr_start < arr_end:
            candidates.append(cleaned[arr_start : arr_end + 1])

        for candidate in candidates:
            try:
                parsed = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            return json.dumps(parsed, ensure_ascii=False, indent=2)

        raise RuntimeError("Syft output could not be normalized to valid JSON.")
