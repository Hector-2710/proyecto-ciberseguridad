"""Dependency vulnerability detection using Grype for the Miner pipeline.

Scans Syft-generated SBOMs with Grype and extracts structured vulnerability
records for aggregation.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .models import StepResult, Vulnerability

LOGGER = logging.getLogger(__name__)

GRYPE_TIMEOUT_SECONDS = 300


class GrypeScanner:
    """Scans SBOM files with Grype to detect dependency vulnerabilities.

    Attributes:
        sboms_dir: Directory containing Syft-generated JSON SBOM files.
        output_dir: Directory where Grype raw JSON output will be saved.
    """

    def __init__(self, sboms_dir: str | Path, output_dir: str | Path) -> None:
        self.sboms_dir = Path(sboms_dir).expanduser().resolve()
        self.output_dir = Path(output_dir).expanduser().resolve()

    def analyze_sbom(self, sbom_path: Path) -> tuple[list[Vulnerability], str | None]:
        """Run Grype on a single SBOM and extract vulnerability matches.

        Args:
            sbom_path: Path to a Syft-generated SBOM JSON file.

        Returns:
            Tuple of (vulnerability list, raw JSON output path or None).

        Raises:
            RuntimeError: If Grype is not installed.
            subprocess.CalledProcessError: If Grype execution fails.
        """
        repo_name = sbom_path.stem
        grype_bin = self._resolve_grype()

        # Check if Grype output already exists (resumability)
        output_path = self.output_dir / f"{repo_name}.json"
        if output_path.exists():
            LOGGER.info("Grype output already exists for %s, parsing cached result.", repo_name)
            with open(output_path, encoding="utf-8") as f:
                grype_data = json.load(f)
            vulnerabilities = self._parse_matches(grype_data, repo_name)
            return vulnerabilities, str(output_path)

        cmd = [grype_bin, f"sbom:{sbom_path}", "-o", "json"]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=GRYPE_TIMEOUT_SECONDS,
            check=False,
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() or "Grype exited with unknown error."
            raise RuntimeError(f"Grype failed for {repo_name}: {error_msg}")

        try:
            grype_data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Grype returned invalid JSON for {repo_name}.") from e

        # Save raw output for traceability
        output_path = self.output_dir / f"{repo_name}.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(result.stdout, encoding="utf-8")

        vulnerabilities = self._parse_matches(grype_data, repo_name)
        LOGGER.info("Found %d Grype vulnerabilities in %s", len(vulnerabilities), repo_name)

        return vulnerabilities, str(output_path)

    def run(self) -> tuple[list[Vulnerability], list[StepResult]]:
        """Process all SBOM files in the sboms_dir.

        Returns:
            Tuple of (all vulnerability records, per-file step results).
        """
        if not self.sboms_dir.exists():
            LOGGER.warning("SBOMs directory not found: %s", self.sboms_dir)
            return [], []

        sbom_files = sorted(self.sboms_dir.glob("*.json"))

        if not sbom_files:
            LOGGER.warning("No SBOM files found in %s", self.sboms_dir)
            return [], []

        all_vulns: list[Vulnerability] = []
        step_results: list[StepResult] = []

        for idx, sbom_path in enumerate(sbom_files, start=1):
            repo_name = sbom_path.stem
            LOGGER.info("[%d/%d] Analyzing %s with Grype", idx, len(sbom_files), repo_name)

            try:
                vulns, output_path = self.analyze_sbom(sbom_path)
                all_vulns.extend(vulns)
                step_results.append(
                    StepResult(
                        repo_name=repo_name,
                        step_name="grype",
                        status="success",
                        output_path=output_path,
                    )
                )
            except KeyboardInterrupt:
                raise
            except Exception as e:
                LOGGER.error("[%d/%d] Grype failed for %s: %s", idx, len(sbom_files), repo_name, e)
                step_results.append(
                    StepResult(
                        repo_name=repo_name,
                        step_name="grype",
                        status="failed",
                        error_message=str(e),
                    )
                )

        success_count = sum(1 for r in step_results if r.status == "success")
        LOGGER.info(
            "Grype summary: %d total, %d success, %d failed, %d vulnerabilities",
            len(step_results),
            success_count,
            len(step_results) - success_count,
            len(all_vulns),
        )

        return all_vulns, step_results

    def _parse_matches(self, grype_data: dict[str, Any], repo_name: str) -> list[Vulnerability]:
        """Extract Vulnerability records from Grype JSON output.

        Args:
            grype_data: Parsed Grype JSON output.
            repo_name: Repository name for attribution.

        Returns:
            List of Vulnerability objects.
        """
        vulnerabilities: list[Vulnerability] = []

        for match in grype_data.get("matches", []):
            vuln_info = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            severity = vuln_info.get("severity", "unknown").lower()

            # Build location from artifact locations or related vulnerabilities
            locations = artifact.get("locations", [])
            location_str = "unknown"
            if locations:
                loc = locations[0]
                path = loc.get("path", "")
                location_str = path if path else "unknown"

            package_name = artifact.get("name", "")
            installed_version = artifact.get("version", "")

            fix = vuln_info.get("fix", {})
            fixed_versions = fix.get("versions", [])
            fixed_version = fixed_versions[0] if fixed_versions else None

            cwe_list: list[str] = vuln_info.get("cweIds", [])
            cwe_id = cwe_list[0] if cwe_list else None

            vuln_id = vuln_info.get("id", "unknown")
            description = vuln_info.get("description", "")

            vulnerabilities.append(
                Vulnerability(
                    vulnerability_id=vuln_id,
                    type="dependency",
                    source_tool="grype",
                    repository=repo_name,
                    location=location_str,
                    severity=severity,
                    description=description,
                    cwe_id=cwe_id,
                    package_name=package_name,
                    installed_version=installed_version,
                    fixed_version=fixed_version,
                )
            )

        return vulnerabilities

    @staticmethod
    def _resolve_grype() -> str:
        """Locate the Grype CLI binary.

        Returns:
            Path to the 'grype' executable.

        Raises:
            RuntimeError: If Grype is not installed.
        """
        grype_path = shutil.which("grype")
        if not grype_path:
            raise RuntimeError(
                "Grype CLI is not installed. "
                "Please install it (https://github.com/anchore/grype) "
                "or run inside the Dev Container."
            )
        return grype_path
