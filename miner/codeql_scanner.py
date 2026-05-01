"""CodeQL analysis integration for the Miner pipeline.

Creates CodeQL databases for Java repositories and runs security analysis
using the default query suite, producing SARIF output.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

from models import StepResult, Vulnerability

from typing import Any

LOGGER = logging.getLogger(__name__)

CODEQL_QUERY_SUITES: dict[str, str] = {
    "java": "java-code-scanning.qls",
    "python": "python-code-scanning.qls",
}
CODEQL_ANALYZE_RAM_MB = 8192
DB_CREATE_TIMEOUT_SECONDS = 1800  # 30 minutes
DB_ANALYZE_TIMEOUT_SECONDS = 600  # 10 minutes

_SEVERITY_MAP: dict[str, str] = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "recommendation": "low",
}


def _resolve_codeql_bin() -> str:
    """Locate the CodeQL CLI binary.

    Returns:
        Path to the 'codeql' executable.

    Raises:
        RuntimeError: If CodeQL is not installed or not in PATH.
    """
    codeql = shutil.which("codeql")
    if not codeql:
        raise RuntimeError(
            "CodeQL CLI is not installed. Please install it or run inside the Dev Container."
        )
    return codeql


def _detect_build_command(repo_path: Path) -> str | None:
    """Detect the Java build system used in a repository.

    Args:
        repo_path: Path to the repository root.

    Returns:
        Build command string, or None if no build system detected.
    """
    pom = repo_path / "pom.xml"
    gradle_kts = repo_path / "build.gradle.kts"
    gradle_groovy = repo_path / "build.gradle"

    if pom.exists():
        return "mvn compile -DskipTests -q"
    if (repo_path / "gradlew").exists() or (repo_path / "gradlew.bat").exists():
        return "./gradlew compileJava -x test -q"
    if gradle_kts.exists() or gradle_groovy.exists():
        return "gradle compileJava -x test -q"

    return None


def _detect_codeql_language(repo_path: Path) -> str | None:
    """Detect the primary CodeQL language for the repository.

    Args:
        repo_path: Path to the repository root.

    Returns:
        "java" or "python" if detected, otherwise None.
    """
    if (repo_path / "pom.xml").exists() or (repo_path / "build.gradle").exists() or (
        repo_path / "build.gradle.kts"
    ).exists():
        return "java"

    # Lightweight Python detection
    python_markers = [
        "pyproject.toml",
        "setup.py",
        "requirements.txt",
        "Pipfile",
    ]
    if any((repo_path / marker).exists() for marker in python_markers):
        return "python"

    # Fallback: check for any .py files in repo root
    if any(repo_path.glob("*.py")):
        return "python"

    return None


def create_codeql_db(repo_path: Path, db_path: Path) -> StepResult:
    """Create a CodeQL database for a Java repository.

    Detects the build system and compiles the project as part of
    database creation. Skips if the database already exists.

    Args:
        repo_path: Absolute path to the cloned repository.
        db_path: Destination path for the CodeQL database.

    Returns:
        StepResult indicating success, skipped, or failure.
    """
    repo_name = repo_path.name

    if db_path.exists() and (db_path / "codeql-database.yml").exists():
        LOGGER.info("CodeQL database already exists for %s, skipping.", repo_name)
        return StepResult(
            repo_name=repo_name,
            step_name="codeql_db",
            status="skipped",
            output_path=str(db_path),
        )

    LOGGER.info("Creating CodeQL database for %s...", repo_name)

    codeql_bin = _resolve_codeql_bin()  # Raises RuntimeError if not installed
    language = _detect_codeql_language(repo_path)
    if not language:
        LOGGER.warning("No supported CodeQL language detected for %s", repo_name)
        return StepResult(
            repo_name=repo_name,
            step_name="codeql_db",
            status="skipped",
            error_message="No supported language detected",
        )

    build_cmd = _detect_build_command(repo_path) if language == "java" else None
    cmd = [
        codeql_bin,
        "database",
        "create",
        str(db_path),
        f"--language={language}",
        f"--source-root={repo_path}",
    ]

    if build_cmd:
        cmd.append(f"--command={build_cmd}")
        LOGGER.info("  Using build command: %s", build_cmd)
    elif language == "java":
        LOGGER.info("  No build system detected, CodeQL will attempt autobuild.")
        cmd.append("--overwrite")  # use codeql autobuild
    else:
        LOGGER.info("  Using CodeQL Python extractor (no build command needed).")

    db_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=DB_CREATE_TIMEOUT_SECONDS,
            check=True,
        )
        LOGGER.info("CodeQL database created for %s", repo_name)
        return StepResult(
            repo_name=repo_name,
            step_name="codeql_db",
            status="success",
            output_path=str(db_path),
        )
    except subprocess.TimeoutExpired:
        LOGGER.error("CodeQL database creation timed out for %s", repo_name)
        return StepResult(
            repo_name=repo_name,
            step_name="codeql_db",
            status="failed",
            error_message=f"Timed out after {DB_CREATE_TIMEOUT_SECONDS}s",
        )
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.strip() if e.stderr else str(e)
        LOGGER.error("CodeQL database creation failed for %s: %s", repo_name, error_msg)
        return StepResult(
            repo_name=repo_name,
            step_name="codeql_db",
            status="failed",
            error_message=error_msg[:2000],
        )


def analyze_codeql_db(db_path: Path, output_path: Path, language: str) -> StepResult:
    """Analyze a CodeQL database and produce SARIF output.

    Args:
        db_path: Path to the CodeQL database.
        output_path: Destination path for the SARIF JSON file.

    Returns:
        StepResult indicating success, skipped, or failure.
    """
    repo_name = db_path.name

    if output_path.exists():
        LOGGER.info("SARIF output already exists for %s, skipping analysis.", repo_name)
        return StepResult(
            repo_name=repo_name,
            step_name="codeql_analyze",
            status="skipped",
            output_path=str(output_path),
        )

    LOGGER.info("Analyzing CodeQL database for %s...", repo_name)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    codeql_bin = _resolve_codeql_bin()  # Raises RuntimeError if not installed
    query_suite = CODEQL_QUERY_SUITES.get(language)
    if not query_suite:
        LOGGER.warning("No CodeQL query suite found for language: %s", language)
        return StepResult(
            repo_name=repo_name,
            step_name="codeql_analyze",
            status="skipped",
            error_message="No query suite for language",
        )

    cmd = [
        codeql_bin,
        "database",
        "analyze",
        str(db_path),
        "--format=sarif-latest",
        f"--output={output_path}",
        f"--ram={CODEQL_ANALYZE_RAM_MB}",
        query_suite,
    ]

    try:
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=DB_ANALYZE_TIMEOUT_SECONDS,
            check=True,
        )
        LOGGER.info("CodeQL analysis complete for %s → %s", repo_name, output_path)
        return StepResult(
            repo_name=repo_name,
            step_name="codeql_analyze",
            status="success",
            output_path=str(output_path),
        )
    except subprocess.TimeoutExpired:
        LOGGER.error("CodeQL analysis timed out for %s", repo_name)
        return StepResult(
            repo_name=repo_name,
            step_name="codeql_analyze",
            status="failed",
            error_message=f"Timed out after {DB_ANALYZE_TIMEOUT_SECONDS}s",
        )
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.strip() if e.stderr else str(e)
        LOGGER.error("CodeQL analysis failed for %s: %s", repo_name, error_msg)
        return StepResult(
            repo_name=repo_name,
            step_name="codeql_analyze",
            status="failed",
            error_message=error_msg[:2000],
        )


def _map_codeql_severity(level: str) -> str:
    """Map CodeQL SARIF level to canonical severity.

    Args:
        level: SARIF result level (error, warning, note, recommendation).

    Returns:
        Canonical severity string.
    """
    return _SEVERITY_MAP.get(level.lower(), "unknown")


def parse_sarif(sarif_path: Path, repo_name: str) -> list[Vulnerability]:
    """Parse CodeQL SARIF output into Vulnerability records.

    Args:
        sarif_path: Path to the SARIF JSON file.
        repo_name: Name of the repository being analyzed.

    Returns:
        List of Vulnerability objects extracted from SARIF results.
    """
    if not sarif_path.exists():
        LOGGER.warning("SARIF file not found: %s", sarif_path)
        return []

    with open(sarif_path, encoding="utf-8") as f:
        sarif_data = json.load(f)

    vulnerabilities: list[Vulnerability] = []

    for run in sarif_data.get("runs", []):
        rules: dict[str, dict[str, Any]] = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rule_id = rule.get("id")
            if rule_id:
                rules[rule_id] = rule

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule = rules.get(rule_id, {})
            severity = _map_codeql_severity(result.get("level", "warning"))

            message = result.get("message", {}).get("text", "")

            locations = result.get("locations", [])
            location_str = "unknown"
            if locations:
                phys = (
                    locations[0]
                    .get("physicalLocation", {})
                    .get("artifactLocation", {})
                    .get("uri", "")
                )
                region = locations[0].get("physicalLocation", {}).get("region", {})
                line = region.get("startLine", "")
                location_str = f"{phys}:{line}" if line else phys

            cwe_ids: list[str] = []
            for tag in rule.get("properties", {}).get("tags", []):
                if tag.startswith("external/cwe/") or tag.startswith("CWE-"):
                    cwe_ids.append(tag.replace("external/cwe/", "CWE-"))

            vulnerabilities.append(
                Vulnerability(
                    vulnerability_id=rule_id,
                    type="codeql",
                    source_tool="codeql",
                    repository=repo_name,
                    location=location_str,
                    severity=severity,
                    description=message,
                    cwe_id=cwe_ids[0] if cwe_ids else None,
                )
            )

    LOGGER.info("Parsed %d CodeQL vulnerabilities from %s", len(vulnerabilities), repo_name)
    return vulnerabilities


def run_codeql_scan(
    repo_path: Path,
    db_dir: Path,
    output_dir: Path,
    repo_name: str,
) -> tuple[list[Vulnerability], list[StepResult]]:
    """Run the full CodeQL pipeline for a single repository.

    Creates the database, analyzes it, and parses the SARIF result.

    Args:
        repo_path: Absolute path to the cloned repository.
        db_dir: Parent directory for CodeQL databases.
        output_dir: Directory for SARIF output files.
        repo_name: Repository name for naming and logging.

    Returns:
        Tuple of (vulnerability list, step result list).
    """
    step_results: list[StepResult] = []
    vulnerabilities: list[Vulnerability] = []

    # Step 1: Create database
    db_path = db_dir / repo_name
    db_result = create_codeql_db(repo_path, db_path)
    step_results.append(db_result)

    if db_result.status in {"failed", "skipped"}:
        return vulnerabilities, step_results

    # Step 2: Analyze
    sarif_path = output_dir / f"{repo_name}.sarif"
    language = _detect_codeql_language(repo_path) or "java"
    analyze_result = analyze_codeql_db(db_path, sarif_path, language)
    step_results.append(analyze_result)

    if analyze_result.status == "failed":
        return vulnerabilities, step_results

    # Step 3: Parse SARIF
    if sarif_path.exists():
        vulnerabilities = parse_sarif(sarif_path, repo_name)

    return vulnerabilities, step_results
