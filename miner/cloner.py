"""Repository cloning for the Miner pipeline."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from miner.models import StepResult

LOGGER = logging.getLogger(__name__)

CLONE_TIMEOUT_SECONDS = 600


def clone_repo(url: str, target: Path, depth: int = 1) -> StepResult:
    """Clone a Git repository with shallow depth.

    Skips cloning if the target directory already contains a Git repository.

    Args:
        url: Git remote URL to clone.
        target: Local directory path for the clone.
        depth: Shallow clone depth (default: 1 for latest commit only).

    Returns:
        StepResult indicating success, skipped, or failure.
    """
    repo_name = target.name

    if target.exists() and (target / ".git").exists():
        LOGGER.info("Repository %s already cloned, skipping.", repo_name)
        return StepResult(
            repo_name=repo_name,
            step_name="clone",
            status="skipped",
        )

    LOGGER.info("Cloning %s → %s (depth=%d)", url, target, depth)

    target.parent.mkdir(parents=True, exist_ok=True)

    try:
        subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                str(depth),
                "--single-branch",
                url,
                str(target),
            ],
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_SECONDS,
            check=True,
        )
        LOGGER.info("Successfully cloned %s", repo_name)
        return StepResult(
            repo_name=repo_name,
            step_name="clone",
            status="success",
            output_path=str(target),
        )
    except subprocess.TimeoutExpired:
        LOGGER.error("Clone timed out for %s after %d seconds", repo_name, CLONE_TIMEOUT_SECONDS)
        return StepResult(
            repo_name=repo_name,
            step_name="clone",
            status="failed",
            error_message=f"Clone timed out after {CLONE_TIMEOUT_SECONDS}s",
        )
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.strip() if e.stderr else str(e)
        LOGGER.error("Clone failed for %s: %s", repo_name, error_msg[:200])
        return StepResult(
            repo_name=repo_name,
            step_name="clone",
            status="failed",
            error_message=error_msg[:500],
        )
    except (OSError, FileNotFoundError) as e:
        LOGGER.error("Clone system error for %s: %s", repo_name, e)
        return StepResult(
            repo_name=repo_name,
            step_name="clone",
            status="failed",
            error_message=f"System error: {e}",
        )
