"""Miner component: vulnerability extraction pipeline.

Extracts vulnerabilities from software repositories using CodeQL, Syft, and Grype,
producing a unified structured dataset.
"""

from miner.pipeline import MinerPipeline
from miner.config import Config
from miner.models import Vulnerability, StepResult, PipelineResult

__all__ = ["MinerPipeline", "Config", "Vulnerability", "StepResult", "PipelineResult"]
__version__ = "0.1.0"
