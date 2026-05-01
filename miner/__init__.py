"""Miner component: vulnerability extraction pipeline.

Extracts vulnerabilities from software repositories using CodeQL, Syft, and Grype,
producing a unified structured dataset.
"""

from pipeline import MinerPipeline
from config import Config
from models import Vulnerability, StepResult, PipelineResult

__all__ = ["MinerPipeline", "Config", "Vulnerability", "StepResult", "PipelineResult"]
__version__ = "0.1.0"
