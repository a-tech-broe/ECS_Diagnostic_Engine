"""ECS SRE Diagnostic & Recommendation Engine.

Collect -> correlate -> diagnose -> recommend. Never remediate.
"""

__version__ = "0.1.0"

from .config import Config
from .engine import Engine, build_engine
from .models import (
    ClusterHealth,
    Confidence,
    Finding,
    Recommendation,
    ServiceDiagnosis,
    ServiceSnapshot,
    Severity,
)

__all__ = [
    "__version__",
    "Config",
    "Engine",
    "build_engine",
    "ClusterHealth",
    "Confidence",
    "Finding",
    "Recommendation",
    "ServiceDiagnosis",
    "ServiceSnapshot",
    "Severity",
]
