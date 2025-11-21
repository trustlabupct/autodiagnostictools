"""trustMITRE: CAR analytic ingestion, compilation, and execution."""

from __future__ import annotations

from .config import TrustMITREConfig, load_config
from .util.version import __version__

__all__ = ["TrustMITREConfig", "load_config", "__version__"]
