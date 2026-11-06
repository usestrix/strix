"""Phase 3: optional Strix run-dir integration for DSA attack-path analysis.

Does not modify agent/scanner loops. Invoked explicitly via CLI after a run
(or on fixture artifacts). Simulated lateral movement is off by default.
"""

from .analyze_run import AnalyzeOptions, analyze_run_dir

__all__ = ["AnalyzeOptions", "analyze_run_dir"]
__version__ = "0.3.0"
