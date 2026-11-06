"""Strix findings → DSA attack-graph bridge (Phase 2).

Independent of the Strix Python package: reads ``vulnerabilities.json`` /
``run.json`` shaped artifacts and emits a labeled graph for the C++ engine.
"""

from .mapper import BridgeOptions, build_attack_graph
from .emit import emit_graph_json, emit_topology_txt

__all__ = [
    "BridgeOptions",
    "build_attack_graph",
    "emit_graph_json",
    "emit_topology_txt",
]

__version__ = "0.2.0"
