"""Shared constants for provenance labeling and severity weighting."""

from __future__ import annotations

SCHEMA_VERSION = "1.0"

# Canonical disclaimer — keep CLI / API / UI wording aligned with this text.
DISCLAIMER = (
    "MODELED ATTACK GRAPH — not a confirmed multi-hop exploit chain. "
    "Nodes/edges marked provenance=from_finding come from Strix finding fields "
    "(target/endpoint/severity). Nodes/edges marked provenance=simulated are "
    "explicit modeling assumptions (threat-model scaffolding), NOT pentest proof."
)

# Short banner for CLIs / analysis.txt headers (same meaning as DISCLAIMER).
DISCLAIMER_BANNER = (
    "MODELED attack-path analysis — not confirmed multi-hop exploits "
    "(see attack_graph.json provenance)."
)

PROVENANCE_FINDING = "from_finding"
PROVENANCE_SIMULATED = "simulated"

SEVERITY_PROBABILITY = {
    "critical": 0.85,
    "high": 0.70,
    "medium": 0.50,
    "low": 0.30,
    "info": 0.15,
    "none": 0.10,
}

SEVERITY_IMPACT = {
    "critical": 95,
    "high": 80,
    "medium": 55,
    "low": 30,
    "info": 10,
    "none": 5,
}

# Simulated lateral / entry weights (ranking only).
SIM_ENTRY_PROBABILITY = 0.75
SIM_LATERAL_PROBABILITY = 0.35
