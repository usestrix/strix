"""Map Strix finding records into a labeled directed attack graph."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


from .constants import (
    DISCLAIMER,
    PROVENANCE_FINDING,
    PROVENANCE_SIMULATED,
    SCHEMA_VERSION,
    SEVERITY_IMPACT,
    SEVERITY_PROBABILITY,
    SIM_ENTRY_PROBABILITY,
    SIM_LATERAL_PROBABILITY,
)


@dataclass
class BridgeOptions:
    """Controls how much simulated scaffolding is injected."""

    allow_simulated_entry: bool = True
    allow_simulated_lateral: bool = False
    entry_node_name: str = "[SIM] External Attacker"
    mark_highest_severity_as_crown: bool = True


@dataclass
class GraphNode:
    id: int
    name: str
    type: str
    zone: str
    impact: int
    is_entry_point: bool = False
    is_crown_jewel: bool = False
    provenance: str = PROVENANCE_SIMULATED
    finding_ids: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    source_fields: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "zone": self.zone,
            "impact": self.impact,
            "is_entry_point": self.is_entry_point,
            "is_crown_jewel": self.is_crown_jewel,
            "provenance": self.provenance,
            "finding_ids": list(self.finding_ids),
            "labels": list(self.labels),
            "source_fields": dict(self.source_fields),
        }


@dataclass
class GraphEdge:
    from_id: int
    to_id: int
    protocol: str
    relation: str
    probability: float
    status: str = "Active"
    provenance: str = PROVENANCE_SIMULATED
    finding_ids: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    title: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_id,
            "to": self.to_id,
            "protocol": self.protocol,
            "relation": self.relation,
            "probability": self.probability,
            "status": self.status,
            "provenance": self.provenance,
            "finding_ids": list(self.finding_ids),
            "labels": list(self.labels),
            "title": self.title,
        }


def _severity_key(raw: Any) -> str:
    text = str(raw or "info").strip().lower()
    return text if text in SEVERITY_PROBABILITY else "info"


def _sanitize_name(text: str) -> str:
    # Topology TXT is comma-separated; keep names CSV-safe.
    return " ".join(text.replace(",", " ").replace("\n", " ").split())


def parse_target(target: str) -> dict[str, str]:
    """Extract host/zone hints from a Strix ``target`` string."""
    raw = (target or "").strip()
    if not raw:
        return {"host": "unknown-target", "scheme": "", "zone": "Unknown", "display": "unknown-target"}

    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlparse(candidate)
    host = parsed.hostname or raw
    scheme = (parsed.scheme or "").lower()
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
        zone = "Lab"
    elif scheme in {"http", "https"}:
        zone = "DMZ"
    else:
        zone = "Internal"
    return {
        "host": host.lower(),
        "scheme": scheme,
        "zone": zone,
        "display": host,
    }


def normalize_endpoint(endpoint: Any) -> str | None:
    if endpoint is None:
        return None
    text = str(endpoint).strip()
    if not text:
        return None
    if not text.startswith("/"):
        text = "/" + text
    return text


def _next_id(used: set[int]) -> int:
    candidate = 1
    while candidate in used:
        candidate += 1
    used.add(candidate)
    return candidate


def build_attack_graph(
    findings: list[dict[str, Any]],
    *,
    run_record: dict[str, Any] | None = None,
    options: BridgeOptions | None = None,
) -> dict[str, Any]:
    """Convert finding-centric Strix artifacts into a labeled attack graph.

    Real finding-derived structure and simulated scaffolding are kept distinct
    via ``provenance`` and ``labels`` on every node and edge.
    """
    opts = options or BridgeOptions()
    run_record = run_record or {}

    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    used_ids: set[int] = set()
    host_ids: dict[str, int] = {}
    endpoint_ids: dict[tuple[str, str], int] = {}
    warnings: list[str] = []
    finding_ids_seen: list[str] = []

    # --- Simulated external attacker (scaffolding) ---
    entry_id: int | None = None
    if opts.allow_simulated_entry:
        entry_id = _next_id(used_ids)
        nodes.append(
            GraphNode(
                id=entry_id,
                name=_sanitize_name(opts.entry_node_name),
                type="Attacker",
                zone="Internet",
                impact=0,
                is_entry_point=True,
                provenance=PROVENANCE_SIMULATED,
                labels=["SIMULATED", "SCAFFOLDING"],
                source_fields={"role": "modeled_foothold"},
            )
        )

    usable = [f for f in findings if isinstance(f, dict)]
    if not usable:
        warnings.append("No finding objects in input; graph contains only simulated scaffolding.")

    for finding in usable:
        fid = str(finding.get("id") or finding.get("title") or f"anon-{len(finding_ids_seen)+1}")
        finding_ids_seen.append(fid)
        severity = _severity_key(finding.get("severity"))
        impact = SEVERITY_IMPACT[severity]
        # Prefer numeric CVSS impact when present (0-10 → 0-100 scale hint).
        cvss = finding.get("cvss")
        if isinstance(cvss, (int, float)) and cvss >= 0:
            impact = max(impact, min(100, int(round(float(cvss) * 10))))

        target_raw = str(finding.get("target") or "").strip()
        if not target_raw:
            warnings.append(f"Finding {fid} missing target; skipped host mapping.")
            continue

        parsed = parse_target(target_raw)
        host_key = parsed["host"]
        if host_key not in host_ids:
            host_id = _next_id(used_ids)
            host_ids[host_key] = host_id
            nodes.append(
                GraphNode(
                    id=host_id,
                    name=_sanitize_name(f"[FINDING] {parsed['display']}"),
                    type="Host",
                    zone=parsed["zone"],
                    impact=impact,
                    provenance=PROVENANCE_FINDING,
                    finding_ids=[fid],
                    labels=["FROM_FINDING"],
                    source_fields={"target": target_raw, "host": host_key},
                )
            )
            if entry_id is not None:
                edges.append(
                    GraphEdge(
                        from_id=entry_id,
                        to_id=host_id,
                        protocol=(parsed["scheme"] or "TCP").upper() or "TCP",
                        relation="InternetExposed" if parsed["zone"] in {"DMZ", "Lab"} else "Unclassified",
                        probability=SIM_ENTRY_PROBABILITY,
                        provenance=PROVENANCE_SIMULATED,
                        labels=["SIMULATED", "MODELED_ENTRY"],
                        title="Modeled external reachability to finding target host",
                    )
                )
        else:
            # Raise host impact if a worse finding lands on it.
            for node in nodes:
                if node.id == host_ids[host_key]:
                    node.impact = max(node.impact, impact)
                    if fid not in node.finding_ids:
                        node.finding_ids.append(fid)
                    break

        host_id = host_ids[host_key]
        endpoint = normalize_endpoint(finding.get("endpoint"))
        method = str(finding.get("method") or "HTTP").upper()
        title = str(finding.get("title") or "Finding")

        if endpoint:
            ep_key = (host_key, endpoint)
            if ep_key not in endpoint_ids:
                ep_id = _next_id(used_ids)
                endpoint_ids[ep_key] = ep_id
                nodes.append(
                    GraphNode(
                        id=ep_id,
                        name=_sanitize_name(f"[FINDING] {parsed['display']}{endpoint}"),
                        type="Endpoint",
                        zone=parsed["zone"],
                        impact=impact,
                        provenance=PROVENANCE_FINDING,
                        finding_ids=[fid],
                        labels=["FROM_FINDING"],
                        source_fields={
                            "target": target_raw,
                            "endpoint": endpoint,
                            "method": method,
                        },
                    )
                )
            else:
                ep_id = endpoint_ids[ep_key]
                for node in nodes:
                    if node.id == ep_id:
                        node.impact = max(node.impact, impact)
                        if fid not in node.finding_ids:
                            node.finding_ids.append(fid)
                        break

            # Finding-backed exploit step: host → endpoint.
            already = any(e.from_id == host_id and e.to_id == ep_id for e in edges)
            if not already:
                edges.append(
                    GraphEdge(
                        from_id=host_id,
                        to_id=ep_id,
                        protocol=method if method else "HTTP",
                        relation="Unclassified",
                        probability=SEVERITY_PROBABILITY[severity],
                        provenance=PROVENANCE_FINDING,
                        finding_ids=[fid],
                        labels=["FROM_FINDING", "EXPLOIT_STEP"],
                        title=_sanitize_name(title),
                    )
                )
            else:
                # Keep the higher modeled probability if duplicate findings share endpoint.
                for edge in edges:
                    if edge.from_id == host_id and edge.to_id == ep_id:
                        edge.probability = max(edge.probability, SEVERITY_PROBABILITY[severity])
                        if fid not in edge.finding_ids:
                            edge.finding_ids.append(fid)
                        break
        else:
            warnings.append(
                f"Finding {fid} has no endpoint; host node retained without exploit-step edge."
            )

    # Optional simulated lateral edges between finding hosts (never look like confirmed paths).
    if opts.allow_simulated_lateral and len(host_ids) >= 2:
        host_id_list = list(host_ids.values())
        for i in range(len(host_id_list) - 1):
            a, b = host_id_list[i], host_id_list[i + 1]
            edges.append(
                GraphEdge(
                    from_id=a,
                    to_id=b,
                    protocol="TCP",
                    relation="Unclassified",
                    probability=SIM_LATERAL_PROBABILITY,
                    provenance=PROVENANCE_SIMULATED,
                    labels=["SIMULATED", "MODELED_LATERAL"],
                    title="Modeled lateral movement (threat-model assumption)",
                )
            )
        warnings.append(
            "Simulated lateral edges were added between finding hosts; "
            "these are modeling assumptions, not confirmed pivots."
        )

    # Mark crown jewel: highest-impact non-attacker node.
    if opts.mark_highest_severity_as_crown:
        candidates = [n for n in nodes if not n.is_entry_point]
        if candidates:
            crown = max(candidates, key=lambda n: (n.impact, n.id))
            crown.is_crown_jewel = True
            if "MODELED_CROWN_JEWEL" not in crown.labels:
                crown.labels.append("MODELED_CROWN_JEWEL")

    # Incorporate run targets that have no findings yet (as finding-derived hosts if listed).
    for info in run_record.get("targets_info") or []:
        if not isinstance(info, dict):
            continue
        original = str(info.get("original") or info.get("target") or "").strip()
        if not original:
            continue
        parsed = parse_target(original)
        if parsed["host"] in host_ids:
            continue
        host_id = _next_id(used_ids)
        host_ids[parsed["host"]] = host_id
        nodes.append(
            GraphNode(
                id=host_id,
                name=_sanitize_name(f"[RUN] {parsed['display']}"),
                type="Host",
                zone=parsed["zone"],
                impact=20,
                provenance=PROVENANCE_FINDING,
                labels=["FROM_RUN_TARGET"],
                source_fields={"target": original, "host": parsed["host"]},
            )
        )
        if entry_id is not None:
            edges.append(
                GraphEdge(
                    from_id=entry_id,
                    to_id=host_id,
                    protocol=(parsed["scheme"] or "TCP").upper() or "TCP",
                    relation="InternetExposed" if parsed["zone"] in {"DMZ", "Lab"} else "Unclassified",
                    probability=SIM_ENTRY_PROBABILITY,
                    provenance=PROVENANCE_SIMULATED,
                    labels=["SIMULATED", "MODELED_ENTRY"],
                    title="Modeled reachability to scan target without filed finding",
                )
            )

    nodes.sort(key=lambda n: n.id)
    start_id = entry_id or (nodes[0].id if nodes else None)
    crown_ids = [n.id for n in nodes if n.is_crown_jewel]
    target_id = crown_ids[0] if crown_ids else (nodes[-1].id if nodes else None)

    return {
        "schema_version": SCHEMA_VERSION,
        "disclaimer": DISCLAIMER,
        "sources": {
            "finding_ids": finding_ids_seen,
            "run_name": run_record.get("run_name") or run_record.get("run_id"),
            "simulated_entry": bool(opts.allow_simulated_entry),
            "simulated_lateral": bool(opts.allow_simulated_lateral),
        },
        "warnings": warnings,
        "analysis_defaults": {
            "start": start_id,
            "target": target_id,
        },
        "nodes": [n.to_dict() for n in nodes],
        "edges": [e.to_dict() for e in edges],
        "counts": {
            "nodes": len(nodes),
            "edges": len(edges),
            "from_finding_nodes": sum(1 for n in nodes if n.provenance == PROVENANCE_FINDING),
            "simulated_nodes": sum(1 for n in nodes if n.provenance == PROVENANCE_SIMULATED),
            "from_finding_edges": sum(1 for e in edges if e.provenance == PROVENANCE_FINDING),
            "simulated_edges": sum(1 for e in edges if e.provenance == PROVENANCE_SIMULATED),
        },
    }
