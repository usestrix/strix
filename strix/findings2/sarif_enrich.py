"""Enrich a written SARIF document with the finding-annotation sidecar's tags.

The ATT&CK / CIS / domain metadata the agent records with ``annotate_finding`` lives
in a separate store (``finding_annotations.json``), keyed by the finding's ``vuln-NNNN``
id — the same id SARIF carries at ``result.properties.strix.id``. This merges those
tags into the SARIF so the framework mapping rides along to code-scanning / ASPM,
**additively and without touching the upstream emitter**: it reads the just-written
``findings.sarif``, adds ``mitre:*`` / ``cis:*`` / ``domain:*`` tags to each matched
result's rule and a ``result.properties.strix.frameworks`` block, then rewrites the
file atomically. No-op when the sidecar is empty or the file is absent, so
upstream-only runs are untouched.
"""

from __future__ import annotations

import json
import logging
import os
from typing import TYPE_CHECKING, Any

from strix.findings2.store import get_annotation_store


if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from strix.findings2.schema import FindingAnnotation


logger = logging.getLogger(__name__)


def _result_finding_id(result: dict[str, Any]) -> str | None:
    props = result.get("properties")
    if not isinstance(props, dict):
        return None
    strix = props.get("strix")
    if not isinstance(strix, dict):
        return None
    fid = strix.get("id")
    return fid if isinstance(fid, str) and fid else None


def _annotation_tags(annotation: FindingAnnotation) -> list[str]:
    tags = [f"mitre:{t}" for t in annotation.mitre_attack]
    tags += [f"cis:{c}" for c in annotation.cis_benchmark]
    if annotation.domain:
        tags.append(f"domain:{annotation.domain}")
    return tags


def _add_rule_tags(rule: dict[str, Any], new_tags: list[str]) -> bool:
    properties = rule.setdefault("properties", {})
    if not isinstance(properties, dict):
        return False
    existing = properties.get("tags")
    tags: list[str] = list(existing) if isinstance(existing, list) else []
    changed = False
    for tag in new_tags:
        if tag not in tags:
            tags.append(tag)
            changed = True
    if changed:
        properties["tags"] = tags
    return changed


def _frameworks_block(annotation: FindingAnnotation) -> dict[str, Any]:
    block: dict[str, Any] = {}
    if annotation.mitre_attack:
        block["mitre_attack"] = list(annotation.mitre_attack)
    if annotation.cis_benchmark:
        block["cis_benchmark"] = list(annotation.cis_benchmark)
    if annotation.domain:
        block["domain"] = str(annotation.domain)
    return block


def _apply_result_frameworks(result: dict[str, Any], annotation: FindingAnnotation) -> bool:
    """Record a finding's own framework set on its result (same rule can span techniques)."""
    block = _frameworks_block(annotation)
    if not block:
        return False
    props = result.setdefault("properties", {})
    if not isinstance(props, dict):
        return False
    strix = props.setdefault("strix", {})
    if not isinstance(strix, dict) or strix.get("frameworks") == block:
        return False
    strix["frameworks"] = block
    return True


def _enrich_result(
    result: dict[str, Any],
    annotations: Mapping[str, FindingAnnotation],
    rules_by_id: dict[Any, dict[str, Any]],
) -> bool:
    annotation = annotations.get(_result_finding_id(result) or "")
    if annotation is None:
        return False
    tags = _annotation_tags(annotation)
    if not tags:
        return False
    changed = False
    rule = rules_by_id.get(result.get("ruleId"))
    if isinstance(rule, dict) and _add_rule_tags(rule, tags):
        changed = True
    if _apply_result_frameworks(result, annotation):
        changed = True
    return changed


def enrich_sarif_document(
    sarif: dict[str, Any], annotations: Mapping[str, FindingAnnotation]
) -> bool:
    """Merge annotation tags into a SARIF document in place. Returns True if changed."""
    if not annotations:
        return False
    runs = sarif.get("runs")
    if not isinstance(runs, list):
        return False

    changed = False
    for run in runs:
        if not isinstance(run, dict):
            continue
        rules = (((run.get("tool") or {}).get("driver") or {}).get("rules")) or []
        rules_by_id = {
            rule.get("id"): rule for rule in rules if isinstance(rule, dict) and rule.get("id")
        }
        for result in run.get("results") or []:
            if isinstance(result, dict) and _enrich_result(result, annotations, rules_by_id):
                changed = True
    return changed


def enrich_sarif_file(path: Path, annotations: Mapping[str, FindingAnnotation]) -> bool:
    """Read, enrich, and atomically rewrite a SARIF file. Returns True if it changed."""
    if not annotations or not path.exists():
        return False
    try:
        sarif = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        logger.warning("could not read SARIF for annotation enrichment: %s", path, exc_info=True)
        return False
    if not isinstance(sarif, dict) or not enrich_sarif_document(sarif, annotations):
        return False

    tmp_path = path.with_name(f"{path.name}.{os.getpid()}.enrich.tmp")
    try:
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(sarif, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        tmp_path.replace(path)  # atomic on the same filesystem
    except OSError:
        logger.warning("could not write enriched SARIF: %s", path, exc_info=True)
        return False
    finally:
        tmp_path.unlink(missing_ok=True)
    return True


def enrich_run_sarif(run_dir: Path, *, filename: str = "findings.sarif") -> bool:
    """Enrich ``run_dir/findings.sarif`` from the run's finding-annotation store.

    No-op (returns False) when no store is bound, the store is empty, or the file is
    absent — so a run without any ``annotate_finding`` calls is untouched.
    """
    store = get_annotation_store()
    if store is None:
        return False
    annotations = {a.vuln_report_id: a for a in store.all_annotations()}
    if not annotations:
        return False
    return enrich_sarif_file(run_dir / filename, annotations)
