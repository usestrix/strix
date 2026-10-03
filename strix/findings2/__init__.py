"""Strix 2 finding annotations — additive framework/domain metadata for validated findings.

The upstream finding model (`create_vulnerability_report` + `ReportState`) stays the
authoritative validated gate and is left untouched. This package adds an **optional,
rebase-safe sidecar** that attaches, to an already-filed finding, the metadata the
validator semantics (`docs/strix2/04-validator-semantics.md` §6) makes optional:
MITRE ATT&CK technique ids, CIS benchmark ids, the finding's domain
(network/cloud/infra/…), and a short pointer to the captured domain evidence. It
never blocks or changes a finding — it enriches it, and persists alongside
``vulnerabilities.json`` as ``finding_annotations.json`` + ``FRAMEWORK_MAP.md``.
"""
