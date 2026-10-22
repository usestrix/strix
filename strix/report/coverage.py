"""``coverage.json`` — the negative space of a scan, with provenance.

A findings list answers "what is wrong". It cannot answer "what did you
check", and in a compliance context that second question is the one that
decides whether a clean result means anything: an auditor reading zero SQL
injection findings cannot tell "tested fourteen endpoints, all parameterized"
apart from "never looked".

This module assembles the artifact that answers it. Two kinds of statement go
in, and they are kept apart on purpose:

- ``agent_reported`` — the coverage ledger (:mod:`strix.tools.coverage.tools`).
  Rich and specific, but it is an agent's account of its own work.
- ``machine_observed`` — facts the runtime recorded regardless of what any
  agent claimed: which agents ran and how they terminated, which skills they
  carried, how many findings were filed, whether the run finished or was cut
  short.

A coverage claim is an attestation, so conflating the two would be the worst
possible failure: a hallucinated "tested and clean" is strictly less honest
than no coverage record at all. Every entry therefore carries its ``source``,
and machine-observed facts contradict rather than confirm — an agent that
carried the ``sql_injection`` skill and recorded nothing about SQL injection
shows up under ``gaps``, and a run that hit its budget ceiling is stamped
``complete: false`` no matter how tidy the ledger looks.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from strix.report.writer import atomic_write_text
from strix.skills import get_available_skills


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)

COVERAGE_FILENAME = "coverage.json"
COVERAGE_SCHEMA_VERSION = 1

#: Ledger outcomes rendered for a reader who has never seen our enum.
OUTCOME_LABELS: dict[str, str] = {
    "reported": "Finding reported",
    "no_issue_found": "No issue identified",
    "ruled_out": "Ruled out",
    "not_applicable": "Not applicable",
    "needs_follow_up": "Requires further review",
}

#: Statuses that mean the agent stopped early rather than finishing its task.
_INCOMPLETE_AGENT_STATUSES = frozenset({"crashed", "stopped", "running", "waiting"})

#: Run statuses that mean the scan itself did not run to completion.
_INCOMPLETE_RUN_STATUSES = frozenset({"failed", "interrupted", "stopped", "running"})

#: Only this skill category names a vulnerability class. ``tooling`` and
#: ``reconnaissance`` skills describe how an agent works, not what it hunts,
#: so holding one implies no coverage obligation.
_RISK_SKILL_CATEGORY = "vulnerabilities"


@dataclass(frozen=True)
class SubTopic:
    """One independently-accountable surface of a bundled skill.

    ``label`` is how the surface is named back to a reader; ``phrasings`` are
    the ledger-row wordings that count as covering it (a row matches when it
    contains every word of any one phrasing).
    """

    label: str
    phrasings: tuple[str, ...]


@dataclass(frozen=True)
class VulnClass:
    """Canonical description of one vulnerability class.

    ``aliases`` are the phrasings a ledger row may use to name the class — a
    skill's filename is not how a pentester writes the class down (an agent
    carrying ``path_traversal_lfi_rfi`` records "Path Traversal"), so the
    aliases bridge the two. ``sub_topics`` are the independently-accountable
    surfaces of a *bundled* skill: testing one surface must not imply the rest,
    so each is checked on its own. ``cwe`` is the canonical id(s) for the class
    — advisory metadata today (SARIF keeps its own CWE map), but the registry
    is the place to unify it.
    """

    aliases: tuple[str, ...]
    sub_topics: tuple[SubTopic, ...] = ()
    cwe: tuple[str, ...] = ()
    #: True when a reporting agent may set this class as a report's
    #: machine-readable ``finding_class`` to separate it from other classes
    #: that share a CWE (e.g. client-side vs server-side path traversal, both
    #: CWE-22). Most classes rely on ``ruleId`` alone and leave this False.
    selectable_finding_class: bool = False


#: The canonical registry of vulnerability classes, keyed by the bare skill
#: name (the ``strix/skills/vulnerabilities/<name>.md`` stem). This is the one
#: place these facts live, so the same class cannot be described by two
#: unrelated string lists — the drift that let client-side path traversal hide
#: behind the server-side "path traversal" name. A new skill absent here is
#: matched strictly by its own name, never crashed on — but add an entry,
#: because a false gap asserts something untrue in a report.
VULN_CLASSES: dict[str, VulnClass] = {
    "agentic_system_security": VulnClass(
        ("agentic", "agent tool", "mcp", "confused deputy", "tool invocation")
    ),
    "argument_injection": VulnClass(
        ("argument injection", "option injection", "argv"), cwe=("CWE-88",)
    ),
    "authentication_jwt": VulnClass(("authentication", "jwt", "session"), cwe=("CWE-287",)),
    "broken_function_level_authorization": VulnClass(
        (
            "function level authorization",
            "authorization",
            "access control",
            "privilege escalation",
        ),
        cwe=("CWE-862",),
    ),
    "browser_security": VulnClass(
        ("browser", "postmessage", "xs leak", "service worker", "cross origin state"),
        sub_topics=(
            SubTopic("postMessage", ("postmessage", "message listener", "window messaging")),
            SubTopic(
                "client-side path traversal",
                ("client side path traversal", "cspt", "client side path"),
            ),
            SubTopic("XS-Leaks", ("xs leak", "xs-leaks", "cross origin oracle", "cross site leak")),
            SubTopic(
                "service workers and caches",
                ("service worker", "cache api", "cache poisoning"),
            ),
            SubTopic("web workers", ("web worker", "worker script")),
            SubTopic(
                "navigation and redirect control",
                ("client side redirect", "spa navigation", "history manipulation", "meta refresh"),
            ),
            SubTopic(
                "CSP and browser parsing",
                ("content security policy", "csp bypass", "trusted types"),
            ),
            SubTopic("local network access", ("local network", "loopback", "dns rebinding")),
            SubTopic("JavaScript gadgets", ("javascript gadget", "gadget chain", "dom gadget")),
        ),
    ),
    "business_logic": VulnClass(("business logic", "logic flaw"), cwe=("CWE-840",)),
    "client_side_path_traversal": VulnClass(
        ("client side path traversal", "cspt", "client side path"),
        cwe=("CWE-22",),
        selectable_finding_class=True,
    ),
    "csrf": VulnClass(("csrf", "cross site request forgery"), cwe=("CWE-352",)),
    "header_injection": VulnClass(("header injection", "host header", "crlf"), cwe=("CWE-113",)),
    "http_request_smuggling": VulnClass(("request smuggling", "desync"), cwe=("CWE-444",)),
    "idor": VulnClass(
        ("idor", "object level authorization", "bola", "direct object reference"),
        cwe=("CWE-639",),
    ),
    "information_disclosure": VulnClass(
        ("information disclosure", "information leak", "sensitive data", "data exposure"),
        cwe=("CWE-200",),
    ),
    "insecure_deserialization": VulnClass(("deserialization",), cwe=("CWE-502",)),
    "insecure_file_uploads": VulnClass(("file upload",), cwe=("CWE-434",)),
    "llm_prompt_injection": VulnClass(("prompt injection",), cwe=("CWE-1427",)),
    "mass_assignment": VulnClass(("mass assignment", "parameter binding"), cwe=("CWE-915",)),
    "nosql_injection": VulnClass(("nosql",), cwe=("CWE-943",)),
    "open_redirect": VulnClass(("redirect",), cwe=("CWE-601",)),
    "path_traversal_lfi_rfi": VulnClass(
        ("path traversal", "directory traversal", "file inclusion", "lfi", "rfi"),
        cwe=("CWE-22",),
    ),
    "prototype_pollution": VulnClass(("prototype pollution",), cwe=("CWE-1321",)),
    "race_conditions": VulnClass(("race condition", "toctou"), cwe=("CWE-362",)),
    "rce": VulnClass(
        ("rce", "remote code execution", "code execution", "command injection"), cwe=("CWE-94",)
    ),
    "semantic_confusion": VulnClass(
        ("semantic confusion", "parser differential", "normalization", "validator sink mismatch")
    ),
    "sql_injection": VulnClass(("sql injection", "sqli"), cwe=("CWE-89",)),
    "ssrf": VulnClass(("ssrf", "server side request forgery"), cwe=("CWE-918",)),
    "ssti": VulnClass(("ssti", "template injection"), cwe=("CWE-1336",)),
    "subdomain_takeover": VulnClass(("subdomain takeover",)),
    "weak_password_detection": VulnClass(
        ("password", "credential", "brute force"), cwe=("CWE-521",)
    ),
    "xss": VulnClass(("xss", "cross site scripting", "script injection"), cwe=("CWE-79",)),
    "xxe": VulnClass(("xxe", "xml external entity", "xml entity"), cwe=("CWE-611",)),
}

#: Backward-compatible view: skill name -> alias phrasings, derived from the
#: registry so the two can never drift. Used wherever a class's top-level
#: phrasings are needed (and imported by the coverage tests).
_SKILL_PHRASINGS: dict[str, tuple[str, ...]] = {
    name: vclass.aliases for name, vclass in VULN_CLASSES.items()
}


def selectable_finding_classes() -> frozenset[str]:
    """Vulnerability classes a reporting agent may set as a report's
    ``finding_class``.

    ``finding_class`` is a machine-readable sub-classification that separates
    findings sharing a CWE rule (``ruleId``) in SARIF and dedup — client-side
    path traversal and server-side path traversal / LFI / RFI all key on
    CWE-22, so the rule alone cannot tell them apart. Sourcing the selectable
    set from the registry keeps it from being hand-maintained in the reporting
    tool, where it would silently drift from the class definitions here.
    """
    return frozenset(
        name for name, vclass in VULN_CLASSES.items() if vclass.selectable_finding_class
    )


def read_agent_graph(state_dir: Path) -> dict[str, Any]:
    """Load the coordinator's snapshot, or ``{}`` when it isn't readable.

    The snapshot is the runtime's own record of the agent tree, written on
    every graph mutation. Reading it here (rather than holding a coordinator
    reference) keeps artifact assembly usable from a finished or resumed run,
    where the live coordinator is gone but the file is still on disk.
    """
    path = state_dir / "agents.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.warning("agent graph snapshot at %s is unreadable", path, exc_info=True)
        return {}
    return data if isinstance(data, dict) else {}


def _normalized(text: str) -> str:
    """Lowercase *text* with punctuation flattened to spaces, for matching."""
    return "".join(char if char.isalnum() else " " for char in text.lower())


def _skill_leaf(skill: str) -> str:
    return skill.rsplit("/", maxsplit=1)[-1].strip().lower()


def _risk_skill_names() -> frozenset[str]:
    """Bare names of every skill that denotes a vulnerability class."""
    try:
        entries = get_available_skills().get(_RISK_SKILL_CATEGORY, [])
        return frozenset(entry["name"] for entry in entries if entry.get("name"))
    except OSError:
        logger.warning("could not enumerate skills for coverage gaps", exc_info=True)
        return frozenset()


def agents_from_graph(graph: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten the coordinator snapshot into one record per agent."""
    statuses = graph.get("statuses")
    if not isinstance(statuses, dict):
        return []
    raw_names = graph.get("names")
    names: dict[str, Any] = raw_names if isinstance(raw_names, dict) else {}
    raw_metadata = graph.get("metadata")
    metadata: dict[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
    raw_parents = graph.get("parent_of")
    parents: dict[str, Any] = raw_parents if isinstance(raw_parents, dict) else {}
    # Only an unambiguous root earns the exemption below. A snapshot with no
    # parent links at all makes every agent look parentless, and excusing all
    # of them would silently delete the silent-agent check.
    parentless = [agent_id for agent_id in statuses if not parents.get(agent_id)]
    root_id = parentless[0] if len(parentless) == 1 else None

    agents: list[dict[str, Any]] = []
    for agent_id, status in statuses.items():
        raw_meta = metadata.get(agent_id)
        meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
        raw_skills = meta.get("skills")
        skills: list[Any] = raw_skills if isinstance(raw_skills, list) else []
        agents.append(
            {
                "agent_id": agent_id,
                "agent_name": names.get(agent_id) or agent_id,
                "status": str(status),
                "skills": [str(skill) for skill in skills],
                "task": str(meta.get("task") or ""),
                "is_root": agent_id == root_id,
            }
        )
    agents.sort(key=lambda agent: str(agent["agent_name"]))
    return agents


def _phrasing_wordlists(phrases: tuple[str, ...]) -> list[list[str]]:
    """Normalize each phrasing into a word list for :func:`_entry_is_about`."""
    return [terms for phrase in phrases if (terms := _normalized(phrase).split())]


def cwe_for_skill(skill: str) -> tuple[str, ...]:
    """Canonical CWE id(s) for a vulnerability skill, or empty if unmapped."""
    vclass = VULN_CLASSES.get(_skill_leaf(skill))
    return vclass.cwe if vclass else ()


def _term_in_words(term: str, words: set[str]) -> bool:
    """A phrasing word matches a row word exactly, or as its simple plural.

    Matching whole words, not substrings, is what stops a short class token
    like ``rce`` matching inside ``brute force`` / ``enforcement`` or ``idor``
    inside ``corridor``. The plural allowance (``worker`` matches a ``workers``
    row, ``password`` a ``passwords`` row) keeps a trivial inflection from
    opening a false gap.

    Only the forward direction (phrasing term + ``s``) is allowed, never the
    reverse (row word + ``s`` == term): the reverse would let the row word
    ``xs`` satisfy the ``xss`` class alias (``"xs" + "s" == "xss"``), so an
    unrelated XS-Leaks row would falsely mark XSS covered. A phrasing that
    needs to match a singular row carries the singular spelling as its own
    alias instead.
    """
    return term in words or f"{term}s" in words


def _entry_is_about(entry: dict[str, Any], phrasings: list[list[str]]) -> bool:
    """True when a ledger row names any phrasing of a risk class.

    A phrasing matches when every one of its words appears as a **word** in the
    row (``risk_area`` + ``surface``) — not as a substring, so "brute force"
    never counts as ``rce`` coverage and "corridor" never as ``idor``. As a
    fallback it also matches the phrasing's words joined into one token, so a
    row that recorded a joined / CamelCase name the normalizer kept whole
    ("DirectoryTraversal" -> "directorytraversal", "XSLeaks" -> "xsleaks")
    still counts — still a whole-token check, never a substring.
    """
    words = set(_normalized(f"{entry.get('risk_area', '')} {entry.get('surface', '')}").split())
    for terms in phrasings:
        if all(_term_in_words(term, words) for term in terms):
            return True
        if len(terms) > 1 and _term_in_words("".join(terms), words):
            return True
    return False


def _entry_authored_by(entry: dict[str, Any], owner_ids: set[str]) -> bool:
    """True when this row — now, or in a superseded revision — was written by
    one of *owner_ids*.

    ``update_coverage`` overwrites ``agent_id`` with the updater's, so a surface
    a carrier genuinely assessed would look unexamined after an unrelated agent
    edits the shared row. History preserves the earlier author, so an earlier
    assessment by a carrier still counts.
    """
    if str(entry.get("agent_id") or "") in owner_ids:
        return True
    history = entry.get("history")
    if isinstance(history, list):
        return any(
            isinstance(item, dict) and str(item.get("agent_id") or "") in owner_ids
            for item in history
        )
    return False


def _topics_for(skill: str) -> list[tuple[str | None, list[list[str]]]]:
    """The independently-accountable topics a carried skill must cover.

    A *bundled* skill (one with declared ``sub_topics``) is accountable per
    surface: proving one does not imply the rest, so each sub-topic is a topic
    of its own. Every other skill has a single implicit topic — the class
    itself, matched by its aliases — which reproduces the original skill-level
    behaviour exactly. Each topic is ``(label, wordlists)``; the label is
    ``None`` for the single-topic case.
    """
    vclass = VULN_CLASSES.get(skill)
    if vclass is None:
        return [(None, _phrasing_wordlists((skill,)))]
    if vclass.sub_topics:
        return [(st.label, _phrasing_wordlists(st.phrasings)) for st in vclass.sub_topics]
    return [(None, _phrasing_wordlists(vclass.aliases))]


def skill_coverage_gaps(
    entries: list[dict[str, Any]], agents: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Vulnerability classes (and bundled-skill surfaces) an agent was equipped
    for but never recorded.

    A skill assigned to an agent is a declaration of intent that the runtime
    observed independently of anything the agent later said. When no ledger
    row mentions that class, the class is unaccounted for — which is a very
    different report line from "tested, nothing found".

    A bundled skill is held to a finer standard: each of its surfaces is
    checked on its own, so testing the easy one (a ``postMessage`` origin
    check) cannot mark the dangerous one (client-side path traversal) as
    covered. A skill nobody touched still collapses to a single class-level
    gap; a partially tested one yields one gap per untested surface.
    """
    risk_skills = _risk_skill_names()
    if not risk_skills:
        return []

    carriers: dict[str, list[str]] = {}
    carrier_ids: dict[str, set[str]] = {}
    for agent in agents:
        agent_id = str(agent.get("agent_id") or "")
        for skill in agent["skills"]:
            leaf = _skill_leaf(skill)
            if leaf in risk_skills:
                carriers.setdefault(leaf, []).append(str(agent["agent_name"]))
                if agent_id:
                    carrier_ids.setdefault(leaf, set()).add(agent_id)

    gaps: list[dict[str, Any]] = []
    for skill, agent_names in sorted(carriers.items()):
        names = ", ".join(sorted(set(agent_names)))
        topics = _topics_for(skill)
        # A bundled skill's surfaces are only covered by rows from an agent that
        # actually carried that skill. Otherwise an unrelated row that merely
        # shares a word — an open_redirect row mentioning "meta refresh" — would
        # mask an untested browser surface. Single-topic skills keep the shared
        # ledger semantics: any row naming the class counts, whoever wrote it.
        vclass = VULN_CLASSES.get(skill)
        if vclass is not None and vclass.sub_topics:
            owner_ids = carrier_ids.get(skill, set())
            relevant = [e for e in entries if _entry_authored_by(e, owner_ids)]
        else:
            relevant = entries
        uncovered = [
            (label, wordlists)
            for label, wordlists in topics
            if not any(_entry_is_about(entry, wordlists) for entry in relevant)
        ]
        if not uncovered:
            continue
        if len(uncovered) == len(topics):
            # Nothing about this class was recorded at all — one class-level gap.
            detail = (
                f"Agent(s) {names} were assigned the '{skill}' skill, but no coverage "
                "entry records this class being assessed. Treat it as unexamined, not "
                "as clean."
            )
            if len(topics) > 1:
                surfaces = ", ".join(str(label) for label, _ in topics)
                detail += f" Its surfaces ({surfaces}) are each separately accountable."
            gaps.append(
                {
                    "kind": "unrecorded_risk_class",
                    "risk_area": skill.replace("_", " "),
                    "detail": detail,
                }
            )
            continue
        # Some surfaces were tested but not all: name each untested surface, so a
        # bundled skill cannot be marked covered on the strength of its easiest one.
        for label, _wordlists in uncovered:
            gaps.append(
                {
                    "kind": "unrecorded_sub_topic",
                    "skill": skill,
                    "risk_area": str(label),
                    "detail": (
                        f"Agent(s) {names} carried '{skill}' and recorded coverage for some "
                        f"of its surfaces, but nothing records '{label}'. Testing one surface "
                        "of a multi-surface skill does not cover the others — treat "
                        f"'{label}' as unexamined."
                    ),
                }
            )
    return gaps


def _silent_agent_gaps(
    entries: list[dict[str, Any]], agents: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Agents that ran and recorded nothing at all.

    The root agent is exempt while it has children: it delegates and
    reconciles rather than testing, so flagging it on every clean scan would
    put a permanent false line in the report and teach readers to skip the
    section. A root that ran alone tested alone, and is held to the rule.
    """
    recorded_ids = {str(entry.get("agent_id")) for entry in entries if entry.get("agent_id")}
    delegated = len(agents) > 1
    gaps: list[dict[str, Any]] = []
    for agent in agents:
        if agent["agent_id"] in recorded_ids or (agent["is_root"] and delegated):
            continue
        gaps.append(
            {
                "kind": "agent_recorded_no_coverage",
                "agent_name": agent["agent_name"],
                "detail": (
                    f"{agent['agent_name']} ran (status: {agent['status']}) without "
                    "recording any coverage. Whatever it examined is absent from this "
                    "record."
                ),
            }
        )
    return gaps


def _unresolved_gaps(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ledger rows the agents themselves left open."""
    return [
        {
            "kind": "needs_follow_up",
            "surface": entry.get("surface", ""),
            "risk_area": entry.get("risk_area", ""),
            "detail": str(entry.get("evidence") or "Left open without a stated reason."),
        }
        for entry in entries
        if entry.get("outcome") == "needs_follow_up"
    ]


def _completeness(
    run_record: dict[str, Any],
    agents: list[dict[str, Any]],
    exit_reason: str | None,
) -> dict[str, Any]:
    """Whether this record can be read as a complete account of the scan.

    Any of these makes it partial, and the caveats say which: the run did not
    reach ``completed``, an agent was still live or died when the scan ended,
    or the run stopped for a reason other than the root agent deciding it was
    done (budget ceilings are the common case).
    """
    status = str(run_record.get("status") or "unknown")
    caveats: list[str] = []

    if status in _INCOMPLETE_RUN_STATUSES:
        caveats.append(
            f"The scan ended with status '{status}' rather than completing, so coverage "
            "reflects only the work finished before it stopped."
        )
    unfinished = [agent for agent in agents if agent["status"] in _INCOMPLETE_AGENT_STATUSES]
    if unfinished:
        names = ", ".join(sorted(str(agent["agent_name"]) for agent in unfinished))
        caveats.append(
            f"{len(unfinished)} agent(s) did not finish cleanly ({names}); any surface they "
            "held is under-covered."
        )
    if exit_reason and exit_reason not in {"finished_by_tool", "completed"}:
        caveats.append(
            f"The run terminated via '{exit_reason}' rather than the root agent finishing, "
            "so remaining scope was not reached."
        )

    return {
        "complete": not caveats,
        "scan_status": status,
        "exit_reason": exit_reason,
        "caveats": caveats,
    }


def _outcome_counts(entries: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in entries:
        outcome = str(entry.get("outcome", ""))
        counts[outcome] = counts.get(outcome, 0) + 1
    return {label: counts[label] for label in OUTCOME_LABELS if label in counts}


def build_coverage_document(
    *,
    run_record: dict[str, Any],
    entries: list[dict[str, Any]],
    agent_graph: dict[str, Any],
    vulnerability_reports: list[dict[str, Any]],
    exit_reason: str | None = None,
) -> dict[str, Any]:
    """Assemble the ``coverage.json`` document."""
    agents = agents_from_graph(agent_graph)
    skills_exercised = sorted(
        {_skill_leaf(skill) for agent in agents for skill in agent["skills"] if skill}
    )

    ledger = [
        {
            "surface": entry.get("surface", ""),
            "risk_area": entry.get("risk_area", ""),
            "outcome": entry.get("outcome", ""),
            "outcome_label": OUTCOME_LABELS.get(str(entry.get("outcome", "")), ""),
            "evidence": entry.get("evidence", ""),
            "recorded_by": entry.get("agent_name", ""),
            "recorded_at": entry.get("created_at", ""),
            "updated_at": entry.get("updated_at", ""),
            "previous_outcomes": [
                str(previous.get("outcome", ""))
                for previous in entry.get("history", [])
                if isinstance(previous, dict)
            ],
            "source": "agent_reported",
        }
        for entry in entries
    ]

    gaps = [
        *_unresolved_gaps(entries),
        *skill_coverage_gaps(entries, agents),
        *_silent_agent_gaps(entries, agents),
    ]

    return {
        "schema_version": COVERAGE_SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "run_id": run_record.get("run_id"),
        "run_name": run_record.get("run_name"),
        "scope": {
            "targets": run_record.get("targets_info") or [],
            "scan_mode": run_record.get("scan_mode"),
            "scope_mode": run_record.get("scope_mode"),
            "diff_scope": run_record.get("diff_scope"),
            "instruction": run_record.get("instruction") or "",
        },
        "summary": {
            "surfaces_reviewed": len(ledger),
            "outcomes": _outcome_counts(entries),
            "findings_filed": len(vulnerability_reports),
            "gaps": len(gaps),
        },
        "machine_observed": {
            "agents": agents,
            "skills_exercised": skills_exercised,
            "findings_filed": len(vulnerability_reports),
            "source": "runtime",
        },
        "completeness": _completeness(run_record, agents, exit_reason),
        "entries": ledger,
        "gaps": gaps,
    }


def write_coverage(run_dir: Path, document: dict[str, Any]) -> Path:
    """Write ``coverage.json`` into the run directory and return its path."""
    path = run_dir / COVERAGE_FILENAME
    atomic_write_text(path, json.dumps(document, ensure_ascii=False, indent=2, default=str))
    logger.info(
        "Saved coverage record to: %s (%d surface(s), %d gap(s))",
        path,
        len(document.get("entries", [])),
        len(document.get("gaps", [])),
    )
    return path
