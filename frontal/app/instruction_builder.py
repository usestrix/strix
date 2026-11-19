"""Instruction builder: fills the six V9 templates (Web, API, Authorization and
their expanded variants).

The templates live in ``instructions/*.md`` with ``{{SELECT_*}}`` and
``{{TEXT_*}}`` placeholders. ``catalogs.json`` holds the options of every
SELECT_ placeholder and ``fields.json`` describes the free-text ones. Strix
never expands placeholders, so the console sends the text rendered here as the
scan ``instruction``.

A value is a dict with any of ``value`` (TEXT_), ``selected`` and ``custom``
(SELECT_), or ``na`` + ``na_reason``: every field is required, and N/A is only
accepted with a concrete reason. A SELECT_ inserts the sentence each selected
option carries (``instruction``), not its id, and an ordered catalog numbers
them in click order.
"""

from __future__ import annotations

import json
import re
from functools import cache
from pathlib import Path
from typing import Any


INSTRUCTIONS_DIR = Path(__file__).parent / "instructions"

BUILDER_TEMPLATES: list[dict[str, Any]] = [
    {
        "id": "web",
        "name": "Web",
        "description": (
            "Aplicación web desde el navegador, con cobertura OWASP WSTG. Excluye pruebas de API."
        ),
        "scan_mode": "standard",
        "file": "web.md",
    },
    {
        "id": "api",
        "name": "API",
        "description": (
            "REST, GraphQL, SOAP, gRPC o WebSocket, con cobertura OWASP API Security Top 10 2023."
        ),
        "scan_mode": "standard",
        "file": "api.md",
    },
    {
        "id": "authorization",
        "name": "Autorización",
        "description": "Autorización vertical y horizontal contra un modelo y matriz de acceso.",
        "scan_mode": "standard",
        "file": "authorization.md",
    },
    {
        "id": "web-exp",
        "name": "Web ampliada",
        "description": (
            "Variante ampliada de Web: inventario de superficie, matrices de contrato "
            "y ledger de cobertura."
        ),
        "scan_mode": "deep",
        "file": "web-exp.md",
    },
    {
        "id": "api-exp",
        "name": "API ampliada",
        "description": (
            "Variante ampliada de API: contrato, inventario de operaciones y validación "
            "por identidad, rol, objeto y propiedad."
        ),
        "scan_mode": "deep",
        "file": "api-exp.md",
    },
    {
        "id": "auth-exp",
        "name": "Autorización ampliada",
        "description": (
            "Variante ampliada de Autorización: casos explícitos, matriz de acceso y "
            "ledger de cobertura por rol y tenant."
        ),
        "scan_mode": "deep",
        "file": "auth-exp.md",
    },
]

MIN_NA_REASON = 5

_PLACEHOLDER_RE = re.compile(r"\{\{([A-Z0-9_]+)\}\}(\.?)")
_FULL_LINE_COMMENT_RE = re.compile(r"^[ \t]*<!--.*?-->[ \t]*(?:\n|$)", re.MULTILINE | re.DOTALL)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_LIST_ITEM_RE = re.compile(r"^(\s*)(?:[-*+]|\d+[.)])\s")

# Warnings only: the instruction is published to Kafka and read by the LLM, so
# credentials must never end up in it.
_SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "clave privada"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"), "JWT"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "clave de acceso de AWS"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"), "token bearer"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "token de GitHub"),
    (
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|contraseña|secret|api[_-]?key|token|client[_-]?secret)"
            r"\s*[:=]\s*[\"']?(?=[^\s\"']*[\d!@#$%^&*])[^\s\"']{6,}"
        ),
        "credencial en claro",
    ),
]


class UnknownTemplateError(KeyError):
    pass


@cache
def _catalogs() -> dict[str, Any]:
    data = json.loads((INSTRUCTIONS_DIR / "catalogs.json").read_text(encoding="utf-8"))
    return {k: {**v, "type": "select"} for k, v in data.items() if not k.startswith("_")}


@cache
def _text_fields() -> dict[str, Any]:
    data = json.loads((INSTRUCTIONS_DIR / "fields.json").read_text(encoding="utf-8"))
    return {k: {**v, "type": "text"} for k, v in data.items() if not k.startswith("_")}


def field_spec(placeholder: str) -> dict[str, Any] | None:
    if placeholder.startswith("SELECT_"):
        return _catalogs().get(placeholder)
    return _text_fields().get(placeholder)


def _template(template_id: str) -> dict[str, Any]:
    for tpl in BUILDER_TEMPLATES:
        if tpl["id"] == template_id:
            return tpl
    raise UnknownTemplateError(template_id)


@cache
def template_source(template_id: str) -> str:
    """The template text with any HTML comment (preparation notes) removed."""
    raw = (INSTRUCTIONS_DIR / _template(template_id)["file"]).read_text(encoding="utf-8")
    text = _COMMENT_RE.sub("", _FULL_LINE_COMMENT_RE.sub("", raw))
    return re.sub(r"\n{3,}", "\n\n", text).strip() + "\n"


def template_placeholders(template_id: str) -> list[str]:
    seen: dict[str, None] = {}
    for m in _PLACEHOLDER_RE.finditer(template_source(template_id)):
        seen.setdefault(m.group(1), None)
    return list(seen)


def template_sections(template_id: str) -> list[dict[str, Any]]:
    """Placeholders grouped by the ``##`` section where each first appears."""
    sections: list[dict[str, Any]] = []
    placed: set[str] = set()
    title = "General"
    for line in template_source(template_id).splitlines():
        if line.startswith("## "):
            title = line[3:].strip()
            continue
        for m in _PLACEHOLDER_RE.finditer(line):
            ph = m.group(1)
            if ph in placed:
                continue
            placed.add(ph)
            if not sections or sections[-1]["title"] != title:
                sections.append({"title": title, "fields": []})
            sections[-1]["fields"].append(ph)
    return sections


def builder_config() -> dict[str, Any]:
    """Everything the console needs to draw the form."""
    templates = []
    used: set[str] = set()
    for tpl in BUILDER_TEMPLATES:
        used.update(template_placeholders(tpl["id"]))
        templates.append(
            {
                "id": tpl["id"],
                "name": tpl["name"],
                "description": tpl["description"],
                "scan_mode": tpl["scan_mode"],
                "sections": template_sections(tpl["id"]),
            }
        )
    fields = {ph: field_spec(ph) for ph in sorted(used) if field_spec(ph) is not None}
    return {
        "templates": templates,
        "fields": fields,
        "min_na_reason": MIN_NA_REASON,
        "mandatory": sorted(ph for ph, spec in fields.items() if _is_mandatory(spec)),
    }


# ── Rendering ──────────────────────────────────────────────────────────────


def _is_na(raw: dict[str, Any]) -> bool:
    return bool(raw.get("na"))


def _is_mandatory(spec: dict[str, Any]) -> bool:
    """SELECT_ placeholders are the mandatory ones; a TEXT_ is optional unless flagged.

    An optional field left empty (or marked N/A) removes the whole line that
    carries it, so the instruction never shows a blank or an "N/A: ..." stub.
    """
    if spec["type"] == "select":
        return True
    return bool(spec.get("mandatory"))


def _select_error(
    spec: dict[str, Any], selected: list[str], custom: str, options: dict[str, dict[str, Any]]
) -> str | None:
    """The first reason the selection is not acceptable, or None."""
    unknown = [s for s in selected if s not in options]
    known = [s for s in selected if s in options]
    groups: dict[str, str] = {}
    error = None
    for sid in known:
        label = options[sid]["label"]
        group = options[sid].get("group")
        if options[sid].get("exclusive") and len(selected) > 1:
            error = error or f"«{label}» no se combina con otras opciones."
        elif group and group in groups:
            error = error or f"«{options[groups[group]]['label']}» y «{label}» son incompatibles."
        elif group:
            groups[group] = sid
    if unknown:
        error = f"Opción desconocida: {', '.join(unknown)}."
    elif spec["selection"] == "single" and len(selected) > 1:
        error = "Elige solo una opción."
    elif custom and not spec.get("allow_custom"):
        error = "Este catálogo no admite texto libre."
    elif not selected and not custom:
        error = "Obligatorio: elige una opción o márcalo N/A con motivo."
    return error


def _resolve_select(spec: dict[str, Any], raw: dict[str, Any]) -> tuple[str | None, str | None]:
    options = {o["id"]: o for o in spec["options"]}
    selected = list(dict.fromkeys(raw.get("selected") or []))
    custom = (raw.get("custom") or "").strip()
    error = _select_error(spec, selected, custom, options)
    if error:
        return None, error
    # The catalog carries the sentence each option contributes; fall back to the
    # label so a catalog without `instruction` still renders.
    parts = [options[sid].get("instruction") or options[sid]["label"] for sid in selected]
    if spec.get("ordered"):
        parts = [f"{i}) {p}" for i, p in enumerate(parts, 1)]
    value = "; ".join(parts)
    if custom:
        prefix = spec.get("custom_prefix")
        custom = f"{prefix}: {custom}" if prefix else custom
        value = f"{value}; {custom}" if value else custom
    return value, None


def _resolve_text(spec: dict[str, Any], raw: dict[str, Any]) -> tuple[str | None, str | None]:
    text = (raw.get("value") or "").strip()
    if not text:
        if not _is_mandatory(spec):
            # Optional: the line carrying it is removed from the instruction.
            return None, None
        return None, "Obligatorio: indica un valor."
    kind = spec.get("kind", "text")
    if kind == "line" and "\n" in text:
        return None, "Debe ser una sola línea."
    if kind == "number" and (not text.isdigit() or int(text) < 1):
        return None, "Debe ser un entero positivo."
    return text, None


def _resolve(spec: dict[str, Any], raw: dict[str, Any]) -> tuple[str | None, str | None]:
    if _is_na(raw):
        if spec.get("allow_na") is False:
            return None, "Este campo no admite N/A: indica un valor concreto."
        if not _is_mandatory(spec):
            # Optional: N/A and an empty value are the same thing, and the line
            # is dropped rather than carrying "N/A: ..." into the instruction.
            return None, None
        reason = (raw.get("na_reason") or "").strip()
        if len(reason) < MIN_NA_REASON:
            return None, "N/A necesita un motivo concreto."
        return f"N/A: {reason}", None
    if spec["type"] == "select":
        return _resolve_select(spec, raw)
    return _resolve_text(spec, raw)


def _substitute(text: str, resolved: dict[str, str | None], dropped: set[str]) -> str:
    """Insert each value. A multiline value keeps the indentation of its bullet."""
    out: list[str] = []
    for line in text.split("\n"):
        present = [m.group(1) for m in _PLACEHOLDER_RE.finditer(line)]
        if present and all(ph in dropped for ph in present):
            # Every field on this line was left empty: the line goes with it.
            continue
        item = _LIST_ITEM_RE.match(line)
        indent = (item.group(1) + "  ") if item else re.match(r"\s*", line).group(0)

        def repl(m: re.Match[str], indent: str = indent) -> str:
            ph, dot = m.groups()
            value = resolved.get(ph)
            if value is None:
                # Unresolved: keep the placeholder so the gap stays visible.
                return m.group(0)
            if "\n" in value:
                body = "\n".join((indent + ln) if ln.strip() else "" for ln in value.split("\n"))
                return f"\n{body}"
            if dot and value[-1] in ".!?":
                dot = ""
            return f"{value}{dot}"

        out.append(_PLACEHOLDER_RE.sub(repl, line))
    joined = "\n".join(ln.rstrip() for ln in "\n".join(out).split("\n"))
    return re.sub(r"\n{3,}", "\n\n", joined)


def _secret_warnings(placeholder: str, raw: dict[str, Any]) -> list[dict[str, str]]:
    texts = [raw.get("value"), raw.get("custom"), raw.get("na_reason")]
    found = []
    for pattern, name in _SECRET_PATTERNS:
        if any(t and pattern.search(t) for t in texts):
            message = f"Parece contener un secreto ({name}). No incluyas credenciales."
            found.append({"field": placeholder, "message": message})
    return found


def render_instruction(template_id: str, values: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Render a template. Unresolved placeholders stay as ``{{X}}`` and are listed in ``issues``."""
    _template(template_id)
    resolved: dict[str, str | None] = {}
    dropped: set[str] = set()
    issues: dict[str, str] = {}
    warnings: list[dict[str, str]] = []

    for ph in template_placeholders(template_id):
        spec = field_spec(ph)
        raw = values.get(ph) or {}
        if spec is None:
            resolved[ph] = None
            issues[ph] = "Placeholder sin definición en catalogs.json / fields.json."
            continue
        resolved[ph], error = _resolve(spec, raw)
        if error:
            issues[ph] = error
        if resolved[ph] is None and not error and not _is_mandatory(spec):
            dropped.add(ph)
        warnings.extend(_secret_warnings(ph, raw))

    return {
        "template": template_id,
        "instruction": _substitute(template_source(template_id), resolved, dropped),
        "complete": not issues,
        "issues": issues,
        "warnings": warnings,
    }
