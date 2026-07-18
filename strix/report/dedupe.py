"""SDK-native vulnerability-report deduplication."""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any

from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from openai.types.responses import ResponseOutputMessage

from strix.config import load_settings
from strix.config.models import (
    DEFAULT_MODEL_RETRY,
    StrixProvider,
    configure_sdk_model_defaults,
    request_timeout_extra_args,
)
from strix.report.state import get_global_report_state


if TYPE_CHECKING:
    from agents.items import ModelResponse


logger = logging.getLogger(__name__)

DEDUPE_SYSTEM_PROMPT = """You are an expert vulnerability report deduplication judge.
Your task is to determine if a candidate vulnerability report describes the SAME vulnerability
as any existing report.

CRITICAL DEDUPLICATION RULES:

1. SAME VULNERABILITY means:
   - Same root cause (e.g., "missing input validation" not just "SQL injection")
   - Same affected component/endpoint/file (exact match or clear overlap)
   - Same exploitation method or attack vector
   - Would be fixed by the same code change/patch

2. NOT DUPLICATES if:
   - Different endpoints even with same vulnerability type (e.g., SQLi in /login vs /search)
   - Different parameters in same endpoint (e.g., XSS in 'name' vs 'comment' field)
   - Different root causes (e.g., stored XSS vs reflected XSS in same field)
   - Different severity levels due to different impact
   - One is authenticated, other is unauthenticated

3. ARE DUPLICATES even if:
   - Titles are worded differently
   - Descriptions have different level of detail
   - PoC uses different payloads but exploits same issue
   - One report is more thorough than another
   - Minor variations in technical analysis

4. DEPENDENCY-CVE reports use package identity:
   - Same CVE and same package/ecosystem is a duplicate
   - Same CVE but different package/ecosystem is NOT a duplicate
   - Same package/ecosystem but different CVE is NOT a duplicate

COMPARISON GUIDELINES:
- Focus on the technical root cause, not surface-level similarities
- Same vulnerability type (SQLi, XSS) doesn't mean duplicate - location matters
- Consider the fix: would fixing one also fix the other?
- When uncertain, lean towards NOT duplicate

FIELDS TO ANALYZE:
- title, description: General vulnerability info
- target, endpoint, method: Exact location of vulnerability
- technical_analysis: Root cause details
- poc_description: How it's exploited
- impact: What damage it can cause

Respond with a single JSON object and nothing else:

{
  "is_duplicate": true,
  "duplicate_id": "vuln-0001",
  "confidence": 0.95,
  "reason": "Both reports describe SQL injection in /api/login via the username parameter"
}

Or, if not a duplicate:

{
  "is_duplicate": false,
  "duplicate_id": "",
  "confidence": 0.90,
  "reason": "Different endpoints: candidate is /api/search, existing is /api/login"
}

Rules:
- ``is_duplicate`` is a boolean.
- ``duplicate_id`` is the exact id from existing reports, or "" if not a duplicate.
- ``confidence`` is a number between 0 and 1.
- ``reason`` is a specific explanation mentioning endpoint/parameter/root cause.
- Output ONLY the JSON object — no surrounding prose, no code fences."""


def _prepare_report_for_comparison(report: dict[str, Any]) -> dict[str, Any]:
    relevant_fields = [
        "id",
        "title",
        "description",
        "impact",
        "target",
        "technical_analysis",
        "poc_description",
        "endpoint",
        "method",
        "cve",
        "dependency_metadata",
    ]

    cleaned = {}
    for field in relevant_fields:
        if report.get(field):
            value = report[field]
            if isinstance(value, str) and len(value) > 8000:
                value = value[:8000] + "...[truncated]"
            cleaned[field] = value

    return cleaned


def _dependency_identity(report: dict[str, Any]) -> tuple[str, str, str] | None:
    metadata = report.get("dependency_metadata")
    if not isinstance(metadata, dict):
        return None

    raw_cve = report.get("cve")
    raw_package = metadata.get("package_name")
    if not raw_cve or not raw_package:
        return None

    cve = str(raw_cve).strip().upper()
    ecosystem = str(metadata.get("package_ecosystem") or "").strip().lower()
    package_name = str(raw_package).strip().lower()
    if not cve or not package_name:
        return None
    return cve, ecosystem, package_name


def _report_cve(report: dict[str, Any]) -> str:
    return str(report.get("cve") or "").strip().upper()


def _legacy_report_mentions_package(
    report: dict[str, Any],
    *,
    ecosystem: str,
    package_name: str,
) -> bool:
    fields = [
        "title",
        "description",
        "impact",
        "target",
        "technical_analysis",
        "poc_description",
        "evidence",
    ]
    haystack = " ".join(str(report.get(field) or "") for field in fields).lower()
    package_pattern = rf"(?<![\w@./-]){re.escape(package_name)}(?![\w@./-])"
    if re.search(package_pattern, haystack) is None:
        return False
    if not ecosystem:
        return True
    ecosystem_pattern = rf"(?<![\w@./-]){re.escape(ecosystem)}(?![\w@./-])"
    return re.search(ecosystem_pattern, haystack) is not None


def _check_dependency_duplicate(
    candidate: dict[str, Any],
    existing_reports: list[dict[str, Any]],
) -> dict[str, Any] | None:
    candidate_identity = _dependency_identity(candidate)
    if candidate_identity is None:
        return None

    cve, ecosystem, package_name = candidate_identity
    found_legacy_same_cve = False
    for report in existing_reports:
        report_identity = _dependency_identity(report)
        if report_identity is not None:
            report_cve, report_ecosystem, report_package_name = report_identity
            if (report_cve, report_package_name) != (cve, package_name):
                continue
            if report_ecosystem == ecosystem:
                return {
                    "is_duplicate": True,
                    "duplicate_id": str(report.get("id") or "")[:64],
                    "confidence": 1.0,
                    "reason": "Same dependency CVE/package identity",
                }
            if not report_ecosystem or not ecosystem:
                return {
                    "is_duplicate": True,
                    "duplicate_id": str(report.get("id") or "")[:64],
                    "confidence": 1.0,
                    "reason": "Same dependency CVE/package identity with missing ecosystem",
                }
            continue

        if _report_cve(report) != cve:
            continue
        found_legacy_same_cve = True
        if _legacy_report_mentions_package(
            report,
            ecosystem=ecosystem,
            package_name=package_name,
        ):
            return {
                "is_duplicate": True,
                "duplicate_id": str(report.get("id") or "")[:64],
                "confidence": 1.0,
                "reason": "Same dependency CVE/package identity in legacy report",
            }

    if found_legacy_same_cve:
        return None

    package_label = f"{ecosystem}/{package_name}" if ecosystem else package_name
    return {
        "is_duplicate": False,
        "duplicate_id": "",
        "confidence": 1.0,
        "reason": f"No existing dependency report for {cve} in {package_label}",
    }


def _parse_dedupe_response(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError(f"No JSON object found in dedupe response: {content[:500]}")
    parsed = json.loads(text[start : end + 1])

    duplicate_id = str(parsed.get("duplicate_id") or "")[:64]
    reason = str(parsed.get("reason") or "")[:500]
    try:
        confidence = float(parsed.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0

    return {
        "is_duplicate": bool(parsed.get("is_duplicate", False)),
        "duplicate_id": duplicate_id,
        "confidence": confidence,
        "reason": reason,
    }


def _extract_text(response: ModelResponse) -> str:
    parts: list[str] = []
    for item in response.output:
        if not isinstance(item, ResponseOutputMessage):
            continue
        for chunk in item.content:
            text = getattr(chunk, "text", None)
            if text:
                parts.append(text)
    return "".join(parts)


async def check_duplicate(
    candidate: dict[str, Any], existing_reports: list[dict[str, Any]]
) -> dict[str, Any]:
    if not existing_reports:
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 1.0,
            "reason": "No existing reports to compare against",
        }

    dependency_duplicate = _check_dependency_duplicate(candidate, existing_reports)
    if dependency_duplicate is not None:
        return dependency_duplicate

    try:
        settings = load_settings()
        model_name = settings.llm.model
        if not model_name:
            return {
                "is_duplicate": False,
                "duplicate_id": "",
                "confidence": 0.0,
                "reason": "STRIX_LLM not configured; skipping dedupe check",
            }

        candidate_cleaned = _prepare_report_for_comparison(candidate)
        existing_cleaned = [_prepare_report_for_comparison(r) for r in existing_reports]
        comparison_data = {"candidate": candidate_cleaned, "existing_reports": existing_cleaned}

        user_msg = (
            f"Compare this candidate vulnerability against existing reports:\n\n"
            f"{json.dumps(comparison_data, indent=2)}\n\n"
            f"Respond with ONLY the JSON object described in the system prompt."
        )

        configure_sdk_model_defaults(settings)
        resolved_model = model_name.strip()
        model = StrixProvider().get_model(resolved_model)
        response = await model.get_response(
            system_instructions=DEDUPE_SYSTEM_PROMPT,
            input=user_msg,
            model_settings=ModelSettings(
                retry=DEFAULT_MODEL_RETRY,
                include_usage=True,
                extra_args=request_timeout_extra_args(settings.llm.timeout),
            ),
            tools=[],
            output_schema=None,
            handoffs=[],
            tracing=ModelTracing.DISABLED,
            previous_response_id=None,
            conversation_id=None,
            prompt=None,
        )
        report_state = get_global_report_state()
        if report_state is not None:
            report_state.record_sdk_usage(
                agent_id="dedupe",
                agent_name="dedupe",
                model=resolved_model,
                usage=response.usage,
            )
        content = _extract_text(response)
        if not content:
            return {
                "is_duplicate": False,
                "duplicate_id": "",
                "confidence": 0.0,
                "reason": "Empty response from LLM",
            }

        result = _parse_dedupe_response(content)

        logger.info(
            "Deduplication check: is_duplicate=%s, confidence=%.2f, reason=%s",
            result["is_duplicate"],
            result["confidence"],
            result["reason"][:100],
        )

    except Exception as e:
        logger.exception("Error during vulnerability deduplication check")
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 0.0,
            "reason": f"Deduplication check failed: {e}",
            "error": str(e),
        }
    else:
        return result
