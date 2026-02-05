import json
import logging
import re
from difflib import SequenceMatcher
from typing import Any

import litellm

from strix.config import Config


logger = logging.getLogger(__name__)

MAX_COMPARISON_CANDIDATES = 10

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

YOU MUST RESPOND WITH EXACTLY THIS XML FORMAT AND NOTHING ELSE:

<dedupe_result>
<is_duplicate>true</is_duplicate>
<duplicate_id>vuln-0001</duplicate_id>
<confidence>0.95</confidence>
<reason>Both reports describe SQL injection in /api/login via the username parameter</reason>
</dedupe_result>

OR if not a duplicate:

<dedupe_result>
<is_duplicate>false</is_duplicate>
<duplicate_id></duplicate_id>
<confidence>0.90</confidence>
<reason>Different endpoints: candidate is /api/search, existing is /api/login</reason>
</dedupe_result>

RULES:
- is_duplicate MUST be exactly "true" or "false" (lowercase)
- duplicate_id MUST be the exact ID from existing reports or empty if not duplicate
- confidence MUST be a decimal (your confidence level in the decision)
- reason MUST be a specific explanation mentioning endpoint/parameter/root cause
- DO NOT include any text outside the <dedupe_result> tags"""


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
    ]

    cleaned = {}
    for field in relevant_fields:
        if report.get(field):
            value = report[field]
            if isinstance(value, str) and len(value) > 8000:
                value = value[:8000] + "...[truncated]"
            cleaned[field] = value

    return cleaned


def _extract_xml_field(content: str, field: str) -> str:
    pattern = rf"<{field}>(.*?)</{field}>"
    match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return ""


def _parse_dedupe_response(content: str) -> dict[str, Any]:
    result_match = re.search(
        r"<dedupe_result>(.*?)</dedupe_result>", content, re.DOTALL | re.IGNORECASE
    )

    if not result_match:
        logger.warning(f"No <dedupe_result> block found in response: {content[:500]}")
        raise ValueError("No <dedupe_result> block found in response")

    result_content = result_match.group(1)

    is_duplicate_str = _extract_xml_field(result_content, "is_duplicate")
    duplicate_id = _extract_xml_field(result_content, "duplicate_id")
    confidence_str = _extract_xml_field(result_content, "confidence")
    reason = _extract_xml_field(result_content, "reason")

    is_duplicate = is_duplicate_str.lower() == "true"

    try:
        confidence = float(confidence_str) if confidence_str else 0.0
    except ValueError:
        confidence = 0.0

    return {
        "is_duplicate": is_duplicate,
        "duplicate_id": duplicate_id[:64] if duplicate_id else "",
        "confidence": confidence,
        "reason": reason[:500] if reason else "",
    }


def _compute_similarity(report_a: dict[str, Any], report_b: dict[str, Any]) -> float:
    """Compute lightweight string similarity between two reports for pre-filtering."""
    fields = ["title", "endpoint", "method", "target", "description"]

    total_score = 0.0
    weights_sum = 0.0

    # Weighted fields: title and endpoint matter most for duplicate detection
    field_weights = {
        "title": 3.0,
        "endpoint": 3.0,
        "method": 1.5,
        "target": 2.0,
        "description": 1.0,
    }

    for field in fields:
        val_a = str(report_a.get(field, "")).lower().strip()
        val_b = str(report_b.get(field, "")).lower().strip()
        weight = field_weights.get(field, 1.0)

        if not val_a or not val_b:
            continue

        ratio = SequenceMatcher(None, val_a, val_b).ratio()
        total_score += ratio * weight
        weights_sum += weight

    return total_score / weights_sum if weights_sum > 0 else 0.0


def _prefilter_candidates(
    candidate: dict[str, Any],
    existing_reports: list[dict[str, Any]],
    max_candidates: int = MAX_COMPARISON_CANDIDATES,
) -> list[dict[str, Any]]:
    """Pre-filter existing reports using string similarity to reduce LLM calls.

    Only the top-N most similar reports are sent to the LLM for detailed comparison,
    avoiding sending hundreds of reports in a single prompt.
    """
    if len(existing_reports) <= max_candidates:
        return existing_reports

    scored = []
    for report in existing_reports:
        score = _compute_similarity(candidate, report)
        scored.append((score, report))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [report for _, report in scored[:max_candidates]]


def check_duplicate(
    candidate: dict[str, Any], existing_reports: list[dict[str, Any]]
) -> dict[str, Any]:
    if not existing_reports:
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 1.0,
            "reason": "No existing reports to compare against",
        }

    try:
        # Pre-filter to only compare against the most similar existing reports
        filtered_reports = _prefilter_candidates(candidate, existing_reports)

        candidate_cleaned = _prepare_report_for_comparison(candidate)
        existing_cleaned = [_prepare_report_for_comparison(r) for r in filtered_reports]

        comparison_data = {"candidate": candidate_cleaned, "existing_reports": existing_cleaned}

        model_name = Config.get("strix_llm")
        api_key = Config.get("llm_api_key")
        api_base = (
            Config.get("llm_api_base")
            or Config.get("openai_api_base")
            or Config.get("litellm_base_url")
            or Config.get("ollama_api_base")
        )

        messages = [
            {"role": "system", "content": DEDUPE_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Compare this candidate vulnerability against existing reports:\n\n"
                    f"{json.dumps(comparison_data, indent=2)}\n\n"
                    f"Respond with ONLY the <dedupe_result> XML block."
                ),
            },
        ]

        completion_kwargs: dict[str, Any] = {
            "model": model_name,
            "messages": messages,
            "timeout": 120,
        }
        if api_key:
            completion_kwargs["api_key"] = api_key
        if api_base:
            completion_kwargs["api_base"] = api_base

        response = litellm.completion(**completion_kwargs)

        content = response.choices[0].message.content
        if not content:
            return {
                "is_duplicate": False,
                "duplicate_id": "",
                "confidence": 0.0,
                "reason": "Empty response from LLM",
            }

        result = _parse_dedupe_response(content)

        logger.info(
            f"Deduplication check: is_duplicate={result['is_duplicate']}, "
            f"confidence={result['confidence']}, reason={result['reason'][:100]}"
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
