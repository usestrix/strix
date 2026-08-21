"""Opt-in verify-before-emit pass for vulnerability findings.

A sibling of the dedupe reject in ``strix.tools.reporting.tool``: just before a
candidate finding is persisted, a (typically cheaper) model re-adjudicates it
and may reject a confident false positive. The pass is off by default and
**fail-open + asymmetric** — only a FALSE_POSITIVE verdict at or above
``min_confidence`` suppresses the report. REAL, uncertain, below-threshold,
unparseable, no-model, or any error all EMIT, so a verifier miss can never drop
a real finding.
"""

from __future__ import annotations

import json
import logging
import math
from typing import TYPE_CHECKING, Any

from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from openai.types.responses import ResponseOutputMessage

from strix.config import load_settings
from strix.config.models import StrixProvider, configure_sdk_model_defaults
from strix.core.inputs import make_model_settings
from strix.report.state import get_global_report_state


if TYPE_CHECKING:
    from agents.items import ModelResponse

    from strix.config.settings import VerifySettings

logger = logging.getLogger(__name__)

# Severity floor ranking (higher = more severe). A finding is verified only when
# its severity rank is >= the configured min_severity's rank.
_SEVERITY_RANK = {
    "info": 0,
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

VERIFY_SYSTEM_PROMPT = """\
You are a security finding verifier. You are given a single vulnerability \
finding that another agent has proposed reporting. Decide whether it is a REAL \
vulnerability or a FALSE_POSITIVE, re-deriving the conclusion from the evidence \
provided — do not assume the proposing agent was correct.

Rules:
- A PARTIAL or INCOMPLETE fix is still REAL. If a control only covers some of \
the dangerous inputs (e.g. a sanitizer that misses an encoding, a path guard \
bypassable via symlink, a blocklist missing an alias), the finding is REAL.
- The absence of a proof-of-concept is NOT grounds for FALSE_POSITIVE. Judge \
the code path, not whether an exploit script was attached.
- "A scanner flagged it but it may not be reachable" is NOT, on its own, \
grounds for FALSE_POSITIVE — say REAL unless you can show the sink is \
unreachable or already neutralised on every path.
- Be asymmetric: only answer FALSE_POSITIVE with confidence >= 0.8 when the \
refutation is airtight. On any genuine doubt, answer REAL.

Respond with ONLY a JSON object:
{"verdict": "REAL" | "FALSE_POSITIVE", "confidence": <0.0-1.0>, "reason": "<one sentence>"}
"""


def _verify_extra_args(verify: VerifySettings) -> dict[str, str]:
    """Per-call credential + endpoint for a *dedicated* verify model.

    Only applies when STRIX_VERIFY_MODEL is set: the verifier's key/base must
    never be overlaid onto the main model when the verifier falls back to it
    (that would point verification at the wrong endpoint/account). Mirrors the
    dedupe module's gating.
    """
    if not verify.model:
        return {}
    extra: dict[str, str] = {}
    if verify.api_key and verify.api_key.strip():
        extra["api_key"] = verify.api_key.strip()
    if verify.api_base and verify.api_base.strip():
        extra["api_base"] = verify.api_base.strip()
    return extra


def _verify_model_settings(
    verify: VerifySettings, model_name: str, request_timeout: float | None
) -> ModelSettings:
    llm = load_settings().llm
    settings = make_model_settings(
        verify.reasoning_effort,
        model_name=model_name,
        force_required_tool_choice=False,
        request_timeout=request_timeout,
        # Only forward the main endpoint's headers when the verifier falls back
        # to the main model; a dedicated verify model may route elsewhere and
        # must not receive the main endpoint's credentials.
        extra_headers=verify.extra_headers if verify.model else llm.extra_headers,
    )
    extra = _verify_extra_args(verify)
    if extra:
        settings = settings.resolve(ModelSettings(extra_args=extra))
    return settings


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


def _parse_verdict(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError(f"No JSON object found in verify response: {content[:500]}")
    parsed = json.loads(text[start : end + 1])

    verdict = str(parsed.get("verdict") or "").strip().upper()
    reason = str(parsed.get("reason") or "")[:500]
    # The model output is untrusted (no schema is enforced on the response), so
    # a confidence outside [0, 1] — 100, 1e999, -5, nan — must not be able to
    # authorize suppression. Anything non-finite or out of range collapses to
    # 0.0, which fails the min_confidence gate and emits (fail-open).
    try:
        confidence = float(parsed.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    if not math.isfinite(confidence) or not (0.0 <= confidence <= 1.0):
        confidence = 0.0
    return {"verdict": verdict, "confidence": confidence, "reason": reason}


def _meets_min_severity(severity: str, min_severity: str) -> bool:
    have = _SEVERITY_RANK.get((severity or "").strip().lower(), 0)
    need = _SEVERITY_RANK.get((min_severity or "high").strip().lower(), 3)
    return have >= need


async def verify_finding(candidate: dict[str, Any], severity: str) -> dict[str, Any]:
    """Adjudicate a candidate finding.

    Returns a dict with ``reject`` (bool), ``verdict``, ``confidence`` and
    ``reason``. ``reject`` is True only for a high-confidence FALSE_POSITIVE;
    every other outcome — including errors — returns ``reject=False`` so the
    finding is emitted (fail-open, FN=0 posture).
    """
    settings = load_settings()
    verify = settings.verify

    if not verify.enabled:
        return {"reject": False, "verdict": "SKIPPED", "confidence": 0.0, "reason": "disabled"}

    if not _meets_min_severity(severity, verify.min_severity):
        return {
            "reject": False,
            "verdict": "SKIPPED",
            "confidence": 0.0,
            "reason": f"severity {severity!r} below min_severity {verify.min_severity!r}",
        }

    model_name = (verify.model or "").strip() or settings.llm.model
    if not model_name:
        return {
            "reject": False,
            "verdict": "SKIPPED",
            "confidence": 0.0,
            "reason": "no LLM model configured; emitting without verification",
        }

    try:
        user_msg = (
            "Verify this candidate vulnerability finding:\n\n"
            f"{json.dumps(candidate, indent=2)}\n\n"
            "Respond with ONLY the JSON object described in the system prompt."
        )

        configure_sdk_model_defaults(settings)
        resolved_model = model_name.strip()
        model = StrixProvider().get_model(resolved_model)
        response = await model.get_response(
            system_instructions=VERIFY_SYSTEM_PROMPT,
            input=user_msg,
            model_settings=_verify_model_settings(verify, resolved_model, settings.llm.timeout),
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
                agent_id="verify",
                agent_name="verify",
                model=resolved_model,
                usage=response.usage,
            )

        content = _extract_text(response)
        if not content:
            return {
                "reject": False,
                "verdict": "ERROR",
                "confidence": 0.0,
                "reason": "empty verifier response; emitting",
            }

        parsed = _parse_verdict(content)
        reject = (
            parsed["verdict"] == "FALSE_POSITIVE" and parsed["confidence"] >= verify.min_confidence
        )
        logger.info(
            "verify: verdict=%s confidence=%.2f reject=%s title=%s",
            parsed["verdict"],
            parsed["confidence"],
            reject,
            candidate.get("title", ""),
        )
        return {
            "reject": reject,
            "verdict": parsed["verdict"],
            "confidence": parsed["confidence"],
            "reason": parsed["reason"],
        }
    except Exception as exc:  # noqa: BLE001 — verifier must never drop a finding
        logger.warning("verify: adjudication failed (%s); emitting without verification", exc)
        return {"reject": False, "verdict": "ERROR", "confidence": 0.0, "reason": str(exc)[:200]}
