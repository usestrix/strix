from typing import Any

from strix.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def create_vulnerability_report(
    title: str,
    content: str,
    severity: str,
) -> dict[str, Any]:
    validation_error = None
    if not title or not title.strip():
        validation_error = "Title cannot be empty"
    elif not content or not content.strip():
        validation_error = "Content cannot be empty"
    elif not severity or not severity.strip():
        validation_error = "Severity cannot be empty"
    else:
        valid_severities = ["critical", "high", "medium", "low", "info"]
        if severity.lower() not in valid_severities:
            validation_error = (
                f"Invalid severity '{severity}'. Must be one of: {', '.join(valid_severities)}"
            )

    if validation_error:
        return {"success": False, "message": validation_error}

    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer:
            report_id = tracer.add_vulnerability_report(
                title=title,
                content=content,
                severity=severity,
            )

            return {
                "success": True,
                "message": f"Vulnerability report '{title}' created successfully",
                "report_id": report_id,
                "severity": severity.lower(),
            }
        import logging

        logging.warning("Global tracer not available - vulnerability report not stored")

        return {  # noqa: TRY300
            "success": True,
            "message": f"Vulnerability report '{title}' created successfully (not persisted)",
            "warning": "Report could not be persisted - tracer unavailable",
        }

    except ImportError:
        return {
            "success": True,
            "message": f"Vulnerability report '{title}' created successfully (not persisted)",
            "warning": "Report could not be persisted - tracer module unavailable",
        }
    except (ValueError, TypeError) as e:
        return {"success": False, "message": f"Failed to create vulnerability report: {e!s}"}
