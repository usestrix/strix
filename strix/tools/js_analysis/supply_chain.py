import json
from typing import Any, List, Dict
from strix.tools.registry import register_tool

@register_tool
def scan_package_json(package_json_content: str) -> str:
    """
    Scans a package.json file content for known vulnerable dependencies (basic check).
    In a real scenario, this would check against a live CVE database.
    Here we check against a static list of common high-risk packages/versions for demo purposes.
    """
    try:
        data = json.loads(package_json_content)
    except json.JSONDecodeError as e:
        return f"Error parsing package.json: {e}"

    dependencies = data.get("dependencies", {})
    dev_dependencies = data.get("devDependencies", {})
    all_deps = {**dependencies, **dev_dependencies}

    vulnerable_patterns = {
        "axios": "<0.21.1", # CVE-2020-28168
        "lodash": "<4.17.21", # Prototype Pollution
        "jquery": "<3.5.0", # XSS
        "react": "<16.14.0", # XSS
        "express": "<4.17.3", # various
        "moment": "<2.29.2", # ReDoS
    }

    report = []

    # Helper to compare versions loosely
    def is_vulnerable(version_str, criteria):
        # Very basic version check (heuristic)
        # Assuming version_str like "^1.2.3" or "1.2.3"
        clean_ver = version_str.lstrip("^~")
        clean_crit = criteria.lstrip("<")

        try:
            v_parts = [int(x) for x in clean_ver.split(".")]
            c_parts = [int(x) for x in clean_crit.split(".")]

            # Pad with zeros
            while len(v_parts) < 3: v_parts.append(0)
            while len(c_parts) < 3: c_parts.append(0)

            if v_parts < c_parts:
                return True
        except ValueError:
            pass # Non-semantic version
        return False

    for dep, ver in all_deps.items():
        if dep in vulnerable_patterns:
            crit = vulnerable_patterns[dep]
            if is_vulnerable(ver, crit):
                report.append(f"[VULNERABLE] {dep} version {ver} matches criteria {crit}")
            else:
                report.append(f"[INFO] {dep} version {ver} found (might be safe, criteria {crit})")

    if not report:
        return "No obvious vulnerable dependencies found in common list."

    return "\n".join(report)
