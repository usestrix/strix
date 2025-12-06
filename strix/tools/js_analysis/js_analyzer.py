import esprima
import json
import curl_cffi.requests
from typing import Any, List, Dict
from strix.tools.registry import register_tool

@register_tool
def analyze_js_ast(js_code: str) -> str:
    """
    Analyzes JavaScript code using AST parsing to find interesting literals (strings, numbers)
    and potential API endpoints or secrets.
    """
    try:
        tree = esprima.parseScript(js_code, options={'tolerant': True, 'loc': True})
    except Exception as e:
        return f"Error parsing JS: {e}"

    findings = {
        "literals": set(),
        "identifiers": set(),
        "potential_urls": set(),
        "potential_secrets": set(),
    }

    def traverse(node):
        if not node:
            return

        # Check for literals
        if node.type == 'Literal':
            value = node.value
            if isinstance(value, str):
                if len(value) > 3:
                    findings["literals"].add(value)
                if value.startswith(("http", "/api", "/v1")):
                    findings["potential_urls"].add(value)
                # Lower threshold for secrets for testing purposes
                if len(value) > 10 and any(k in value.lower() for k in ["key", "token", "secret", "password", "sk_", "pk_"]):
                     findings["potential_secrets"].add(value) # Heuristic

        # Check for identifiers
        if node.type == 'Identifier':
            findings["identifiers"].add(node.name)

        # Recursion
        for key, value in node.__dict__.items():
            if key in ['type', 'loc', 'range']: continue
            if isinstance(value, list):
                for item in value:
                    if hasattr(item, 'type'):
                        traverse(item)
            elif hasattr(value, 'type'):
                traverse(value)

    traverse(tree)

    # Format output
    report = []
    if findings["potential_urls"]:
        report.append("Potential URLs/Endpoints:")
        report.extend(f"- {u}" for u in sorted(findings["potential_urls"]))
        report.append("")

    if findings["potential_secrets"]:
        report.append("Potential Secrets (High Entropy/Keywords):")
        report.extend(f"- {s}" for s in sorted(findings["potential_secrets"]))
        report.append("")

    report.append(f"Found {len(findings['literals'])} string literals and {len(findings['identifiers'])} identifiers.")

    return "\n".join(report) if report else "No significant findings from AST analysis."

@register_tool
def validate_secrets(secrets: List[str], target_url: str) -> str:
    """
    Validates a list of potential secrets by testing them against the target URL.
    Attempts common authentication headers.

    Args:
        secrets: List of potential secret strings.
        target_url: The URL to test against (e.g., /api/user).

    Returns:
        Report of valid/invalid secrets.
    """
    results = []

    # Common auth headers to try
    auth_headers_schemes = [
        "Bearer {}",
        "Token {}",
        "Basic {}", # Might need encoding, but we'll try raw first if it looks like b64
        "{}", # Custom header value
    ]

    custom_headers_keys = [
        "Authorization",
        "X-API-Key",
        "X-Token",
        "ApiKey"
    ]

    for secret in secrets:
        is_valid = False
        for header_key in custom_headers_keys:
            for scheme in auth_headers_schemes:
                try:
                    auth_value = scheme.format(secret)
                    headers = {header_key: auth_value}

                    # Use curl_cffi for stealth
                    response = curl_cffi.requests.get(
                        target_url,
                        headers=headers,
                        timeout=5,
                        impersonate="chrome110",
                        verify=False
                    )

                    if response.status_code in [200, 201, 204]:
                        results.append(f"[VALID] Secret: {secret} | Header: {header_key}: {auth_value} | Status: {response.status_code}")
                        is_valid = True
                        break # Found a working combo for this secret
                    elif response.status_code in [401, 403]:
                        pass # Invalid
                    else:
                        results.append(f"[UNKNOWN] Secret: {secret} | Header: {header_key} | Status: {response.status_code}")

                except Exception as e:
                     results.append(f"[ERROR] Testing {secret}: {e}")

            if is_valid: break

    if not results:
        return "No valid secrets found (all returned 401/403 or failed)."

    return "\n".join(results)
