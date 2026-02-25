import os
from typing import Any

import requests

from strix.tools.registry import register_tool


SYSTEM_PROMPT = """# Role
You are assisting a cybersecurity agent specialized in vulnerability
scanning and security assessment running on Kali Linux.

# Priority Areas
When responding to search queries, prioritize cybersecurity-relevant information including:
- Vulnerability details (CVEs, CVSS scores, impact)
- Security tools, techniques, and methodologies
- Exploit information and proof-of-concepts
- Security best practices and mitigations
- Penetration testing approaches
- Web application security findings

# Response Guidelines
- Provide technical depth appropriate for security professionals
- Include specific versions, configurations, and technical details when available
- Focus on actionable intelligence for security assessment
- Cite reliable security sources (NIST, OWASP, CVE databases, security vendors)
- When providing commands or installation instructions, prioritize
  Kali Linux compatibility and use apt package manager or tools
  pre-installed in Kali
- Be detailed and specific - avoid general answers. Always include
  concrete code examples, command-line instructions, configuration
  snippets, or practical implementation steps when applicable
- Structure your response to be comprehensive yet concise, emphasizing
  the most critical security implications and details"""


@register_tool(sandbox_execution=False)
def web_search(query: str) -> dict[str, Any]:
    try:
        api_key = os.getenv("PERPLEXITY_API_KEY")
        if not api_key:
            return {
                "success": False,
                "message": "PERPLEXITY_API_KEY environment variable not set",
                "results": [],
            }

        url = "https://api.perplexity.ai/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

        payload = {
            "model": "sonar-reasoning",
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": query},
            ],
        }

        response = requests.post(url, headers=headers, json=payload, timeout=300)
        response.raise_for_status()

        response_data = response.json()
        content = response_data["choices"][0]["message"]["content"]

    except requests.exceptions.Timeout:
        return {"success": False, "message": "Request timed out", "results": []}
    except requests.exceptions.RequestException as e:
        return {"success": False, "message": f"API request failed: {e!s}", "results": []}
    except KeyError as e:
        return {
            "success": False,
            "message": f"Unexpected API response format: missing {e!s}",
            "results": [],
        }
    except Exception as e:  # noqa: BLE001
        return {"success": False, "message": f"Web search failed: {e!s}", "results": []}
    else:
        return {
            "success": True,
            "query": query,
            "content": content,
            "message": "Web search completed successfully",
        }
