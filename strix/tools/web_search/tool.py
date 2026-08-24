"""``web_search`` — Perplexity-backed security-focused web search."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import requests
from agents import RunContextWrapper, function_tool

from strix.config import load_settings


logger = logging.getLogger(__name__)


_SYSTEM_PROMPT = """You are assisting a cybersecurity agent specialized in vulnerability scanning
and security assessment running on Kali Linux. When responding to search queries:

1. Prioritize cybersecurity-relevant information including:
   - Vulnerability details (CVEs, CVSS scores, impact)
   - Security tools, techniques, and methodologies
   - Exploit information and proof-of-concepts
   - Security best practices and mitigations
   - Penetration testing approaches
   - Web application security findings

2. Provide technical depth appropriate for security professionals
3. Include specific versions, configurations, and technical details when available
4. Focus on actionable intelligence for security assessment
5. Cite reliable security sources (NIST, OWASP, CVE databases, security vendors)
6. When providing commands or installation instructions, prioritize Kali Linux compatibility
   and use apt package manager or tools pre-installed in Kali
7. Be detailed and specific - avoid general answers. Always include concrete code examples,
   command-line instructions, configuration snippets, or practical implementation steps
   when applicable

Structure your response to be comprehensive yet concise, emphasizing the most critical
security implications and details."""


def _do_search(query: str) -> dict[str, Any]:  # noqa: PLR0911 - each error class needs its own sanitized return
    if not query or not query.strip():
        return {"success": False, "error": "Query cannot be empty"}

    api_key = load_settings().integrations.perplexity_api_key
    if not api_key:
        logger.warning("web_search invoked without PERPLEXITY_API_KEY configured")
        return {
            "success": False,
            "error": (
                "Web search is not configured for this scan "
                "(operator needs to set PERPLEXITY_API_KEY). Proceed without it"
            ),
        }
    logger.info("web_search query (len=%d): %s", len(query), query[:120])

    url = "https://api.perplexity.ai/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": query},
        ],
    }

    try:
        with requests.post(url, headers=headers, json=payload, timeout=300) as response:
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
    except requests.exceptions.Timeout:
        logger.warning("web_search timed out")
        return {
            "success": False,
            "error": "Web search timed out. Try again or shorten the query",
        }
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else None
        logger.exception("web_search HTTP error status=%s", status)
        if status is not None and 400 <= status < 500:
            return {
                "success": False,
                "error": (
                    "Web search rejected the query. Refine it "
                    "(more specific, shorter, no unusual characters) and retry"
                ),
            }
        return {
            "success": False,
            "error": "Web search service is unavailable. Try again later",
        }
    except requests.exceptions.RequestException:
        logger.exception("web_search network error")
        return {
            "success": False,
            "error": "Web search network error. Try again later",
        }
    except (KeyError, IndexError, ValueError):
        logger.exception("web_search response shape unexpected")
        return {
            "success": False,
            "error": "Web search returned an unexpected response. Try again",
        }
    except Exception:
        logger.exception("web_search failed")
        return {
            "success": False,
            "error": "Web search failed unexpectedly",
        }
    else:
        return {
            "success": True,
            "query": query,
            "content": content,
        }


@function_tool(timeout=330)
async def web_search(ctx: RunContextWrapper, query: str) -> str:
    """Real-time web search via Perplexity — your primary research tool.

    Use it liberally for anything that's not in your training data:

    - Current CVEs, advisories, and 0-days for a specific
      service/version (``OpenSSH 9.6 RCE``, ``Jenkins 2.401.3 auth
      bypass``).
    - Latest WAF / EDR bypass techniques (``Cloudflare WAF SQLi
      bypass 2025``, ``CrowdStrike Falcon evasion``).
    - Tool documentation, flag references, payload galleries.
    - Target reconnaissance / OSINT (company tech stack, leaked
      credentials, exposed assets).
    - Cloud-provider misconfiguration patterns
      (Azure/AWS/GCP-specific attack paths).
    - Bug-bounty writeups and security research papers.
    - Compliance frameworks and CWE/CVSS guidance.
    - Picking the right Python lib / Kali tool for a job (``best 2025
      lib for JWT alg-confusion``).
    - When stuck — looking up the exact error message, ``Access
      denied`` quirks, kernel-specific local-privesc exploits.

    Be specific: include version numbers, error messages, target
    technology, and the exact problem you're stuck on. The more context
    in the query, the more actionable the answer. Vague queries get
    generic answers.

    A security-focused system prompt biases responses toward CVEs,
    exploits, Kali-compatible tooling, and concrete code/command
    examples.

    **Good example queries** (each is a full sentence, names a
    version/product, and asks one concrete thing):

    - ``"Found OpenSSH 7.4 on port 22 — any known RCE or privesc for
      this exact version?"``
    - ``"Cloudflare WAF is blocking my sqlmap on a login form — what
      bypass techniques work in 2025?"``
    - ``"Target runs WordPress 5.8.3 + WooCommerce 6.1.1 — current
      RCE chains for this combo?"``
    - ``"Low-priv shell on Ubuntu 20.04 kernel 5.4.0-74-generic — what
      local privesc exploits hit this kernel?"``
    - ``"Compromised domain user on Windows Server 2019 AD — quietest
      paths to Domain Admin without tripping EDR?"``
    - ``"'Access denied' uploading a webshell to IIS 10.0 — alternate
      Windows IIS upload bypass techniques?"``
    - ``"Discovered Jenkins 2.401.3 on staging — current authn-bypass
      and RCE exploits for this version?"``
    - ``"Best 2025 Python lib for JWT algorithm-confusion + weak-secret
      cracking?"``

    Args:
        query: The search query — a full sentence with version numbers,
            target tech, and the specific question. Treat it like a
            ticket title for a senior security engineer.
    """
    result = await asyncio.to_thread(_do_search, query)
    return json.dumps(result, ensure_ascii=False, default=str)
