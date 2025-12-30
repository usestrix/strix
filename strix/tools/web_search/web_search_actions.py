import os
import logging
import tarfile
import io
from pathlib import Path
from typing import Any

import litellm
import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from strix.tools.registry import register_tool
from strix.telemetry.tracer import get_global_tracer
from strix.runtime import get_runtime

logger = logging.getLogger(__name__)

SYSTEM_PROMPT_FIRECRAWL = """You are assisting a cybersecurity agent specialized in vulnerability scanning
and security assessment running on Kali Linux.

You have been provided with search results from the web in Markdown format.
Your task is to synthesize this information to answer the user's query comprehensively.

1. Prioritize cybersecurity-relevant information including:
   - Vulnerability details (CVEs, CVSS scores, impact)
   - Security tools, techniques, and methodologies
   - Exploit information and proof-of-concepts
   - Security best practices and mitigations
   - Web application security findings

2. Provide technical depth appropriate for security professionals.
3. Cite sources implicitly by validating facts against the provided search context.
4. If the search results do not contain the answer, state that clearly and suggest what else might be searched.
5. Focus on actionable intelligence for security assessment.
6. Be detailed and specific - always include concrete code examples, command-line instructions,
   or practical implementation steps when applicable.

Structure your response to be comprehensive yet concise, emphasizing the most critical
security implications.
"""

SYSTEM_PROMPT_PERPLEXITY = """You are assisting a cybersecurity agent specialized in vulnerability scanning
and security assessment running on Kali Linux. When responding to search queries:

1. Prioritize cybersecurity-relevant information including:
   - Vulnerability details (CVEs, CVSS scores, impact)
   - Security tools, techniques, and methodologies
   - Exploit information and proof-of-concepts
   - Security best practices and mitigations
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


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10), reraise=True)
def _firecrawl_search(query: str, api_key: str) -> dict[str, Any]:
    """Execute search via Firecrawl API with retries."""
    url = "https://api.firecrawl.dev/v1/search"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    # We ask for markdown content to feed into the LLM
    payload = {
        "query": query,
        "limit": 5,
        "scrapeOptions": {
            "formats": ["markdown"]
        }
    }

    response = requests.post(url, headers=headers, json=payload, timeout=60)
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        # Include the response text in the error for debugging
        raise RuntimeError(f"Firecrawl API Error ({e.response.status_code}): {e.response.text}") from e

    return response.json()


def _save_scraped_data(data: list[dict[str, Any]], query: str, agent_state: Any | None) -> None:
    """Save scraped data to host and sandbox."""
    try:
        tracer = get_global_tracer()
        if not tracer:
            return

        run_dir = tracer.get_run_dir()
        scraped_dir = run_dir / "scraped_data"
        scraped_dir.mkdir(exist_ok=True)

        # Sanitize query for filename
        import re
        safe_query = re.sub(r'[^a-zA-Z0-9]', '_', query)[:50]

        saved_files = []

        for i, item in enumerate(data):
            markdown = item.get("markdown", "")
            title = item.get("title", "untitled")
            url = item.get("url", "no_url")

            if not markdown:
                continue

            filename = f"{safe_query}_{i}.md"
            file_path = scraped_dir / filename

            with file_path.open("w", encoding="utf-8") as f:
                f.write(f"--- \nTitle: {title}\nURL: {url}\n---\n\n")
                f.write(markdown)
            saved_files.append(file_path)

        # If we have an active agent state (sandbox), copy files there
        if agent_state and agent_state.sandbox_id:
            try:
                runtime = get_runtime()
                # Check if it's DockerRuntime by duck typing or import
                if hasattr(runtime, "client"):
                    container = runtime.client.containers.get(agent_state.sandbox_id)

                    # Create tarball in memory
                    tar_buffer = io.BytesIO()
                    with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
                        for file_path in saved_files:
                            arcname = f"scraped_data/{file_path.name}"
                            tar.add(file_path, arcname=arcname)

                    tar_buffer.seek(0)

                    # Create directory in container first
                    container.exec_run("mkdir -p /workspace/scraped_data")

                    # Copy files
                    container.put_archive("/workspace", tar_buffer.getvalue())

                    # Fix permissions
                    container.exec_run("chown -R pentester:pentester /workspace/scraped_data")

                    logger.info(f"Copied {len(saved_files)} scraped files to sandbox /workspace/scraped_data")

            except Exception as e:
                logger.warning(f"Failed to copy scraped data to sandbox: {e}")

    except Exception as e:
        logger.warning(f"Failed to save scraped data: {e}")


def _perplexity_search(query: str, api_key: str) -> dict[str, Any]:
    """Execute search via Perplexity API."""
    url = "https://api.perplexity.ai/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    payload = {
        "model": "sonar-reasoning",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_PERPLEXITY},
            {"role": "user", "content": query},
        ],
    }

    response = requests.post(url, headers=headers, json=payload, timeout=300)
    response.raise_for_status()

    response_data = response.json()
    content = response_data["choices"][0]["message"]["content"]
    return {
        "success": True,
        "query": query,
        "content": content,
        "message": "Web search completed successfully via Perplexity",
    }


@register_tool(sandbox_execution=False)
def web_search(query: str, agent_state: Any | None = None) -> dict[str, Any]:
    try:
        # Prioritize Perplexity if available
        perplexity_key = os.getenv("PERPLEXITY_API_KEY")
        if perplexity_key:
            return _perplexity_search(query, perplexity_key)

        firecrawl_key = os.getenv("FIRECRAWL_API_KEY")
        if not firecrawl_key:
            return {
                "success": False,
                "message": "Neither PERPLEXITY_API_KEY nor FIRECRAWL_API_KEY environment variables are set. Please configure one to use web search.",
                "results": [],
            }

        # 1. Search and Crawl with Firecrawl
        try:
            search_data = _firecrawl_search(query, firecrawl_key)
        except Exception as e:
            logger.error(f"Firecrawl search failed: {e}")
            return {
                "success": False,
                "message": f"Search failed: {e}",
                "results": []
            }

        if not search_data.get("success") or not search_data.get("data"):
             return {
                "success": False,
                "message": "No results found.",
                "results": [],
            }

        # 1.5 Save Scraped Data
        _save_scraped_data(search_data["data"], query, agent_state)

        # 2. Prepare Context for LLM
        context_parts = []
        for item in search_data["data"]:
            title = item.get("title", "No Title")
            url = item.get("url", "No URL")
            markdown = item.get("markdown", "")
            # Truncate very long pages to avoid token limits, though modern models handle large context well.
            # 10k chars is a safe starting heuristic per page for 5 pages.
            markdown_snippet = markdown[:15000]

            context_parts.append(f"Source: {title} ({url})\n\nContent:\n{markdown_snippet}\n---")

        full_context = "\n".join(context_parts)

        # 3. Synthesize with LLM
        llm_model = os.getenv("STRIX_LLM", "openai/gpt-4o")
        llm_api_key = os.getenv("LLM_API_KEY")
        llm_api_base = os.getenv("LLM_API_BASE")

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT_FIRECRAWL},
            {"role": "user", "content": f"User Query: {query}\n\nSearch Results:\n{full_context}"}
        ]

        completion_kwargs = {
            "model": llm_model,
            "messages": messages,
            "timeout": 120,
        }
        if llm_api_key:
            completion_kwargs["api_key"] = llm_api_key
        if llm_api_base:
            completion_kwargs["api_base"] = llm_api_base

        response = litellm.completion(**completion_kwargs)
        content = response.choices[0].message.content

    except Exception as e:
        logger.exception("Web search synthesis failed")
        return {"success": False, "message": f"Web search failed: {e!s}", "results": []}
    else:
        return {
            "success": True,
            "query": query,
            "content": content,
            "message": "Web search completed successfully via Firecrawl",
        }