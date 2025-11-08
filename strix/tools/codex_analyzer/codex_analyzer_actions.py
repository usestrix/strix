"""
OpenAI Codex integration for advanced code analysis and vulnerability detection.

This module provides specialized code analysis capabilities using OpenAI's Codex models
for enhanced static analysis, vulnerability detection, and code explanation.
"""

import logging
import os
from typing import Any

import litellm


logger = logging.getLogger(__name__)


def _get_codex_model() -> str:
    """
    Get the Codex model to use for analysis.
    
    Returns:
        Model name for Codex analysis
    """
    # Check if user has specified a Codex model
    codex_model = os.getenv("STRIX_CODEX_MODEL")
    if codex_model:
        return codex_model
    
    # Default to code-davinci-002 if available, otherwise use main LLM
    return os.getenv("STRIX_LLM", "openai/gpt-4")


def _make_codex_request(prompt: str, max_tokens: int = 2000) -> str:
    """
    Make a request to Codex model.
    
    Args:
        prompt: The prompt to send to Codex
        max_tokens: Maximum tokens in response
        
    Returns:
        Response text from Codex
    """
    model = _get_codex_model()
    
    try:
        response = litellm.completion(
            model=model,
            messages=[
                {"role": "system", "content": "You are an expert security researcher and code analyst."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens,
            temperature=0.1,  # Low temperature for consistent analysis
        )
        
        if response.choices and response.choices[0].message:
            return response.choices[0].message.content or ""
        
        return ""
        
    except Exception as e:
        logger.error(f"Codex request failed: {e}")
        return f"Error: Failed to analyze code - {e}"


def analyze_code_security(
    code: str,
    language: str = "python",
    focus_areas: list[str] | None = None
) -> dict[str, Any]:
    """
    Perform comprehensive security analysis on code using Codex.
    
    Args:
        code: Source code to analyze
        language: Programming language (python, javascript, java, etc.)
        focus_areas: Specific vulnerability types to focus on
        
    Returns:
        Dictionary containing security analysis results
    """
    focus = ", ".join(focus_areas) if focus_areas else "all common vulnerabilities"
    
    prompt = f"""Analyze the following {language} code for security vulnerabilities.
Focus on: {focus}

Code:
```{language}
{code}
```

Provide a detailed security analysis including:
1. Identified vulnerabilities (with severity: critical, high, medium, low)
2. Specific line numbers or code sections affected
3. Exploitation scenarios
4. Recommended fixes

Format your response as structured findings."""

    analysis = _make_codex_request(prompt, max_tokens=3000)
    
    return {
        "language": language,
        "analysis": analysis,
        "focus_areas": focus_areas or ["all"],
        "model": _get_codex_model(),
    }


def find_vulnerabilities(
    code: str,
    language: str = "python",
    vulnerability_type: str | None = None
) -> dict[str, Any]:
    """
    Find specific types of vulnerabilities in code.
    
    Args:
        code: Source code to analyze
        language: Programming language
        vulnerability_type: Specific vulnerability type (SQL injection, XSS, etc.)
        
    Returns:
        Dictionary containing vulnerability findings
    """
    vuln_focus = vulnerability_type or "any security vulnerabilities"
    
    prompt = f"""Search the following {language} code for {vuln_focus}.

Code:
```{language}
{code}
```

For each vulnerability found, provide:
1. Vulnerability type and severity
2. Exact location (line numbers)
3. Vulnerable code snippet
4. How it can be exploited
5. Proof of concept (if applicable)
6. Remediation steps

Be thorough and precise."""

    findings = _make_codex_request(prompt, max_tokens=2500)
    
    return {
        "language": language,
        "vulnerability_type": vulnerability_type or "all",
        "findings": findings,
        "model": _get_codex_model(),
    }


def explain_code(
    code: str,
    language: str = "python",
    focus: str = "security implications"
) -> dict[str, Any]:
    """
    Get detailed explanation of code with security context.
    
    Args:
        code: Source code to explain
        language: Programming language
        focus: What to focus on (security implications, logic flow, etc.)
        
    Returns:
        Dictionary containing code explanation
    """
    prompt = f"""Explain the following {language} code with focus on {focus}.

Code:
```{language}
{code}
```

Provide:
1. High-level overview of what the code does
2. Step-by-step breakdown of the logic
3. Security implications and potential risks
4. Data flow and trust boundaries
5. Attack surface analysis

Be clear and detailed."""

    explanation = _make_codex_request(prompt, max_tokens=2000)
    
    return {
        "language": language,
        "focus": focus,
        "explanation": explanation,
        "model": _get_codex_model(),
    }


def suggest_fixes(
    code: str,
    vulnerability_description: str,
    language: str = "python"
) -> dict[str, Any]:
    """
    Generate secure code fixes for identified vulnerabilities.
    
    Args:
        code: Vulnerable code
        vulnerability_description: Description of the vulnerability
        language: Programming language
        
    Returns:
        Dictionary containing fix suggestions
    """
    prompt = f"""Given the following {language} code with a known vulnerability:

Vulnerability: {vulnerability_description}

Code:
```{language}
{code}
```

Provide:
1. Detailed explanation of why the code is vulnerable
2. Secure replacement code (complete, ready to use)
3. Explanation of how the fix addresses the vulnerability
4. Additional security best practices to apply
5. Test cases to verify the fix

Make the fixed code production-ready and follow security best practices."""

    fixes = _make_codex_request(prompt, max_tokens=3000)
    
    return {
        "language": language,
        "vulnerability": vulnerability_description,
        "fixes": fixes,
        "model": _get_codex_model(),
    }
