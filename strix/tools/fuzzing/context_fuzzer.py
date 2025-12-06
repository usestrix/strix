from typing import List, Optional
import re
import os
import subprocess
import tempfile
from bs4 import BeautifulSoup
from strix.tools.registry import register_tool

class ContextFuzzer:
    """
    Context-Aware Smart Fuzzer.

    Generates custom wordlists based on target HTML, JS variables, and comments.
    """

    def generate_wordlist(self, html_content: str, js_content: List[str]) -> List[str]:
        words = set()

        # 1. Scrape HTML IDs and Classes
        soup = BeautifulSoup(html_content, 'html.parser')
        for element in soup.find_all(True):
            if element.get('id'):
                words.add(element['id'])
            if element.get('class'):
                if isinstance(element['class'], list):
                    words.update(element['class'])
                else:
                    words.add(element['class'])
            if element.get('name'):
                words.add(element['name'])

        # 2. Extract JS Variables
        # Simple regex for variable declarations. A full parser would be better.
        var_pattern = re.compile(r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)')
        for js in js_content:
            matches = var_pattern.findall(js)
            words.update(matches)

        # 3. Generate Mutations
        mutated_words = set()
        for word in words:
            mutated_words.add(word)
            # Example: user_v1 -> admin_v1, super_user_v1
            if "user" in word.lower():
                mutated_words.add(word.lower().replace("user", "admin"))
                mutated_words.add(word.lower().replace("user", "superuser"))

            # Common suffixes/prefixes
            mutated_words.add(f"{word}_test")
            mutated_words.add(f"{word}_dev")
            mutated_words.add(f"{word}_api")

        return sorted(list(mutated_words))

context_fuzzer = ContextFuzzer()

@register_tool
def generate_context_wordlist(html_content: str, js_content: List[str]) -> str:
    """
    Generates a custom wordlist based on the target's HTML and JS content.

    Args:
        html_content: The HTML source of the page.
        js_content: A list of JavaScript source strings.

    Returns:
        A newline-separated string of words.
    """
    words = context_fuzzer.generate_wordlist(html_content, js_content)
    return "\n".join(words)

@register_tool
def fuzz_with_context(target_url: str, wordlist_content: str) -> str:
    """
    Executes ffuf using the provided wordlist content against the target URL.

    Args:
        target_url: The URL to fuzz (must contain FUZZ keyword).
        wordlist_content: The content of the wordlist to use (newline separated).

    Returns:
        The output from ffuf.
    """
    if "FUZZ" not in target_url:
        return "Error: target_url must contain 'FUZZ' keyword."

    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_wordlist:
        temp_wordlist.write(wordlist_content)
        temp_wordlist_path = temp_wordlist.name

    try:
        # Run ffuf
        # -u: Target URL
        # -w: Wordlist
        # -mc: Match codes (default 200,204,301,302,307,401,403) - we'll stick to defaults or 200,301,302
        # -o: Output file (we'll read stdout/json)
        # -json: Output JSON

        cmd = [
            "ffuf",
            "-u", target_url,
            "-w", temp_wordlist_path,
            "-json",
            "-mc", "200,204,301,302,403" # 403 to detect WAF blocks
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120) # 2 min timeout

        if result.returncode != 0 and not result.stdout:
            return f"ffuf failed: {result.stderr}"

        return result.stdout

    except Exception as e:
        return f"Error running ffuf: {e}"
    finally:
        if os.path.exists(temp_wordlist_path):
            os.unlink(temp_wordlist_path)
