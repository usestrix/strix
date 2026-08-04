import hljs from "highlight.js/lib/common";
import http from "highlight.js/lib/languages/http";
import nginx from "highlight.js/lib/languages/nginx";
import apache from "highlight.js/lib/languages/apache";
import dockerfile from "highlight.js/lib/languages/dockerfile";
import properties from "highlight.js/lib/languages/properties";

hljs.registerLanguage("http", http);
hljs.registerLanguage("nginx", nginx);
hljs.registerLanguage("apache", apache);
hljs.registerLanguage("dockerfile", dockerfile);
hljs.registerLanguage("properties", properties);

/**
 * Highlight code, preferring an explicit language when it's recognized,
 * otherwise auto-detecting. Falls back to Python when auto-detection is
 * inconclusive, since legacy (unfenced) PoC scripts are Python.
 */
export function highlightCode(code: string, language?: string | null): string {
  try {
    if (language && hljs.getLanguage(language)) {
      return hljs.highlight(code, { language, ignoreIllegals: true }).value;
    }
    const auto = hljs.highlightAuto(code);
    if (auto.language) return auto.value;
    return hljs.highlight(code, { language: "python", ignoreIllegals: true }).value;
  } catch {
    return hljs.highlight(code, { language: "python", ignoreIllegals: true }).value;
  }
}

export default hljs;
