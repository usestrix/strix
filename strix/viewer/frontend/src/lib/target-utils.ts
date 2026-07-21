export interface ParsedTarget {
  display: string;
  href: string | null;
  provider: "github" | "gitlab" | "bitbucket" | null;
}

export function parseTarget(target: string): ParsedTarget {
  // GitHub URL
  const ghMatch = target.match(
    /(?:https?:\/\/)?(?:www\.)?github\.com\/([^\s/]+\/[^\s/]+)/
  );
  if (ghMatch) {
    const slug = ghMatch[1].replace(/\.git$/, "");
    return { display: slug, href: `https://github.com/${slug}`, provider: "github" };
  }

  // GitLab URL
  const glMatch = target.match(
    /(?:https?:\/\/)?(?:www\.)?gitlab\.com\/([^\s/]+\/[^\s/]+)/
  );
  if (glMatch) {
    const slug = glMatch[1].replace(/\.git$/, "");
    return { display: slug, href: `https://gitlab.com/${slug}`, provider: "gitlab" };
  }

  // Bitbucket URL
  const bbMatch = target.match(
    /(?:https?:\/\/)?(?:www\.)?bitbucket\.org\/([^\s/]+\/[^\s/]+)/
  );
  if (bbMatch) {
    const slug = bbMatch[1].replace(/\.git$/, "");
    return { display: slug, href: `https://bitbucket.org/${slug}`, provider: "bitbucket" };
  }

  // URL with protocol
  if (/^https?:\/\//i.test(target)) {
    return {
      display: target.replace(/^https?:\/\/(www\.)?/, ""),
      href: target,
      provider: null,
    };
  }

  // Bare domain (e.g. "example.com" or "example.com/path")
  if (/^[a-zA-Z0-9][\w.-]*\.[a-zA-Z]{2,}/.test(target)) {
    return { display: target, href: `https://${target}`, provider: null };
  }

  // Not a URL
  return { display: target, href: null, provider: null };
}

/**
 * A clean, human-readable run title derived from the scan target (e.g.
 * "arch.co") rather than the raw run dir name ("arch-co_ca3f"). Falls back to
 * the raw name, then a generic label.
 */
export function runTitle(target: string | null, fallback: string): string {
  if (target) return parseTarget(target).display.replace(/\/$/, "");
  return fallback || "Untitled scan";
}
