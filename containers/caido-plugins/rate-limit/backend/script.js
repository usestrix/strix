// Spaces requests to each configured domain (and its subdomains) so that at
// most N per second go upstream. A request over the rate waits for its slot;
// it is never dropped. Hosts outside the configured domains pass through.
//
// The plugin runtime has no process environment, so the sandbox entrypoint
// writes the STRIX_RATE_LIMITS map ({"example.com": 5}) to LIMITS_FILE before
// installing the plugin.
import { readFileSync } from "fs";

const LIMITS_FILE = "/tmp/strix-rate-limits.json";

function loadLimits(sdk) {
  const limits = new Map();
  let raw;
  try {
    raw = JSON.parse(readFileSync(LIMITS_FILE, "utf8"));
  } catch (error) {
    sdk.console.error(`Could not read ${LIMITS_FILE}: ${error}`);
    return limits;
  }
  for (const [domain, rate] of Object.entries(raw ?? {})) {
    const host = String(domain).trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
    const perSecond = Number(rate);
    if (host && Number.isFinite(perSecond) && perSecond > 0) {
      limits.set(host, 1000 / perSecond);
    }
  }
  return limits;
}

function matchDomain(limits, host) {
  let best = null;
  for (const domain of limits.keys()) {
    if ((host === domain || host.endsWith(`.${domain}`)) && (!best || domain.length > best.length)) {
      best = domain;
    }
  }
  return best;
}

export function init(sdk) {
  const limits = loadLimits(sdk);
  const nextSlot = new Map();
  sdk.console.log(`Rate limits: ${JSON.stringify(Object.fromEntries(limits))} (ms between requests)`);

  sdk.events.onUpstream(async (_sdk, request) => {
    const domain = matchDomain(limits, request.getHost().toLowerCase());
    if (domain === null) return undefined;
    const now = Date.now();
    const slot = Math.max(now, nextSlot.get(domain) ?? 0);
    nextSlot.set(domain, slot + limits.get(domain));
    if (slot > now) await new Promise((resolve) => setTimeout(resolve, slot - now));
    return undefined;
  });
}
