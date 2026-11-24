// Spaces requests to each configured domain (and its subdomains) so that at
// most N per second go upstream. A key with a path ("api.example.com/v1")
// limits that host's path and every path below it; such a request waits for
// its endpoint slot and then for its domain slot. A request over the rate waits
// for its slot; it is never dropped. Hosts outside the configured domains pass
// through.
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
  for (const [key, rate] of Object.entries(raw ?? {})) {
    const text = String(key).trim();
    const slash = text.indexOf("/");
    const host = (slash === -1 ? text : text.slice(0, slash))
      .toLowerCase()
      .replace(/^\*\./, "")
      .replace(/\.$/, "");
    const path = slash === -1 ? "" : text.slice(slash).replace(/\/+$/, "");
    const perSecond = Number(rate);
    if (host && Number.isFinite(perSecond) && perSecond > 0) {
      limits.set(host + path, { host, path, interval: 1000 / perSecond });
    }
  }
  return limits;
}

function matchDomain(limits, host) {
  let best = null;
  for (const [key, limit] of limits) {
    if (limit.path) continue;
    if ((host === limit.host || host.endsWith(`.${limit.host}`)) && (!best || key.length > best.length)) {
      best = key;
    }
  }
  return best;
}

function matchEndpoint(limits, host, path) {
  let best = null;
  for (const [key, limit] of limits) {
    if (!limit.path || host !== limit.host) continue;
    if ((path === limit.path || path.startsWith(`${limit.path}/`)) && (!best || key.length > best.length)) {
      best = key;
    }
  }
  return best;
}

export function init(sdk) {
  const limits = loadLimits(sdk);
  const nextSlot = new Map();
  const intervals = Object.fromEntries([...limits].map(([key, limit]) => [key, limit.interval]));
  sdk.console.log(`Rate limits: ${JSON.stringify(intervals)} (ms between requests)`);

  // Reserves the next free slot for a key and waits for it.
  async function take(key) {
    const now = Date.now();
    const slot = Math.max(now, nextSlot.get(key) ?? 0);
    nextSlot.set(key, slot + limits.get(key).interval);
    if (slot > now) await new Promise((resolve) => setTimeout(resolve, slot - now));
  }

  sdk.events.onUpstream(async (_sdk, request) => {
    const host = request.getHost().toLowerCase();
    // The endpoint slot comes first, so a queue on one endpoint does not hold
    // the domain's slots for the rest of its traffic.
    const endpoint = matchEndpoint(limits, host, request.getPath());
    if (endpoint !== null) await take(endpoint);
    const domain = matchDomain(limits, host);
    if (domain !== null) await take(domain);
    return undefined;
  });
}
