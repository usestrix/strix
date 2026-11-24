// Spaces requests to each configured domain (and its subdomains) so that at
// most N per second go upstream. A key with a path ("api.example.com/v1")
// limits that exact host's path and every path below it, and replaces the
// domain's limit there: a request waits only for the longest endpoint path it
// is under, and the domain's limit covers the paths with no endpoint limit. A
// request over the rate waits for its slot; it is never dropped. Hosts outside
// the configured domains pass through.
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
  const endpointHosts = new Set([...limits.values()].filter((limit) => limit.path).map((limit) => limit.host));
  const intervals = Object.fromEntries([...limits].map(([key, limit]) => [key, limit.interval]));
  sdk.console.log(`Rate limits: ${JSON.stringify(intervals)} (ms between requests)`);

  const sleepUntil = (time) => {
    const delay = time - Date.now();
    return delay > 0 ? new Promise((resolve) => setTimeout(resolve, delay)) : undefined;
  };

  // Domains reserve the next free slot, so one queue cannot hold back another.
  async function takeDomain(key) {
    const now = Date.now();
    const slot = Math.max(now, nextSlot.get(key) ?? 0);
    nextSlot.set(key, slot + limits.get(key).interval);
    await sleepUntil(slot);
  }

  // Endpoints send one request at a time, spaced from when the previous one left.
  const lastSent = new Map();
  const chains = new Map();
  function takeEndpoint(key) {
    const run = (chains.get(key) ?? Promise.resolve()).then(async () => {
      await sleepUntil((lastSent.get(key) ?? 0) + limits.get(key).interval);
      lastSent.set(key, Date.now());
    });
    chains.set(key, run.catch(() => undefined));
    return run;
  }

  sdk.events.onUpstream(async (_sdk, request) => {
    const host = request.getHost().toLowerCase();
    // The upstream request is raw, so the path comes from its parsed spec,
    // only for hosts with endpoint limits.
    const endpoint = endpointHosts.has(host) ? matchEndpoint(limits, host, request.getSpec().getPath()) : null;
    if (endpoint !== null) {
      await takeEndpoint(endpoint);
    } else {
      const domain = matchDomain(limits, host);
      if (domain !== null) await takeDomain(domain);
    }
    return undefined;
  });
}
