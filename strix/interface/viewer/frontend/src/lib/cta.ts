// All upsell / sign-up CTAs route anonymous local-viewer users to the public
// cloud sign-up. Open in a new tab so the local results stay put.
export const SIGNUP_URL = "https://app.strix.ai/api/auth/signup";
export const DEMO_URL = "https://strix.ai/demo";
export const PRICING_URL = "https://strix.ai/pricing";

// Attribution params appended to every outbound CTA link so the destination
// analytics can see the local viewer drove the click, with utm_content carrying
// the CTA slug so we know which one.
const CTA_PARAMS =
  "ref=oss_viewer&utm_source=oss_viewer&utm_medium=local_viewer&utm_campaign=oss_viewer";

export function ctaUrl(base: string, slug: string): string {
  const sep = base.includes("?") ? "&" : "?";
  return `${base}${sep}${CTA_PARAMS}&utm_content=${encodeURIComponent(slug)}`;
}

// Best-effort, anonymous beacon. The local server forwards this to PostHog only
// if the user has telemetry enabled; it never blocks navigation. Undefined
// props are dropped so we only send what is set. NEVER pass PII here (no email,
// code, or report content) - the props are limited to anonymous metadata.
export function track(event: string, props: Record<string, string | undefined> = {}): void {
  try {
    const body: Record<string, string> = { event };
    for (const [key, value] of Object.entries(props)) {
      if (value !== undefined) body[key] = value;
    }
    const payload = JSON.stringify(body);
    if (typeof navigator !== "undefined" && navigator.sendBeacon) {
      navigator.sendBeacon("/api/event", payload);
    } else {
      void fetch("/api/event", { method: "POST", body: payload, keepalive: true });
    }
  } catch {
    /* analytics is best-effort */
  }
}

// Anonymous conversion tracking for a sign-up/upsell click. `surface` records
// where the click happened so one CTA slug can be reused across placements.
export function trackCta(cta: string, surface?: string): void {
  track("cta_clicked", { cta, surface });
}
