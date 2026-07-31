import React, { useState } from "react";
import { SIGNUP_URL, ctaUrl, trackCta } from "@/lib/cta";

/**
 * Lightweight hover tooltip. Wraps a trigger and reveals `text` above it on
 * hover/focus. Plain Tailwind + local state (no radix vendored).
 */
export function Tooltip({
  text,
  children,
  className = "",
}: {
  text: string;
  children: React.ReactNode;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <span
      className={`relative inline-flex ${className}`}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      {children}
      {open && (
        <span
          role="tooltip"
          className="pointer-events-none absolute bottom-full left-1/2 z-50 mb-2 w-max max-w-[240px] -translate-x-1/2 rounded-md px-2.5 py-1.5 text-xs text-[#ddd] shadow-lg"
          style={{ border: "1px solid #2a2a2a", background: "#0a0a0a" }}
        >
          {text}
        </span>
      )}
    </span>
  );
}

/**
 * Compact inline CTA button that links out to sign-up in a new tab, with a
 * hover tooltip one-liner. Used in per-surface rows where a full card is too
 * heavy.
 */
export function ProInlineCta({
  label,
  desc,
  slug,
  icon: Icon,
  surface,
}: {
  label: string;
  desc: string;
  slug: string;
  icon: React.ElementType;
  surface?: string;
}) {
  return (
    <Tooltip text={desc}>
      <a
        href={ctaUrl(SIGNUP_URL, slug)}
        target="_blank"
        rel="noopener noreferrer"
        onClick={() => trackCta(slug, surface)}
        className="group inline-flex items-center gap-2 rounded-lg border border-[#222] bg-[rgba(255,255,255,0.02)] px-3 py-2 text-sm text-[#aaa] transition-colors hover:border-[#444] hover:text-white"
      >
        <Icon className="h-4 w-4 text-[#888] transition-colors group-hover:text-white" aria-hidden="true" />
        <span>{label}</span>
      </a>
    </Tooltip>
  );
}
