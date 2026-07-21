import React, { useState } from "react";
import { ArrowUpRight } from "lucide-react";
import { SIGNUP_URL, ctaUrl, trackCta } from "@/lib/cta";
import type { ProFeature } from "@/lib/pro-features";

/**
 * Shared Pro CTA primitives. Every Pro item is a direct link-out to the cloud
 * sign-up in a new tab with a hover tooltip one-liner (no modal, no lock icon).
 * Built once here and reused by the sidebar Platform section, the top upsell
 * row, and the inline CTAs in the tabs.
 */

/** Small tier pill ("Pro" or "Enterprise"). Deliberately not a padlock. */
export function ProTag({ label = "Pro", className = "" }: { label?: string; className?: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-[#aaa] ${className}`}
      style={{ border: "1px solid #2a2a2a", background: "rgba(255,255,255,0.04)" }}
    >
      {label}
    </span>
  );
}

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

export interface ProItem {
  title: string;
  desc: string;
  slug: string;
  icon: React.ElementType;
}

/**
 * Card-style Pro feature tile: icon + name + one-liner + Pro tag + arrow.
 * Used in the top upsell row and inline CTA grids.
 */
export function ProTile({ item, surface }: { item: ProItem; surface?: string }) {
  const Icon = item.icon;
  return (
    <a
      href={ctaUrl(SIGNUP_URL, item.slug)}
      target="_blank"
      rel="noopener noreferrer"
      onClick={() => trackCta(item.slug, surface)}
      title={item.desc}
      className="group block cursor-pointer rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-4 text-left transition-colors hover:border-[#444]"
    >
      <div className="mb-2 flex items-center justify-between">
        <Icon className="h-4 w-4 text-[#888] transition-colors group-hover:text-white" aria-hidden="true" />
        <div className="flex items-center gap-1.5">
          <ProTag />
          <ArrowUpRight className="h-3.5 w-3.5 text-[#555] transition-colors group-hover:text-[#aaa]" aria-hidden="true" />
        </div>
      </div>
      <p className="text-sm font-medium text-white">{item.title}</p>
      <p className="mt-0.5 text-xs text-[#666]">{item.desc}</p>
    </a>
  );
}

/**
 * Sidebar-row Pro item: a two-line row (icon + label + short one-liner
 * underneath) with a small right-aligned tier tag. Opens the in-app
 * FeatureDetail view via onClick (no link-out) so it sits uniformly beside the
 * run/local rows in the themed nav list.
 */
export function ProNavItem({
  feature,
  active,
  onClick,
  collapsed = false,
}: {
  feature: ProFeature;
  active?: boolean;
  onClick: () => void;
  collapsed?: boolean;
}) {
  const Icon = feature.icon;
  if (collapsed) {
    return (
      <button
        onClick={onClick}
        title={`${feature.title} (${feature.tier})`}
        className={`group flex w-full cursor-pointer items-center justify-center rounded-md px-2.5 py-2 transition-colors ${
          active
            ? "text-white"
            : "text-[#888] hover:bg-[rgba(255,255,255,0.06)] hover:text-white"
        }`}
        style={active ? { background: "rgba(255,255,255,0.12)" } : undefined}
      >
        <Icon className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
      </button>
    );
  }
  return (
    <button
      onClick={onClick}
      className={`group flex w-full cursor-pointer items-start gap-2.5 rounded-md px-2.5 py-1.5 text-left transition-colors ${
        active
          ? "text-white"
          : "text-[#888] hover:bg-[rgba(255,255,255,0.06)] hover:text-white"
      }`}
      style={active ? { background: "rgba(255,255,255,0.12)" } : undefined}
    >
      <Icon className="mt-0.5 h-4 w-4 flex-shrink-0" aria-hidden="true" />
      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-1.5">
          <span className="flex-1 truncate text-sm">{feature.title}</span>
          <ProTag label={feature.tier} />
        </span>
        <span className="mt-0.5 block text-[11px] leading-snug text-[#666]">{feature.navDesc}</span>
      </span>
    </button>
  );
}

/**
 * Inline Pro CTA button (compact). Used in the finding detail and per-surface
 * rows where a full card is too heavy.
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
        <ProTag className="ml-0.5" />
      </a>
    </Tooltip>
  );
}
