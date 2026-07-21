import React, { useEffect, useState } from "react";
import {
  FileText,
  Bug,
  Waypoints,
  History,
  Mail,
  ArrowUpRight,
  LogOut,
  ShieldCheck,
  PanelLeftClose,
  PanelLeft,
} from "lucide-react";
import { SIGNUP_URL, ctaUrl, trackCta } from "@/lib/cta";
import { ProNavItem } from "@/components/ProCta";
import { FEATURES, PLATFORM_ORDER } from "@/lib/pro-features";
import type { View } from "@/App";

/**
 * Persistent left rail. A single, ungrouped, ordered list of uniform two-line
 * rows (icon + label + short one-liner): the current run's views, the local
 * run-history + email-report actions, then the platform features. No section
 * headers. Tier is shown only by the inline Pro/Enterprise tag on platform
 * rows. Matches App.tsx's dark palette.
 *
 * Can collapse to a narrow icon-only rail; the collapsed state persists in
 * localStorage and each icon row keeps a `title` tooltip so the labels stay
 * discoverable.
 */

const COLLAPSE_KEY = "strix_viewer_sidebar_collapsed";

interface SidebarProps {
  view: View;
  onSelectView: (view: View) => void;
  activeFeature: string | null;
  onSelectFeature: (slug: string) => void;
  issuesCount: number;
  agentCount: number;
  runCount: number;
  finished: boolean;
  verified: boolean;
  email: string | null;
  onOpenEmail: () => void;
  onOpenHistory: () => void;
  onForget: () => void;
}

export default function Sidebar({
  view,
  onSelectView,
  activeFeature,
  onSelectFeature,
  issuesCount,
  agentCount,
  runCount,
  finished,
  verified,
  email,
  onOpenEmail,
  onOpenHistory,
  onForget,
}: SidebarProps) {
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    try {
      setCollapsed(localStorage.getItem(COLLAPSE_KEY) === "1");
    } catch {
      /* localStorage may be unavailable; default to expanded */
    }
  }, []);

  const toggleCollapsed = () => {
    setCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem(COLLAPSE_KEY, next ? "1" : "0");
      } catch {
        /* best-effort persistence */
      }
      return next;
    });
  };

  return (
    <aside
      className={`hidden flex-shrink-0 border-r border-[#222] lg:block ${collapsed ? "w-14" : "w-72"}`}
    >
      <div className="sticky top-0 flex h-screen flex-col overflow-y-auto px-3 py-4">
        {/* Header: wordmark + Explore full platform + signed-in chip */}
        <div className="px-1.5">
          <div className={`flex items-center ${collapsed ? "flex-col gap-2" : "justify-between"}`}>
            <a
              href={ctaUrl("https://app.strix.ai", "logo")}
              target="_blank"
              rel="noopener noreferrer"
              onClick={() => trackCta("logo", "sidebar")}
              className="flex items-center gap-1.5 opacity-90 transition-opacity hover:opacity-100"
              title="Open Strix Cloud"
            >
              <img src="./logo.png" alt="Strix" className="h-8 w-10 object-cover" />
              {!collapsed && (
                <span className="text-base font-medium tracking-tight text-white">Strix</span>
              )}
            </a>
            <button
              onClick={toggleCollapsed}
              title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
              aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
              className="flex-shrink-0 cursor-pointer rounded-md p-1.5 text-[#666] transition-colors hover:bg-[rgba(255,255,255,0.06)] hover:text-white"
            >
              {collapsed ? (
                <PanelLeft className="h-4 w-4" aria-hidden="true" />
              ) : (
                <PanelLeftClose className="h-4 w-4" aria-hidden="true" />
              )}
            </button>
          </div>
          <a
            href={ctaUrl(SIGNUP_URL, "sidebar_start_free")}
            target="_blank"
            rel="noopener noreferrer"
            onClick={() => trackCta("sidebar_start_free", "sidebar")}
            title="Explore full platform"
            className={`mt-3 flex w-full cursor-pointer items-center justify-center gap-1.5 rounded-lg bg-white font-semibold text-black transition-opacity hover:opacity-90 ${
              collapsed ? "px-0 py-2" : "px-3 py-2 text-sm"
            }`}
          >
            {!collapsed && "Explore full platform"}
            <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
          </a>
          {verified && email && (
            collapsed ? (
              <div
                className="mt-2.5 flex items-center justify-center rounded-lg py-2"
                style={{ border: "1px solid #222", background: "rgba(255,255,255,0.02)" }}
                title={`Linked email: ${email}`}
              >
                <ShieldCheck className="h-3.5 w-3.5 flex-shrink-0 text-emerald-400" aria-hidden="true" />
              </div>
            ) : (
              <div
                className="mt-2.5 flex items-center gap-2 rounded-lg px-2.5 py-2"
                style={{ border: "1px solid #222", background: "rgba(255,255,255,0.02)" }}
              >
                <ShieldCheck className="h-3.5 w-3.5 flex-shrink-0 text-emerald-400" aria-hidden="true" />
                <div className="min-w-0 flex-1">
                  <p className="truncate text-[11px] text-[#666]">Linked email</p>
                  <p className="truncate text-xs text-[#aaa]" title={email}>{email}</p>
                </div>
                <button
                  onClick={onForget}
                  title="Forget this email on this machine"
                  className="flex-shrink-0 cursor-pointer text-[#666] transition-colors hover:text-white"
                  aria-label="Forget"
                >
                  <LogOut className="h-3.5 w-3.5" />
                </button>
              </div>
            )
          )}
        </div>

        {/* One single ordered list, no section headers. */}
        <div className="mt-6 space-y-0.5">
          <NavItem
            icon={FileText}
            label="Overview"
            desc="This run's executive report"
            active={view === "overview"}
            onClick={() => onSelectView("overview")}
            collapsed={collapsed}
          />
          <NavItem
            icon={Bug}
            label="Issues"
            desc="Findings from this run"
            count={issuesCount > 0 ? issuesCount : undefined}
            active={view === "issues"}
            onClick={() => onSelectView("issues")}
            collapsed={collapsed}
          />
          {agentCount > 0 && (
            <NavItem
              icon={Waypoints}
              label="Agents"
              desc="What each agent did"
              count={agentCount}
              active={view === "agents"}
              onClick={() => onSelectView("agents")}
              collapsed={collapsed}
            />
          )}
          <NavItem
            icon={History}
            label="Past runs"
            desc="Every run on this machine"
            count={runCount > 0 ? runCount : undefined}
            active={view === "history"}
            onClick={onOpenHistory}
            collapsed={collapsed}
          />
          {/* Emailing a report only makes sense once the run is complete; a
              live scan would send a partial report, so hide it until finished. */}
          {finished && (
            <NavItem
              icon={Mail}
              label="Email report"
              desc="Get an encrypted PDF by email"
              active={view === "email"}
              onClick={onOpenEmail}
              collapsed={collapsed}
            />
          )}

          {PLATFORM_ORDER.map((slug) => {
            const feature = FEATURES[slug];
            if (!feature) return null;
            return (
              <ProNavItem
                key={slug}
                feature={feature}
                active={view === "feature" && activeFeature === slug}
                onClick={() => onSelectFeature(slug)}
                collapsed={collapsed}
              />
            );
          })}
        </div>
      </div>
    </aside>
  );
}

function NavItem({
  icon: Icon,
  label,
  desc,
  count,
  active,
  onClick,
  collapsed = false,
}: {
  icon: React.ElementType;
  label: string;
  desc: string;
  count?: number;
  active?: boolean;
  onClick: () => void;
  collapsed?: boolean;
}) {
  if (collapsed) {
    return (
      <button
        onClick={onClick}
        title={count != null ? `${label} (${count})` : label}
        className={`flex w-full cursor-pointer items-center justify-center rounded-md px-2.5 py-2 transition-colors ${
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
      className={`flex w-full cursor-pointer items-start gap-2.5 rounded-md px-2.5 py-1.5 text-left transition-colors ${
        active
          ? "text-white"
          : "text-[#888] hover:bg-[rgba(255,255,255,0.06)] hover:text-white"
      }`}
      style={active ? { background: "rgba(255,255,255,0.12)" } : undefined}
    >
      <Icon className="mt-0.5 h-4 w-4 flex-shrink-0" aria-hidden="true" />
      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-1.5">
          <span className="flex-1 truncate text-sm">{label}</span>
          {count != null && <span className="text-xs text-[#666] tabular-nums">{count}</span>}
        </span>
        <span className="mt-0.5 block text-[11px] leading-snug text-[#666]">{desc}</span>
      </span>
    </button>
  );
}
