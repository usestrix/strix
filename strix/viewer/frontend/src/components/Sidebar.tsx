import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  Bot,
  Users,
  History,
  Mail,
  LogOut,
  ChevronsUpDown,
} from "lucide-react";
import { LuGitPullRequestArrow } from "react-icons/lu";
import { VscExtensions } from "react-icons/vsc";
import { IoChatbubblesOutline } from "react-icons/io5";
import { cn } from "@/lib/utils";
import { ctaUrl, trackCta } from "@/lib/cta";
import { UpgradeModal } from "@/components/UpgradeModal";
import type { View } from "@/App";

/**
 * Persistent left rail: a black rail with a right hairline border, an
 * account-switcher-style header, a single ungrouped list of h-9 nav rows (36px
 * icon slot, 14px label, rgba(255,255,255,0.12) active fill), a hairline
 * separator, and a user footer. Drag the right edge to resize; drag past the
 * collapse threshold to hide it, then click the left pull-zone to bring it back.
 */

const MIN_WIDTH = 160;
const DEFAULT_WIDTH = 260;
const MAX_WIDTH = 400;
const COLLAPSE_THRESHOLD = 140;

const WIDTH_KEY = "strix_viewer_sidebar_width";
const COLLAPSE_KEY = "strix_viewer_sidebar_collapsed";

interface SidebarProps {
  view: View;
  onSelectView: (view: View) => void;
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

function readInt(key: string, fallback: number): number {
  try {
    const raw = localStorage.getItem(key);
    const n = raw ? parseInt(raw, 10) : NaN;
    return Number.isFinite(n) ? n : fallback;
  } catch {
    return fallback;
  }
}

export default function Sidebar({
  view,
  onSelectView,
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
  const [width, setWidth] = useState(() => {
    const w = readInt(WIDTH_KEY, DEFAULT_WIDTH);
    return Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, w));
  });
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem(COLLAPSE_KEY) === "1";
    } catch {
      return false;
    }
  });
  const [isResizing, setIsResizing] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [upgradeFeature, setUpgradeFeature] = useState<string | null>(null);
  const userMenuRef = useRef<HTMLDivElement>(null);

  const persistWidth = useCallback((w: number) => {
    setWidth(w);
    try {
      localStorage.setItem(WIDTH_KEY, String(w));
    } catch {
      /* best-effort persistence */
    }
  }, []);

  const persistCollapsed = useCallback((c: boolean) => {
    setCollapsed(c);
    try {
      localStorage.setItem(COLLAPSE_KEY, c ? "1" : "0");
    } catch {
      /* best-effort persistence */
    }
  }, []);

  const expandSidebar = useCallback(() => {
    persistCollapsed(false);
    persistWidth(DEFAULT_WIDTH);
  }, [persistCollapsed, persistWidth]);

  const handleResizeStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsResizing(true);
  }, []);

  // Global drag handlers for the resize handle. Dragging below the collapse
  // threshold hides the rail entirely.
  useEffect(() => {
    if (!isResizing || collapsed) return;

    const handleMouseMove = (e: MouseEvent) => {
      const newWidth = e.clientX;
      if (newWidth >= MIN_WIDTH && newWidth <= MAX_WIDTH) {
        setWidth(newWidth);
      } else if (newWidth > MAX_WIDTH) {
        setWidth(MAX_WIDTH);
      }
    };
    const handleMouseUp = (e: MouseEvent) => {
      const finalWidth = e.clientX;
      if (finalWidth < COLLAPSE_THRESHOLD) {
        persistCollapsed(true);
        persistWidth(DEFAULT_WIDTH);
      } else {
        persistWidth(Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, finalWidth)));
      }
      setIsResizing(false);
    };

    window.addEventListener("mousemove", handleMouseMove);
    window.addEventListener("mouseup", handleMouseUp);
    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseup", handleMouseUp);
    };
  }, [isResizing, collapsed, persistCollapsed, persistWidth]);

  // Close the user menu when clicking outside it.
  useEffect(() => {
    if (!showUserMenu) return;
    const onDown = (e: MouseEvent) => {
      if (userMenuRef.current && !userMenuRef.current.contains(e.target as Node)) {
        setShowUserMenu(false);
      }
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [showUserMenu]);

  return (
    <>
      {/* Left-edge pull zone: click to bring the rail back when collapsed. */}
      {collapsed && (
        <div
          className="fixed left-0 top-0 z-40 hidden h-full w-4 cursor-pointer transition-colors hover:bg-[rgba(255,255,255,0.08)] lg:block"
          onClick={expandSidebar}
          title="Expand sidebar"
        />
      )}

      <aside
        className={cn(
          "sticky top-0 z-20 hidden h-screen flex-shrink-0 flex-col overflow-hidden border-r border-[rgba(255,255,255,0.08)] bg-black lg:flex",
          !isResizing && "transition-[width] duration-200 ease-out"
        )}
        style={{ width: collapsed ? 0 : width }}
      >
        {/* Header — account-switcher stand-in (links out to Strix Cloud). */}
        <header className="relative flex flex-col gap-1 pt-1 min-w-[160px]">
          <div className="flex flex-row py-1 px-2">
            <div className="flex h-10 w-full flex-row items-center">
              <a
                href={ctaUrl("https://app.strix.ai", "logo")}
                target="_blank"
                rel="noopener noreferrer"
                onClick={() => trackCta("logo", "sidebar")}
                className="flex flex-1 flex-row items-center gap-2 rounded-md py-2 pl-2.5 pr-1 min-w-0 transition-colors hover:bg-[rgba(255,255,255,0.06)]"
                title="Open Strix Cloud"
              >
                <span
                  className="flex flex-shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-emerald-400 to-cyan-500"
                  style={{ width: 20, height: 20 }}
                >
                  <span className="text-[10px] font-semibold text-white">S</span>
                </span>
                <span className="flex flex-1 flex-row items-center gap-2 min-w-0">
                  <span className="truncate min-w-0 text-[14px] font-medium text-[#ededed]">Strix</span>
                  <span className="flex h-5 flex-shrink-0 items-center rounded px-2 text-[11px] font-medium text-[#888] bg-[rgba(255,255,255,0.08)]">
                    Local
                  </span>
                </span>
              </a>
              <a
                href={ctaUrl("https://app.strix.ai", "logo")}
                target="_blank"
                rel="noopener noreferrer"
                onClick={() => trackCta("logo", "sidebar")}
                className="flex flex-none items-center rounded-md px-1.5 py-2 transition-colors hover:bg-[rgba(255,255,255,0.06)]"
                aria-label="Open Strix Cloud"
              >
                <ChevronsUpDown className="h-4 w-4 text-[#666]" />
              </a>
            </div>
          </div>
        </header>

        {/* Navigation */}
        <nav className="relative min-w-[160px] flex-1 overflow-y-auto overflow-x-clip scrollbar-thin pb-10 pt-2">
          <div className="relative flex flex-col gap-px px-2">
            <NavItem
              icon={<ProjectsIcon />}
              label="Overview"
              active={view === "overview"}
              onClick={() => onSelectView("overview")}
            />
            <NavItem
              icon={<AlertTriangle className="h-4 w-4" />}
              label="Issues"
              count={issuesCount > 0 ? issuesCount : undefined}
              active={view === "issues"}
              onClick={() => onSelectView("issues")}
            />
            {agentCount > 0 && (
              <NavItem
                icon={<Bot className="h-4 w-4" />}
                label="Agents"
                count={agentCount}
                active={view === "agents"}
                onClick={() => onSelectView("agents")}
              />
            )}
            <NavItem
              icon={<History className="h-4 w-4" />}
              label="Past runs"
              count={runCount > 0 ? runCount : undefined}
              active={view === "history"}
              onClick={onOpenHistory}
            />
            {finished && (
              <NavItem
                icon={<Mail className="h-4 w-4" />}
                label="Export report"
                active={view === "email"}
                onClick={onOpenEmail}
              />
            )}
            <NavItem
              icon={<IoChatbubblesOutline className="h-4 w-4" />}
              label="Feedback & support"
              active={view === "feedback"}
              onClick={() => onSelectView("feedback")}
            />

            <hr className="mx-0 my-1 h-px w-full border-0 bg-[rgba(255,255,255,0.08)]" />

            <NavItem
              icon={<LuGitPullRequestArrow className="h-4 w-4" />}
              label="PR Security Reviews"
              active={false}
              onClick={() =>
                setUpgradeFeature(
                  "Strix reviews every pull request and flags exploitable changes before they merge."
                )
              }
            />
            <NavItem
              icon={<VscExtensions className="h-4 w-4" />}
              label="Integrations"
              active={false}
              onClick={() =>
                setUpgradeFeature(
                  "Sync findings to Jira, Linear, and Slack so fixes happen where your team already works."
                )
              }
            />
            <NavItem
              icon={<Users className="h-4 w-4" />}
              label="Members"
              active={false}
              onClick={() =>
                setUpgradeFeature(
                  "Invite your team, set roles, and share findings and run history across your org."
                )
              }
            />
          </div>
        </nav>

        {/* User footer — verified-email footer. */}
        <section className="flex min-w-[160px] flex-col gap-0.5" ref={userMenuRef}>
          <div className="relative p-2">
            {verified && email ? (
              <button
                onClick={() => setShowUserMenu((v) => !v)}
                className="relative flex w-full cursor-pointer items-center gap-2 rounded-md bg-transparent px-2.5 py-2 transition-colors hover:bg-[rgba(255,255,255,0.06)]"
              >
                <span
                  className="flex flex-shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-emerald-400 to-cyan-500"
                  style={{ width: 20, height: 20 }}
                >
                  <span className="text-[9px] font-semibold text-white">
                    {email[0]?.toUpperCase() || "U"}
                  </span>
                </span>
                <span className="flex min-w-0 flex-1 flex-col text-left">
                  <span className="truncate text-[13px] font-medium text-[#ededed]">{email}</span>
                  <span className="truncate text-[11px] text-[#555]">Linked to this machine</span>
                </span>
              </button>
            ) : (
              <div className="flex items-center gap-2 rounded-md px-2.5 py-2">
                <span
                  className="flex flex-shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-emerald-400 to-cyan-500"
                  style={{ width: 20, height: 20 }}
                >
                  <span className="text-[9px] font-semibold text-white">S</span>
                </span>
                <span className="flex min-w-0 flex-1 flex-col text-left">
                  <span className="truncate text-[13px] font-medium text-[#ededed]">Local viewer</span>
                </span>
              </div>
            )}

            {showUserMenu && verified && email && (
              <div className="absolute bottom-full left-2 right-2 z-50 mb-1 overflow-hidden rounded-lg border border-[#333] bg-black shadow-xl">
                <div className="border-b border-[#333] px-3 py-2">
                  <p className="truncate text-[13px] font-medium text-white">Linked email</p>
                  <p className="truncate text-[11px] text-[#666]">{email}</p>
                </div>
                <button
                  onClick={() => {
                    setShowUserMenu(false);
                    onForget();
                  }}
                  className="flex w-full items-center gap-2 px-3 py-2 text-[13px] text-[#888] transition-colors hover:bg-[rgba(255,255,255,0.06)] hover:text-red-400"
                >
                  <LogOut className="h-4 w-4" />
                  Forget this email
                </button>
              </div>
            )}
          </div>
        </section>

        {/* Resize handle */}
        <div
          className="group absolute right-0 top-0 z-30 h-full w-1 cursor-col-resize"
          onMouseDown={handleResizeStart}
        >
          <div
            className={cn(
              "absolute right-0 top-0 h-full w-px bg-[rgba(255,255,255,0.08)] transition-all duration-100",
              isResizing ? "w-0.5 bg-[rgba(255,255,255,0.3)]" : "group-hover:bg-[rgba(255,255,255,0.2)]"
            )}
          />
        </div>
      </aside>

      {/* Overlay during resize to prevent text selection. */}
      {isResizing && <div className="fixed inset-0 z-10 cursor-col-resize" />}

      <UpgradeModal
        open={upgradeFeature !== null}
        description={upgradeFeature ?? ""}
        source="sidebar"
        onClose={() => setUpgradeFeature(null)}
      />
    </>
  );
}

interface NavItemProps {
  icon: React.ReactNode;
  label: string;
  active: boolean;
  onClick: () => void;
  count?: number;
}

function NavItem({ icon, label, active, onClick, count }: NavItemProps) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "group flex h-9 w-full origin-left flex-row items-center rounded-md transition-colors",
        active
          ? "bg-[rgba(255,255,255,0.12)] text-white"
          : "text-[#888] hover:bg-[rgba(255,255,255,0.06)] hover:text-[#ededed]"
      )}
    >
      <div className="grid flex-none place-content-center" style={{ width: 36, height: 36 }}>
        {icon}
      </div>
      <span className="min-w-0 flex-1 truncate text-left text-[14px] font-medium">{label}</span>
      {count != null && (
        <span className="mr-2 flex-none rounded-full border border-white/10 px-2 py-0.5 text-[10px] tabular-nums leading-none text-[#777]">
          {count}
        </span>
      )}
    </button>
  );
}

// Overview icon: a dashboard grid glyph (16x16 viewBox).
function ProjectsIcon() {
  return (
    <svg style={{ width: 16, height: 16, color: "currentcolor" }} viewBox="0 0 16 16" fill="currentColor">
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d="M2.5 5.5V2.5H5.5V5.5H2.5ZM1 2C1 1.44772 1.44772 1 2 1H6C6.55228 1 7 1.44772 7 2V6C7 6.55228 6.55228 7 6 7H2C1.44772 7 1 6.55228 1 6V2ZM2.5 13.5V10.5H5.5V13.5H2.5ZM1 10C1 9.44772 1.44772 9 2 9H6C6.55228 9 7 9.44772 7 10V14C7 14.5523 6.55228 15 6 15H2C1.44772 15 1 14.5523 1 14V10ZM10.5 2.5V5.5H13.5V2.5H10.5ZM10 1C9.44772 1 9 1.44772 9 2V6C9 6.55228 9.44772 7 10 7H14C14.5523 7 15 6.55228 15 6V2C15 1.44772 14.5523 1 14 1H10ZM10.5 13.5V10.5H13.5V13.5H10.5ZM9 10C9 9.44772 9.44772 9 10 9H14C14.5523 9 15 9.44772 15 10V14C15 14.5523 14.5523 15 14 15H10C9.44772 15 9 14.5523 9 14V10Z"
      />
    </svg>
  );
}
