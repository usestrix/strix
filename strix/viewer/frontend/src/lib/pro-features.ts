import type React from "react";
import {
  GitPullRequest,
  Layers,
  Globe,
  Puzzle,
  Users,
  Search,
  LayoutDashboard,
  AlertTriangle,
  MessageSquare,
  Network,
  Database,
} from "lucide-react";

/**
 * Platform (Pro / Enterprise) feature catalog. Powers both the unified sidebar
 * nav rows and the in-app FeatureDetail upsell view. Everything is "Pro" except
 * Networks, which is "Enterprise". No lock icons anywhere.
 */

export type FeatureTier = "Pro" | "Enterprise";

export interface ProFeature {
  slug: string;
  title: string;
  icon: React.ElementType;
  tier: FeatureTier;
  /** Short one-liner for the sidebar nav row (two-line layout). */
  navDesc: string;
  /** Headline shown on the FeatureDetail upsell page. */
  headline: string;
  /** Longer sentence shown on the FeatureDetail upsell page. */
  description: string;
}

// Flat catalog of every platform feature, keyed by slug for routing. The
// sidebar groups these into capability themes (see PLATFORM_THEMES); nothing
// here implies a tier ordering.
export const PLATFORM_FEATURES: ProFeature[] = [
  {
    slug: "pr_reviews",
    title: "PR Reviews",
    icon: GitPullRequest,
    tier: "Pro",
    navDesc: "Pentest every pull request",
    headline: "Pentest every pull request",
    description:
      "Strix reviews every pull request your team opens and catches exploitable changes before they merge.",
  },
  {
    slug: "repositories",
    title: "Repositories",
    icon: Layers,
    tier: "Pro",
    navDesc: "Connect your team's repos",
    headline: "Connect your team's repositories",
    description:
      "Link your org's repositories so Strix can scan them continuously and track findings over time.",
  },
  {
    slug: "domains",
    title: "Domains",
    icon: Globe,
    tier: "Pro",
    navDesc: "Cover the domains you own",
    headline: "Cover every domain you own",
    description:
      "Add the domains your team owns and let Strix watch them for newly exposed paths and drift.",
  },
  {
    slug: "integrations",
    title: "Integrations",
    icon: Puzzle,
    tier: "Pro",
    navDesc: "Sync to Jira, Linear, Slack",
    headline: "Sync findings to your tools",
    description:
      "Two-way sync findings to Jira, Linear, and Slack so fixes happen where your team already works.",
  },
  {
    slug: "members",
    title: "Members",
    icon: Users,
    tier: "Pro",
    navDesc: "Invite your team, set roles",
    headline: "Bring your whole team",
    description:
      "Invite your team, set roles, and share findings and run history across your org.",
  },
  {
    slug: "pentests",
    title: "Pentests",
    icon: Search,
    tier: "Pro",
    navDesc: "Deeper scans on managed infra",
    headline: "Launch deeper pentests",
    description:
      "Run deeper, longer pentests on managed infrastructure whenever you need them.",
  },
  {
    slug: "dashboard",
    title: "Dashboard",
    icon: LayoutDashboard,
    tier: "Pro",
    navDesc: "Everything in one place",
    headline: "See everything in one place",
    description:
      "Track every project, run, and finding across your org from a single dashboard.",
  },
  {
    slug: "platform_issues",
    title: "Issues",
    icon: AlertTriangle,
    tier: "Pro",
    navDesc: "Triage across your org",
    headline: "Triage findings across your org",
    description:
      "Manage and triage findings across every project and repository in one queue.",
  },
  {
    slug: "chat",
    title: "Chat",
    icon: MessageSquare,
    tier: "Pro",
    navDesc: "Ask about any finding",
    headline: "Ask Strix anything",
    description:
      "Ask the agents about any finding, run, or part of your app in natural language.",
  },
  {
    slug: "networks",
    title: "Networks",
    icon: Network,
    tier: "Enterprise",
    navDesc: "Reach internal, VPN-only targets",
    headline: "Scan internal networks",
    description:
      "Connect private networks to scan internal applications, VPN-only services, and RFC1918 targets.",
  },
  {
    slug: "knowledge",
    title: "Knowledge",
    icon: Database,
    tier: "Pro",
    navDesc: "Give agents context",
    headline: "Give agents context",
    description:
      "Teach Strix about your systems and business logic so every run gets smarter.",
  },
];

export const FEATURES: Record<string, ProFeature> = Object.fromEntries(
  PLATFORM_FEATURES.map((f) => [f.slug, f])
);

/**
 * Order the platform rows appear in the sidebar's single, ungrouped nav list
 * (after the run/local rows). No section headers; tier is shown only by each
 * row's inline tag.
 */
export const PLATFORM_ORDER: string[] = [
  "pr_reviews",
  "repositories",
  "domains",
  "integrations",
  "members",
  "pentests",
  "networks",
  "chat",
  "dashboard",
  "platform_issues",
  "knowledge",
];
