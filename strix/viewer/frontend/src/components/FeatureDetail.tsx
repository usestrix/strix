import {
  CalendarClock,
  WandSparkles,
  Puzzle,
  Users,
  ArrowUpRight,
} from "lucide-react";
import { SIGNUP_URL, PRICING_URL, ctaUrl, trackCta } from "@/lib/cta";
import type { ProFeature } from "@/lib/pro-features";
import { ProTag } from "@/components/ProCta";

/**
 * In-app upsell page for a single platform feature. Modeled on the cloud app's
 * Networks upsell: a centered bordered card with an icon medallion, tier pill,
 * headline, one-line description, a shared "Included in Strix Pro" bullet list,
 * then a primary sign-up CTA and a secondary link to all plans.
 */

const INCLUDED = [
  {
    icon: CalendarClock,
    text: "Continuous coverage: scheduled pentests and attack surface monitoring",
  },
  { icon: WandSparkles, text: "One-click autofix that opens a retested pull request" },
  { icon: Puzzle, text: "Two-way sync to Jira, Linear, and Slack" },
  { icon: Users, text: "Your whole team, with roles and shared history" },
];

export default function FeatureDetail({ feature }: { feature: ProFeature }) {
  const Icon = feature.icon;
  return (
    <div className="mx-auto w-full max-w-lg">
      <div className="rounded-2xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-8 text-center">
        <div
          className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl"
          style={{ border: "1px solid #2a2a2a", background: "rgba(255,255,255,0.04)" }}
        >
          <Icon className="h-5 w-5 text-[#888]" aria-hidden="true" />
        </div>

        <div className="mt-4 flex justify-center">
          <ProTag label={feature.tier} />
        </div>

        <h2 className="mt-3 text-2xl font-semibold text-white">{feature.headline}</h2>
        <p className="mx-auto mt-2 max-w-md text-sm text-[#888]">{feature.description}</p>

        <div
          className="mt-6 rounded-xl p-4 text-left"
          style={{ border: "1px solid #222", background: "rgba(255,255,255,0.02)" }}
        >
          <p className="mb-3 text-xs font-semibold uppercase tracking-wide text-[#666]">
            Included in Strix Pro
          </p>
          <ul className="space-y-2.5">
            {INCLUDED.map((item) => {
              const BulletIcon = item.icon;
              return (
                <li key={item.text} className="flex items-start gap-2.5">
                  <BulletIcon
                    className="mt-0.5 h-4 w-4 flex-shrink-0 text-[#888]"
                    aria-hidden="true"
                  />
                  <span className="text-sm text-[#aaa]">{item.text}</span>
                </li>
              );
            })}
          </ul>
        </div>

        <div className="mt-6 flex flex-col items-center gap-3">
          <a
            href={ctaUrl(SIGNUP_URL, feature.slug)}
            target="_blank"
            rel="noopener noreferrer"
            onClick={() => trackCta(feature.slug, "feature_page")}
            className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg bg-white px-4 py-2.5 text-sm font-semibold text-black transition-opacity hover:opacity-90"
          >
            Start free
            <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
          </a>
          <a
            href={ctaUrl(PRICING_URL, feature.slug)}
            target="_blank"
            rel="noopener noreferrer"
            onClick={() => trackCta(feature.slug, "feature_page_plans")}
            className="inline-flex items-center gap-1 text-xs text-[#888] transition-colors hover:text-white"
          >
            View all plans
            <ArrowUpRight className="h-3 w-3" aria-hidden="true" />
          </a>
        </div>
      </div>
    </div>
  );
}
