import { useEffect, useState } from "react";
import {
  X,
  Sparkles,
  ExternalLink,
  GitPullRequest,
  Shield,
  Zap,
  CalendarClock,
  WandSparkles,
  Plug,
} from "lucide-react";
import { SIGNUP_URL, PRICING_URL, ctaUrl, trackCta } from "@/lib/cta";

/**
 * Dialog shown when a platform feature is clicked in the sidebar: a short
 * description of the feature plus what Strix Cloud includes. The local viewer
 * has no billing, so both CTAs link out to the public sign-up / pricing pages.
 */

const CLOUD_HIGHLIGHTS: { icon: React.ElementType; label: string }[] = [
  { icon: GitPullRequest, label: "PR security reviews" },
  { icon: Shield, label: "Attack surface monitoring" },
  { icon: Zap, label: "Real-time threat intelligence" },
  { icon: CalendarClock, label: "Scheduled pentesting" },
  { icon: WandSparkles, label: "One-click autofix" },
  { icon: Plug, label: "Jira, Linear & Slack integrations" },
];

export function UpgradeModal({
  open,
  onClose,
  description,
  source = "sidebar",
}: {
  open: boolean;
  onClose: () => void;
  /** A short sentence describing what the clicked feature does. */
  description: string;
  source?: string;
}) {
  // Keep the dialog mounted through its exit animation: `render` controls
  // presence in the DOM and `state` ("open"/"closed") drives the keyframe. On
  // close we flip to "closed", let the 200ms animation play, then unmount --
  // the same lifecycle Radix gives shadcn's Dialog.
  const [render, setRender] = useState(open);
  const [state, setState] = useState<"open" | "closed">(open ? "open" : "closed");

  useEffect(() => {
    if (open) {
      setRender(true);
      setState("open");
      return;
    }
    setState("closed");
    const t = setTimeout(() => setRender(false), 200);
    return () => clearTimeout(t);
  }, [open]);

  useEffect(() => {
    if (!render) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [render, onClose]);

  if (!render) return null;

  return (
    <div
      data-state={state}
      className="dialog-overlay fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Upgrade your plan"
    >
      <div
        data-state={state}
        className="dialog-panel relative w-full max-w-md rounded-2xl border border-[#222] bg-black p-6 shadow-lg sm:rounded-lg"
        onClick={(e) => e.stopPropagation()}
      >
        <button
          type="button"
          onClick={onClose}
          aria-label="Close"
          className="absolute right-4 top-4 rounded-md p-1 text-[#888] transition-colors hover:bg-[#1a1a1a] hover:text-white"
        >
          <X className="h-4 w-4" />
        </button>

        <div>
          <h2 className="text-lg text-white">Available in Strix Cloud</h2>
          {description && (
            <p className="mt-2 text-base leading-relaxed text-[#e5e5e5]">{description}</p>
          )}
        </div>

        <div className="space-y-4 pt-4">
          <div className="rounded-xl border border-[#333] bg-[#0a0a0a] p-4 sm:rounded-lg">
            <div className="mb-3 flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-blue-400" />
              <span className="text-sm font-medium text-white">Strix Cloud also includes</span>
            </div>
            <ul className="space-y-2 text-sm text-[#888]">
              {CLOUD_HIGHLIGHTS.map((f) => (
                <li key={f.label} className="flex items-center gap-2">
                  <f.icon className="h-3.5 w-3.5 text-[#555]" />
                  {f.label}
                </li>
              ))}
            </ul>
          </div>

          <div className="flex flex-col gap-2">
            <a
              href={ctaUrl(SIGNUP_URL, "upgrade_try_free")}
              target="_blank"
              rel="noopener noreferrer"
              onClick={() => trackCta("upgrade_try_free", source)}
              className="flex h-10 w-full items-center justify-center gap-2 rounded-lg bg-white px-4 text-sm font-semibold text-black transition-colors hover:bg-neutral-200"
            >
              Open Strix Cloud
              <ExternalLink className="h-3.5 w-3.5" />
            </a>
            <a
              href={ctaUrl(PRICING_URL, "upgrade_view_plans")}
              target="_blank"
              rel="noopener noreferrer"
              onClick={() => trackCta("upgrade_view_plans", source)}
              className="flex h-9 w-full items-center justify-center gap-1.5 rounded-lg border border-[#333] px-4 text-sm font-medium text-[#888] transition-colors hover:border-[#555] hover:text-white"
            >
              Learn more
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}

export default UpgradeModal;
