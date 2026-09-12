import { useState } from "react";
import { ShieldCheck, X } from "lucide-react";

const DISMISS_KEY = "strix_viewer_trust_dismissed";

/**
 * One-time privacy notice, shown as a toast pinned over the sidebar. Dismissing
 * it persists to localStorage so it never returns on reload or view changes.
 */
export function TrustToast({ message }: { message: string }) {
  const [dismissed, setDismissed] = useState<boolean>(() => {
    try {
      return localStorage.getItem(DISMISS_KEY) === "1";
    } catch {
      return false;
    }
  });

  if (dismissed) return null;

  const dismiss = () => {
    try {
      localStorage.setItem(DISMISS_KEY, "1");
    } catch {
      /* non-fatal: worst case the toast shows again next session */
    }
    setDismissed(true);
  };

  return (
    <div
      className="fixed bottom-3 left-3 z-[60] max-w-xs rounded-lg bg-[#0a0a0a] p-3 shadow-2xl"
      style={{ border: "1px solid #2a2a2a" }}
      role="status"
    >
      <div className="flex gap-2.5">
        <ShieldCheck className="mt-0.5 h-4 w-4 flex-shrink-0 text-emerald-400" aria-hidden="true" />
        <p className="text-xs leading-relaxed text-[#aaa]">{message}</p>
        <button
          onClick={dismiss}
          aria-label="Dismiss"
          className="-mr-0.5 -mt-0.5 flex-shrink-0 cursor-pointer rounded p-0.5 text-[#666] transition-colors hover:text-white"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}

export default TrustToast;
