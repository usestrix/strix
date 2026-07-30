import { useState } from "react";
import { Loader2, AlertCircle } from "lucide-react";
import { otpStart, otpVerify } from "@/data/serverSource";
import { track } from "@/lib/cta";

/**
 * Compact inline email -> 6-digit-code verify flow. Unlike EmailReportView this
 * has no page chrome, no report send, and no password panel: it just confirms
 * the email so the past-runs list can unlock in place. On success it calls
 * `onVerified` (the parent refreshes auth + runs).
 */

const OTP_START_ERRORS: Record<string, string> = {
  work_email_required: "Please use your work email, not a personal one.",
  rate_limited: "Too many requests. Wait a minute and try again.",
  invalid_email: "That email does not look right. Check it and try again.",
  unavailable: "The email service is unavailable right now. Try again shortly.",
};

// A small set of common personal providers for instant client-side feedback.
// The relay is authoritative (it checks the full free-email-domains list).
const COMMON_FREE_DOMAINS = new Set([
  "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com",
  "hotmail.com", "live.com", "icloud.com", "me.com", "aol.com", "proton.me",
  "protonmail.com", "gmx.com", "mail.com",
]);

export default function EmailVerifyInline({ onVerified }: { onVerified: () => void }) {
  const [step, setStep] = useState<"email" | "code">("email");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const submitEmail = async () => {
    const value = email.trim();
    if (!value) {
      setError("Enter your email to continue.");
      return;
    }
    const domain = value.slice(value.lastIndexOf("@") + 1).toLowerCase();
    if (COMMON_FREE_DOMAINS.has(domain)) {
      track("work_email_required");
      setError(OTP_START_ERRORS.work_email_required);
      return;
    }
    setBusy(true);
    setError(null);
    const result = await otpStart(value);
    setBusy(false);
    if (result.ok) {
      track("email_submitted", { purpose: "verify" });
      setNotice(`We sent a 6-digit code to ${value}.`);
      setStep("code");
    } else {
      if (result.error === "work_email_required") track("work_email_required");
      setError(OTP_START_ERRORS[result.error] ?? "Could not send a code. Try again.");
    }
  };

  const submitCode = async () => {
    const value = code.trim();
    if (value.length < 4) {
      setError("Enter the 6-digit code from your email.");
      return;
    }
    setBusy(true);
    setError(null);
    const result = await otpVerify(email.trim(), value);
    setBusy(false);
    if (!result.verified) {
      setError("That code did not match. Check it and try again.");
      return;
    }
    track("email_verified", { purpose: "verify" });
    onVerified();
  };

  return (
    <div className="mx-auto mt-5 max-w-sm text-left">
      {error && (
        <div className="mb-3 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2">
          <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-red-400" aria-hidden="true" />
          <p className="text-xs text-red-300">{error}</p>
        </div>
      )}
      {notice && !error && <p className="mb-3 text-xs text-[#888]">{notice}</p>}

      {step === "email" ? (
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            void submitEmail();
          }}
        >
          <label className="block">
            <span className="mb-1.5 block text-xs text-[#888]">Your work email</span>
            <input
              type="email"
              autoFocus
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@company.com"
              className="w-full rounded-lg bg-black px-3 py-2.5 text-sm text-white outline-none transition-colors focus:border-[#444]"
              style={{ border: "1px solid #2a2a2a" }}
            />
            <span className="mt-1.5 block text-[11px] text-[#666]">Use your work email.</span>
          </label>
          <button
            type="submit"
            disabled={busy}
            className="flex w-full cursor-pointer items-center justify-center gap-2 rounded-lg bg-white px-4 py-2.5 text-sm font-semibold text-black transition-opacity hover:opacity-90 disabled:opacity-60"
          >
            {busy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
            Send me a code
          </button>
        </form>
      ) : (
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            void submitCode();
          }}
        >
          <label className="block">
            <span className="mb-1.5 block text-xs text-[#888]">6-digit code</span>
            <input
              inputMode="numeric"
              autoFocus
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              placeholder="123456"
              className="w-full rounded-lg bg-black px-3 py-2.5 text-center text-lg font-mono tracking-[0.4em] text-white outline-none transition-colors focus:border-[#444]"
              style={{ border: "1px solid #2a2a2a" }}
            />
          </label>
          <button
            type="submit"
            disabled={busy}
            className="flex w-full cursor-pointer items-center justify-center gap-2 rounded-lg bg-white px-4 py-2.5 text-sm font-semibold text-black transition-opacity hover:opacity-90 disabled:opacity-60"
          >
            {busy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
            Verify
          </button>
          <button
            type="button"
            onClick={() => {
              setStep("email");
              setError(null);
              setNotice(null);
            }}
            className="w-full cursor-pointer text-center text-xs text-[#666] transition-colors hover:text-[#aaa]"
          >
            Use a different email
          </button>
        </form>
      )}
    </div>
  );
}
