// Extracted ProviderIcon from strix-app's AddRepositoryDialog. The dialog itself
// (and its next/link dependency) is dropped; the IssueSidebar only needs this SVG
// switch to badge a finding's source-control provider. Web-app targets resolve to
// provider === null and never reach here (they render a globe icon instead).
import { Github, Gitlab } from "lucide-react";

function BitbucketIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden="true">
      <path d="M2.65 3a.72.72 0 0 0-.72.83l2.86 17.39a.98.98 0 0 0 .96.82h13.72a.72.72 0 0 0 .72-.6l2.86-17.4A.72.72 0 0 0 22.3 3H2.65Zm12.1 12.53H9.3L8.06 8.9h7.8l-1.11 6.63Z" />
    </svg>
  );
}

export function ProviderIcon({ provider, className }: { provider: string; className?: string }) {
  const cls = className ?? "w-4 h-4";
  if (provider === "gitlab") return <Gitlab className={`${cls} text-orange-400`} />;
  if (provider === "bitbucket") return <BitbucketIcon className={`${cls} text-blue-400`} />;
  return <Github className={`${cls} text-white`} />;
}
