"use client";

import type { ToolRendererProps } from "@/types/events";

export default function LoadSkillRenderer({ args }: ToolRendererProps) {
  const requestedRaw = (args.skills as string) ?? "";
  const requestedSkills = requestedRaw
    .split(",")
    .map((skill) => skill.trim())
    .filter(Boolean);

  return (
    <div className="flex items-center gap-2">
      <span className="text-emerald-400/80 font-semibold text-sm">Loading skill</span>
      {requestedSkills.length > 0 && (
        <span className="text-[#888] text-[13px]">{requestedSkills.join(", ")}</span>
      )}
    </div>
  );
}
