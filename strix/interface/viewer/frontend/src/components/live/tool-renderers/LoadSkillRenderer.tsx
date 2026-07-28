"use client";

import type { ToolRendererProps } from "@/types/events";

export default function LoadSkillRenderer({ args }: ToolRendererProps) {
  // `skills` may arrive as an array of names or a comma-separated string
  // depending on the tool call, so normalize both to a clean list.
  const raw = args.skills;
  const requestedSkills = (Array.isArray(raw) ? raw : String(raw ?? "").split(","))
    .map((skill) => String(skill).trim())
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
