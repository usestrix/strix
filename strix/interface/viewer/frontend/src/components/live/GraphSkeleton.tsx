"use client";

function SkeletonNode({ w = 24 }: { w?: number }) {
  return (
    <div className="w-[180px] h-[72px] rounded-lg border border-[#222] bg-[#0a0a0a] px-3 py-2 shrink-0">
      <div className="flex items-center gap-2 mb-1.5">
        <div className="w-2 h-2 rounded-full bg-[#2a2a2a]" />
        <div className="h-3 rounded bg-[#252525]" style={{ width: `${w * 4}px` }} />
      </div>
      <div className="h-2 w-28 rounded bg-[#1e1e1e] mb-1.5" />
      <div className="flex gap-3">
        <div className="h-2 w-8 rounded bg-[#1e1e1e]" />
        <div className="h-2 w-8 rounded bg-[#1e1e1e]" />
      </div>
    </div>
  );
}

function VLine() {
  return <div className="w-px h-6 bg-[#2a2a2a]" />;
}

function HBranch({ count }: { count: number }) {
  return (
    <div className="relative flex justify-center">
      <div className="absolute top-0 h-px bg-[#2a2a2a]" style={{ width: `${(count - 1) * 220}px` }} />
    </div>
  );
}

export default function GraphSkeleton() {
  return (
    <div className="h-full bg-black overflow-hidden">
      <div className="flex flex-col items-center pt-10 animate-pulse">
        <SkeletonNode w={20} />
        <VLine />
        <HBranch count={3} />
        <div className="flex gap-10">
          {[18, 22, 16].map((w, i) => (
            <div key={i} className="flex flex-col items-center">
              <VLine />
              <SkeletonNode w={w} />
            </div>
          ))}
        </div>
        <div className="flex gap-10 w-full justify-center">
          <div className="flex flex-col items-center">
            <VLine />
            <HBranch count={2} />
            <div className="flex gap-10">
              {[14, 20].map((w, i) => (
                <div key={i} className="flex flex-col items-center">
                  <VLine />
                  <SkeletonNode w={w} />
                </div>
              ))}
            </div>
          </div>
          <div className="flex flex-col items-center">
            <VLine />
            <SkeletonNode w={18} />
            <VLine />
            <SkeletonNode w={12} />
          </div>
          <div className="w-[180px]" />
        </div>
      </div>
    </div>
  );
}
