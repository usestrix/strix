import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  AlertCircle,
  Bot,
  Mail,
  ChevronDown,
  ChevronRight,
  ShieldCheck,
  FileText,
  Radar,
  Rocket,
  ArrowUpRight,
  History,
} from "lucide-react";
import type { Vulnerability, VulnerabilitySeverity } from "@/types/issues";
import { SEVERITY_COLORS } from "@/types/issues";
import { getSeverityDot } from "@/lib/vulnerability-utils";
import VulnerabilityDetail from "@/components/vulnerability/VulnerabilityDetail";
import { ContentSection } from "@/components/vulnerability/ContentSection";
import { IssueSeveritySummary } from "@/components/IssueSeveritySummary";
import AgentGraph from "@/components/live/AgentGraph";
import { buildGraphAgents } from "@/components/live/AgentTranscript";
import AgentDetailModal from "@/components/live/AgentDetailModal";
import { ScanPromptComposer } from "@/components/live/ScanPromptComposer";
import { severityCounts, type ParsedRunSummary } from "@/lib/local-run-parser";
import {
  fetchAll,
  fetchAuthStatus,
  fetchCapabilities,
  fetchRunSummary,
  fetchRuns,
  fetchTranscript,
  fetchVulnerabilities,
  forgetAuth,
  type AuthStatus,
  type LoadedRun,
  type RunsPayload,
} from "@/data/serverSource";
import { SIGNUP_URL, ctaUrl, trackCta } from "@/lib/cta";
import { runTitle } from "@/lib/target-utils";
import Sidebar from "@/components/Sidebar";
import PastRunsView from "@/components/PastRunsView";
import EmailReportView from "@/components/EmailReportView";
import { RunDetails } from "@/components/RunDetails";
import { TrustToast } from "@/components/TrustToast";
import FeedbackView from "@/components/FeedbackView";
import { ProInlineCta } from "@/components/ProCta";
import { LiveActivityFeed } from "@/components/live/LiveActivityFeed";
import type { Transcript } from "@/data/serverSource";
import React, { Component, type ReactNode } from "react";

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

class AppErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error("ErrorBoundary caught an error:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-8 text-center space-y-3">
          <AlertCircle className="w-8 h-8 mx-auto text-red-400" />
          <p className="text-base font-semibold text-white">视图渲染遇到异常</p>
          <p className="text-xs text-red-300 font-mono">
            {this.state.error?.message || "未知组件错误"}
          </p>
          <button
            onClick={() => {
              this.setState({ hasError: false, error: null });
              window.location.reload();
            }}
            className="px-4 py-2 text-xs font-semibold rounded-lg bg-white text-black hover:bg-neutral-200 transition-colors"
          >
            重新加载页面
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

export type View = "overview" | "issues" | "agents" | "history" | "email" | "feedback";

const TRUST_BANNER =
  "所有渗透测试结果与漏洞数据均保存在本地服务器中，完全通过本地浏览器渲染呈现，绝不会上传或外泄。";

const SEVERITY_ORDER: VulnerabilitySeverity[] = ["critical", "high", "medium", "low"];
const POLL_MS = 500;

export default function App() {
  const [activeRun, setActiveRun] = useState<string | null>(null);
  const [run, setRun] = useState<LoadedRun | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [view, setView] = useState<View>("overview");
  const [auth, setAuth] = useState<AuthStatus | null>(null);
  const [runs, setRuns] = useState<RunsPayload | null>(null);
  const [emailPurpose, setEmailPurpose] = useState<"report" | "verify">("report");
  const [emailSkipDisclosure, setEmailSkipDisclosure] = useState(false);
  const [canSteer, setCanSteer] = useState(false);

  const refreshAuth = useCallback(async () => {
    try {
      setAuth(await fetchAuthStatus());
    } catch {
      /* auth status is best-effort */
    }
  }, []);

  const refreshRuns = useCallback(async () => {
    try {
      setRuns(await fetchRuns());
    } catch {
      /* history list is best-effort */
    }
  }, []);

  useEffect(() => {
    void refreshAuth();
    void refreshRuns();
    fetchCapabilities()
      .then((caps) => setCanSteer(caps.can_steer))
      .catch(() => {});
  }, [refreshAuth, refreshRuns]);

  const finishedRef = useRef(false);
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    finishedRef.current = false;

    const schedule = () => {
      timer = setTimeout(tick, POLL_MS);
    };

    const tick = async () => {
      if (cancelled) return;
      try {
        const { summary, raw, finished } = await fetchRunSummary(activeRun);
        if (cancelled) return;
        if (finished && !finishedRef.current) {
          finishedRef.current = true;
          const full = await fetchAll(activeRun);
          if (!cancelled) setRun(full);
          return;
        }
        const [transcript, vulnerabilities] = await Promise.all([
          fetchTranscript(activeRun).catch(() => ({ agents: [], events: [] })),
          fetchVulnerabilities(summary.runId, activeRun).catch(() => [] as Vulnerability[]),
        ]);
        if (cancelled) return;
        setRun((prev) => ({
          summary,
          raw,
          finished,
          transcript,
          vulnerabilities,
          reportMarkdown: prev?.reportMarkdown ?? null,
        }));
        schedule();
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : "无法加载扫描数据。");
        schedule();
      }
    };

    (async () => {
      try {
        const full = await fetchAll(activeRun);
        if (cancelled) return;
        setRun(full);
        if (full.finished) {
          finishedRef.current = true;
        } else {
          schedule();
        }
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : "无法加载扫描数据。");
        schedule();
      }
    })();

    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [activeRun]);

  const counts = useMemo(
    () => (run ? severityCounts(run.vulnerabilities) : null),
    [run]
  );
  const selected = run?.vulnerabilities.find((v) => v.id === selectedId) ?? null;
  const agentCount = run?.transcript.agents.length ?? 0;
  const verified = auth?.verified === true;

  const initialViewAppliedRef = useRef(false);

  useEffect(() => {
    initialViewAppliedRef.current = false;
  }, [activeRun]);

  useEffect(() => {
    if (initialViewAppliedRef.current || !run) return;
    if (run.finished) {
      initialViewAppliedRef.current = true;
      setView("overview");
    } else if (agentCount > 0) {
      initialViewAppliedRef.current = true;
      setView("agents");
    }
  }, [run, agentCount]);

  const userSetView = useCallback((v: View) => {
    initialViewAppliedRef.current = true;
    setView(v);
  }, []);

  const selectRun = useCallback((name: string) => {
    setActiveRun(name);
    setSelectedId(null);
    setRun(null);
    setError(null);
    initialViewAppliedRef.current = false;
  }, []);

  const goEmail = useCallback((skipDisclosure: boolean, surface: string) => {
    trackCta("email_report", surface);
    setEmailPurpose("report");
    setEmailSkipDisclosure(skipDisclosure);
    userSetView("email");
  }, [userSetView]);

  const openEmail = useCallback(() => goEmail(false, "sidebar"), [goEmail]);
  const openEmailFromOverview = useCallback(() => goEmail(true, "overview"), [goEmail]);

  const openHistory = useCallback(() => {
    void refreshRuns();
    userSetView("history");
  }, [refreshRuns, userSetView]);

  const onPastRunsVerified = useCallback(async () => {
    await refreshAuth();
    await refreshRuns();
  }, [refreshAuth, refreshRuns]);

  const onForget = useCallback(async () => {
    await forgetAuth();
    await refreshAuth();
    await refreshRuns();
  }, [refreshAuth, refreshRuns]);

  return (
    <div className="min-h-screen bg-black text-white flex">
      <Sidebar
        view={view}
        onSelectView={(v) => {
          setSelectedId(null);
          if (v === "history") openHistory();
          else userSetView(v);
        }}
        issuesCount={run?.vulnerabilities.length ?? 0}
        agentCount={agentCount}
        runCount={runs?.count ?? 0}
        finished={run?.finished ?? false}
        verified={verified}
        email={auth?.email ?? null}
        onOpenEmail={openEmail}
        onOpenHistory={openHistory}
        onForget={() => void onForget()}
      />

      <div className="flex-1 min-w-0">
        {/* Top bar */}
        <div className="border-b border-[#222]">
          <div className="max-w-[88rem] mx-auto px-3 sm:px-6 py-4 flex items-center gap-1.5">
            <a
              href={ctaUrl("https://app.strix.ai", "logo")}
              target="_blank"
              rel="noopener noreferrer"
              onClick={() => trackCta("logo", "topbar")}
              className="flex items-center gap-1.5 opacity-90 transition-opacity hover:opacity-100 lg:hidden"
              title="Open Strix Cloud"
            >
              <img src="./logo.png" alt="Strix" className="w-10 h-8 object-cover" />
              <div className="text-base text-white font-medium tracking-tight">Strix</div>
            </a>
            {run && <LiveIndicator finished={run.finished} />}
            <div className="ml-auto flex items-center gap-3">
              {runs && runs.runs.length > 0 && (
                <RunSwitcher
                  runs={runs}
                  activeRun={activeRun}
                  launchedName={runTitle(run?.summary.targets[0] ?? null, run?.summary.runName ?? run?.summary.runId ?? "当前任务")}
                  onSelect={selectRun}
                />
              )}
              <span className="inline-flex items-center rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold text-emerald-400">
                本地私有化版
              </span>
            </div>
          </div>
        </div>

        <div className="max-w-[88rem] mx-auto px-3 sm:px-6 py-8 sm:py-12 space-y-6">
          {error && !run && view !== "history" && view !== "email" && (
            <div className="rounded-lg px-4 py-3 flex gap-3 items-start border border-red-500/30 bg-red-500/5">
              <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5 text-red-400" aria-hidden="true" />
              <p className="text-sm text-red-300">{error}</p>
            </div>
          )}

          <AppErrorBoundary>
            <div
              key={`${activeRun ?? "launched"}:${view}:${selectedId ?? ""}`}
              className="animate-page-in space-y-6"
            >
            {view === "email" ? (
              <EmailReportView
                activeRun={activeRun}
                auth={auth}
                purpose={emailPurpose}
                skipDisclosure={emailSkipDisclosure}
                onAuthChanged={() => {
                  void refreshAuth();
                  void refreshRuns();
                }}
                onExit={(dest) => setView(dest === "history" ? "history" : "overview")}
              />
            ) : view === "feedback" ? (
              <FeedbackView
                defaultEmail={auth?.email ?? null}
                onExit={(dest) => setView(dest)}
              />
            ) : view === "history" ? (
              <div className="space-y-4">
                <div className="flex items-center gap-2">
                  <History className="w-5 h-5 text-[#888]" aria-hidden="true" />
                  <h1 className="text-2xl font-semibold text-white">历史扫描记录</h1>
                </div>
                <PastRunsView
                  runs={runs}
                  activeRun={activeRun}
                  onSelectRun={selectRun}
                  onVerified={() => void onPastRunsVerified()}
                />
              </div>
            ) : !run && !error ? (
              <div className="rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-10 text-center">
                <div className="w-6 h-6 mx-auto mb-3 rounded-full border-2 border-[#333] border-t-white animate-spin" />
                <p className="text-sm text-[#888]">正在加载扫描数据...</p>
              </div>
            ) : run && counts ? (
              <>
                <SummaryHeader summary={run.summary} />

                {/* Tab strip: shown on small screens where the sidebar is hidden. */}
                <div className="flex gap-5 border-b border-[#2a2a2a] lg:hidden">
                  <TabButton active={view === "overview"} onClick={() => userSetView("overview")}>
                    渗透概览
                  </TabButton>
                  <TabButton active={view === "issues"} onClick={() => userSetView("issues")}>
                    漏洞与风险{run.vulnerabilities.length > 0 ? ` (${run.vulnerabilities.length})` : ""}
                  </TabButton>
                  {agentCount > 0 && (
                    <TabButton active={view === "agents"} onClick={() => userSetView("agents")}>
                      智能体拓扑 ({agentCount})
                    </TabButton>
                  )}
                </div>

                {view === "overview" ? (
                  <OverviewTab
                    summary={run.summary}
                    counts={counts}
                    total={run.vulnerabilities.length}
                    reportMarkdown={run.reportMarkdown}
                    raw={run.raw}
                    finished={run.finished}
                    transcript={run.transcript}
                    onOpenEmail={openEmailFromOverview}
                    onSelectAgent={() => userSetView("agents")}
                  />
                ) : view === "agents" && agentCount > 0 ? (
                  <AgentsTab run={run} canSteer={canSteer} />
                ) : selected ? (
                  <div className="space-y-4">
                    <button
                      onClick={() => setSelectedId(null)}
                      className="cursor-pointer inline-flex items-center gap-1.5 text-sm text-[#888] hover:text-white transition-colors"
                    >
                      <ArrowLeft className="w-4 h-4" /> 返回所有漏洞列表
                    </button>
                    <VulnerabilityDetail vulnerability={selected} />
                  </div>
                ) : (
                  <FindingsList
                    vulnerabilities={run.vulnerabilities}
                    finished={run.finished}
                    reportMarkdown={run.reportMarkdown}
                    summary={run.summary}
                    transcript={run.transcript}
                    onSelect={(id) => setSelectedId(id)}
                    onSelectAgent={() => userSetView("agents")}
                  />
                )}
              </>
            ) : null}
            </div>
          </AppErrorBoundary>
        </div>
      </div>
      <TrustToast message={TRUST_BANNER} />
    </div>
  );
}

function RunSwitcher({
  runs,
  activeRun,
  launchedName,
  onSelect,
}: {
  runs: RunsPayload;
  activeRun: string | null;
  launchedName: string;
  onSelect: (name: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const activeEntry = runs.runs.find((r) => r.name === activeRun);
  const current = activeEntry ? runTitle(activeEntry.target, activeEntry.name) : launchedName;
  return (
    <div className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        aria-label="切换渗透任务"
        className="flex items-center gap-2 rounded-lg border border-[#3a3a3a] bg-[rgba(255,255,255,0.05)] px-3 py-2 text-sm text-white transition-colors hover:border-[#555] hover:bg-[rgba(255,255,255,0.09)]"
      >
        <History className="h-4 w-4 flex-shrink-0 text-[#888]" aria-hidden="true" />
        <span className="flex-shrink-0 text-[#888]">任务</span>
        <span className="max-w-[260px] truncate font-medium">{current}</span>
        <ChevronDown className="h-4 w-4 flex-shrink-0 text-[#aaa]" aria-hidden="true" />
      </button>
      {open && (
        <div
          className="absolute right-0 z-50 mt-2 max-h-96 w-96 overflow-y-auto rounded-xl py-1.5 shadow-2xl"
          style={{ border: "1px solid #3a3a3a", background: "#0a0a0a" }}
        >
          <div className="border-b border-[#222] px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-[#666]">
            切换扫描任务
          </div>
          {runs.runs.map((r) => {
            const active = r.name === activeRun;
            return (
              <button
                key={r.name}
                onMouseDown={() => onSelect(r.name)}
                className={`flex w-full items-center gap-2 px-3 py-2.5 text-left text-sm transition-colors hover:bg-[rgba(255,255,255,0.06)] ${
                  active ? "bg-[rgba(255,255,255,0.04)] text-white" : "text-[#aaa]"
                }`}
              >
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-medium">{runTitle(r.target, r.name)}</span>
                  {r.target && <span className="block truncate font-mono text-xs text-[#666]">{r.target}</span>}
                </span>
                {active && <span className="h-2 w-2 flex-shrink-0 rounded-full bg-emerald-400" />}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function LiveIndicator({ finished }: { finished: boolean }) {
  if (finished) {
    return (
      <span className="ml-3 inline-flex items-center gap-1.5 text-xs text-[#888]">
        <span className="w-1.5 h-1.5 rounded-full bg-[#555]" />
        扫描已完成
      </span>
    );
  }
  return (
    <span className="ml-3 inline-flex items-center gap-1.5 text-xs text-emerald-400">
      <span className="relative flex h-1.5 w-1.5">
        <span className="absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75 animate-ping" />
        <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-400" />
      </span>
      扫描执行中
    </span>
  );
}

function formatDuration(seconds: number | null): string | null {
  if (seconds == null) return null;
  if (seconds < 60) return `${seconds} 秒`;
  const m = Math.floor(seconds / 60);
  if (m < 60) return `${m} 分钟`;
  const h = Math.floor(m / 60);
  return `${h} 小时 ${m % 60} 分钟`;
}

function SummaryHeader({ summary }: { summary: ParsedRunSummary }) {
  const duration = formatDuration(summary.durationSeconds);
  const modeName = summary.scanMode === "deep" ? "深度扫描 (Deep)" : summary.scanMode === "standard" ? "标准扫描 (Standard)" : "快速扫描 (Quick)";
  const statusName = summary.status === "completed" ? "已完成" : summary.status === "running" ? "进行中" : "异常/已停止";
  return (
    <div>
      <h1 className="text-2xl font-semibold text-white">
        {runTitle(summary.targets[0] ?? null, summary.runName ?? summary.runId ?? "渗透测试结果")}
      </h1>
      <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-[#888]">
        {summary.targets.length > 0 && (
          <span className="font-mono text-[#aaa]">{summary.targets.join(", ")}</span>
        )}
        {summary.scanMode && <Meta label={modeName} />}
        {duration && <Meta label={duration} />}
        {summary.status && <Meta label={statusName} />}
      </div>
    </div>
  );
}

function Meta({ label }: { label: string }) {
  return (
    <>
      <span className="text-[#333]">·</span>
      <span className="capitalize">{label}</span>
    </>
  );
}

function FindingsList({
  vulnerabilities,
  finished,
  reportMarkdown,
  summary,
  transcript,
  onSelect,
  onSelectAgent,
}: {
  vulnerabilities: Vulnerability[];
  finished: boolean;
  reportMarkdown?: string | null;
  summary?: ParsedRunSummary;
  transcript?: Transcript | null;
  onSelect: (id: string) => void;
  onSelectAgent?: () => void;
}) {
  const sorted = [...vulnerabilities].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  const sections = summary
    ? (
        [
          ["管理层执行摘要 (Executive Summary)", summary.executiveSummary],
          ["技术深度分析 (Technical Analysis)", summary.technicalAnalysis],
          ["渗透测试方法与策略 (Methodology)", summary.methodology],
          ["安全整改建议 (Recommendations)", summary.recommendations],
        ] as const
      )
        .filter(([, content]) => !!content)
        .map(([title, content]) => ({ title, content: stripLeadingHeading(content as string) }))
    : [];

  return (
    <div className="space-y-6">
      {sorted.length > 0 ? (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white">
              已发现漏洞与安全风险 ({sorted.length})
            </h2>
            <span className="text-xs text-[#888]">点击卡片查看详细验证 PoC 与修复建议</span>
          </div>

          <div className="grid gap-3">
            {sorted.map((v) => (
              <div
                key={v.id}
                onClick={() => onSelect(v.id)}
                className="animate-card-in group cursor-pointer w-full text-left rounded-xl border border-[#222] hover:border-emerald-500/40 bg-[rgba(255,255,255,0.02)] hover:bg-[rgba(255,255,255,0.04)] p-5 transition-all space-y-3"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0 flex-1 space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${getSeverityDot(v.severity)}`} aria-hidden="true" />
                      <span className="text-base font-semibold text-white group-hover:text-emerald-400 transition-colors">
                        {v.title}
                      </span>
                    </div>

                    {(v.target || v.endpoint) && (
                      <div className="text-xs text-[#888] font-mono">
                        {v.method ? <span className="text-emerald-400/80 mr-1.5 font-bold">{v.method}</span> : null}
                        {v.target}{v.endpoint ? ` ${v.endpoint}` : ""}
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-2 flex-shrink-0">
                    {v.cvss != null && (
                      <span className="text-xs font-mono text-[#aaa] border border-[#333] bg-[#111] px-2 py-0.5 rounded">
                        CVSS {v.cvss}
                      </span>
                    )}
                    {v.cve && (
                      <span className="text-xs font-mono text-purple-400 border border-purple-500/30 bg-purple-500/10 px-2 py-0.5 rounded">
                        {v.cve}
                      </span>
                    )}
                    <span
                      className={`text-xs font-semibold px-2.5 py-0.5 rounded-full border uppercase ${SEVERITY_COLORS[v.severity]}`}
                    >
                      {v.severity}
                    </span>
                  </div>
                </div>

                {v.description && (
                  <p className="text-sm text-[#aaa] line-clamp-2 leading-relaxed">
                    {v.description}
                  </p>
                )}

                <div className="flex items-center justify-between pt-1 border-t border-[#1a1a1a] text-xs text-[#666]">
                  <span>{v.cwe ? `CWE: ${Array.isArray(v.cwe) ? v.cwe.join(", ") : v.cwe}` : "已验证漏洞"}</span>
                  <span className="text-emerald-400/80 group-hover:text-emerald-400 flex items-center gap-1 font-medium">
                    查看完整细节与 PoC <ChevronRight className="w-3.5 h-3.5 inline" />
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-6 space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg border border-emerald-500/30 bg-emerald-500/10 flex items-center justify-center flex-shrink-0">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
              </div>
              <div className="min-w-0 flex-1">
                <h3 className="text-base font-semibold text-white">
                  {finished ? "本次渗透测试未发现可直接利用的高危漏洞" : "当前扫描任务执行中，正在深度排查漏洞与安全风险…"}
                </h3>
                <p className="text-xs text-[#888] mt-0.5">
                  {finished
                    ? "已针对目标资产完成端口探测、服务指纹识别、已知 CVE 匹配与安全基线合规检查。"
                    : "多个专职安全智能体正在并行对目标主机的端口暴露面、管理控制台与已知服务漏洞进行持续探测。"}
                </p>
              </div>
            </div>

            {/* Audit Scope & Live Status */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-3 border-t border-[#1a1a1a]">
              <div className="rounded-lg border border-[#222] bg-black/40 p-3 space-y-1.5">
                <span className="text-xs font-semibold text-white flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  边界端口与服务指纹探测
                </span>
                <p className="text-xs text-[#888]">
                  排查 SSH、Web 管理控制台、VPN、SNMP 等常见开放端口及服务版本信息。
                </p>
              </div>

              <div className="rounded-lg border border-[#222] bg-black/40 p-3 space-y-1.5">
                <span className="text-xs font-semibold text-white flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-blue-400" />
                  管理面与认证机制审计
                </span>
                <p className="text-xs text-[#888]">
                  核验未授权访问接口、弱认证配置、默认凭据与越权安全风险。
                </p>
              </div>

              <div className="rounded-lg border border-[#222] bg-black/40 p-3 space-y-1.5">
                <span className="text-xs font-semibold text-white flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-purple-400" />
                  已知组件公开 CVE 检索验证
                </span>
                <p className="text-xs text-[#888]">
                  自动比对服务指纹与公开漏洞库，针对性执行非破坏性验证 PoC。
                </p>
              </div>

              <div className="rounded-lg border border-[#222] bg-black/40 p-3 space-y-1.5">
                <span className="text-xs font-semibold text-white flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-amber-400" />
                  非破坏性安全基线合规检查
                </span>
                <p className="text-xs text-[#888]">
                  严禁高并发拒绝服务操作，确保网络服务可用性与设备正常运转。
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Real-time Probe Results and Activity Stream */}
      <LiveActivityFeed
        transcript={transcript ?? null}
        finished={finished}
        onSelectAgent={onSelectAgent}
      />

      {/* Audit Report & Technical Findings Details Section */}
      {sections.length > 0 ? (
        <div className="animate-card-in rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-6 space-y-8">
          <div className="flex items-center gap-2 border-b border-[#222] pb-3">
            <FileText className="w-4 h-4 text-emerald-400" />
            <h3 className="text-base font-semibold text-white">本次渗透测试审计与侦察发现详情</h3>
          </div>
          {sections.map((s) => (
            <ContentSection key={s.title} title={s.title} content={s.content} />
          ))}
        </div>
      ) : reportMarkdown ? (
        <div className="animate-card-in rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-6 space-y-4">
          <div className="flex items-center gap-2 border-b border-[#222] pb-3">
            <FileText className="w-4 h-4 text-emerald-400" />
            <h3 className="text-base font-semibold text-white">本次渗透测试审计与侦察发现详情</h3>
          </div>
          <ContentSection content={dedupeHeadings(reportMarkdown)} />
        </div>
      ) : null}
    </div>
  );
}

function stripLeadingHeading(md: string): string {
  return md.replace(/^\s*#{1,6}[ \t]+.*(?:\r?\n)+/, "").trimStart();
}

function dedupeHeadings(md: string): string {
  const out: string[] = [];
  let lastHeading: string | null = null;
  for (const line of md.split("\n")) {
    const m = line.match(/^#{1,6}\s+(.*)$/);
    if (m) {
      const norm = m[1].trim().toLowerCase();
      if (norm === lastHeading) continue;
      lastHeading = norm;
    } else if (line.trim() !== "") {
      lastHeading = null;
    }
    out.push(line);
  }
  return out.join("\n");
}

function EmailReportCta({ onOpenEmail }: { onOpenEmail: () => void }) {
  return (
    <button
      onClick={onOpenEmail}
      className="group w-full cursor-pointer rounded-xl border border-emerald-500/25 bg-emerald-500/[0.06] p-4 text-left transition-colors hover:border-emerald-500/40"
    >
      <div className="flex items-center gap-3">
        <div
          className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg"
          style={{ border: "1px solid rgba(16,185,129,0.3)", background: "rgba(16,185,129,0.08)" }}
        >
          <Mail className="h-4 w-4 text-emerald-400" aria-hidden="true" />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-white">一键导出本次渗透测试评估报告</p>
          <p className="mt-0.5 text-xs text-[#888]">
            支持本地直接下载 Markdown / PDF 报告，数据完全私有化，无需经过外部中继。
          </p>
        </div>
        <span className="flex-shrink-0 rounded-lg bg-white px-3 py-1.5 text-xs font-semibold text-black transition-opacity group-hover:opacity-90">
          导出测试报告
        </span>
      </div>
    </button>
  );
}

function OverviewTab({
  summary,
  counts,
  total,
  reportMarkdown,
  raw,
  finished,
  transcript,
  onOpenEmail,
  onSelectAgent,
}: {
  summary: ParsedRunSummary;
  counts: Record<VulnerabilitySeverity, number>;
  total: number;
  reportMarkdown: string | null;
  raw: Record<string, unknown>;
  finished: boolean;
  transcript: Transcript | null;
  onOpenEmail: () => void;
  onSelectAgent?: () => void;
}) {
  const sections = (
    [
      ["管理层摘要 (Executive Summary)", summary.executiveSummary],
      ["技术深度分析 (Technical Analysis)", summary.technicalAnalysis],
      ["渗透方法与策略 (Methodology)", summary.methodology],
      ["安全整改建议 (Recommendations)", summary.recommendations],
    ] as const
  )
    .filter(([, content]) => !!content)
    .map(([title, content]) => ({ title, content: stripLeadingHeading(content as string) }));

  return (
    <div className="space-y-6">
      <div className="animate-card-in">
        <RunDetails raw={raw} durationSeconds={summary.durationSeconds} />
      </div>

      {/* Live Probe and Activity Stream */}
      <LiveActivityFeed
        transcript={transcript}
        finished={finished}
        onSelectAgent={onSelectAgent}
      />

      {total > 0 && (
        <div className="animate-card-in rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5">
          <IssueSeveritySummary findings={{ total, ...counts }} />
        </div>
      )}

      {finished && (
        <div className="animate-card-in">
          <EmailReportCta onOpenEmail={onOpenEmail} />
        </div>
      )}

      {sections.length > 0 ? (
        <div className="animate-card-in rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5 space-y-8">
          {sections.map((s) => (
            <ContentSection key={s.title} title={s.title} content={s.content} />
          ))}
        </div>
      ) : reportMarkdown ? (
        <div className="animate-card-in rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5">
          <ContentSection content={dedupeHeadings(reportMarkdown)} />
        </div>
      ) : null}
    </div>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`cursor-pointer relative pb-2.5 text-sm font-semibold transition-colors ${
        active ? "text-white" : "text-[#666] hover:text-white"
      }`}
    >
      {children}
      {active && <span className="absolute bottom-0 inset-x-0 h-0.5 bg-white rounded-full" />}
    </button>
  );
}

function AgentsTab({ run, canSteer }: { run: LoadedRun; canSteer: boolean }) {
  const { agents, events } = run.transcript;
  const graphAgents = useMemo(() => buildGraphAgents(agents, events), [agents, events]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selectedAgent = selectedId ? (agents.find((a) => a.id === selectedId) ?? null) : null;

  const steerable = canSteer && !run.finished;

  return (
    <div className="space-y-5">
      <div className="rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5">
        <div className="flex items-center gap-2">
          <Bot className="w-4 h-4 text-[#888]" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-white">智能体协同拓扑图 (Agent Graph)</h2>
          <span className="text-xs text-[#666]">
            {agents.length} 个智能体协同执行中
          </span>
        </div>
        <p className="mt-1 mb-4 text-xs text-[#666]">
          点击任意智能体节点，可展开查看其完整的思考过程、工具调用与交互轨迹。
        </p>
        <div className="h-[480px] rounded-lg border border-[#1a1a1a] overflow-hidden">
          <AgentGraph
            agents={graphAgents}
            selectedAgentId={selectedId}
            onSelectAgent={(id) => setSelectedId(id)}
            eventsLoaded
            eventsEmpty={graphAgents.size === 0}
            scanCompleted={run.finished}
          />
        </div>
      </div>

      {steerable && <ScanPromptComposer agents={agents} />}

      {/* Live Probe and Activity Stream */}
      <LiveActivityFeed
        transcript={run.transcript}
        finished={run.finished}
        onSelectAgent={(id) => setSelectedId(id)}
      />

      <AgentDetailModal
        open={selectedAgent !== null}
        agent={selectedAgent}
        events={events}
        steerable={steerable}
        onClose={() => setSelectedId(null)}
      />
    </div>
  );
}
