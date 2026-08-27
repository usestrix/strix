import { useEffect, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  FileText,
  Download,
  Copy,
  Check,
  Loader2,
  AlertCircle,
  ArrowLeft,
  Printer,
  ShieldCheck,
  Eye,
  Code,
  Globe,
  Lock,
} from "lucide-react";
import { fetchReportMarkdown, type AuthStatus } from "@/data/serverSource";
import { rehypeCodeMeta, mdComponents } from "@/components/vulnerability/MdCodeBlock";

interface EmailReportViewProps {
  activeRun: string | null;
  auth: AuthStatus | null;
  purpose: "report" | "verify";
  skipDisclosure?: boolean;
  onAuthChanged: () => void;
  onExit: (dest: "overview" | "history") => void;
}

export default function EmailReportView({
  activeRun,
  onExit,
}: EmailReportViewProps) {
  const [loading, setLoading] = useState(true);
  const [reportMarkdown, setReportMarkdown] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [viewMode, setViewMode] = useState<"rendered" | "raw">("rendered");

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    setError(null);

    fetchReportMarkdown(activeRun)
      .then((md) => {
        if (!mounted) return;
        if (md) {
          setReportMarkdown(md);
        } else {
          setReportMarkdown("# 渗透测试报告\n\n当前任务暂未生成总结报告。");
        }
        setLoading(false);
      })
      .catch((err) => {
        if (!mounted) return;
        setError(String(err));
        setLoading(false);
      });

    return () => {
      mounted = false;
    };
  }, [activeRun]);

  const downloadMarkdown = () => {
    if (!reportMarkdown) return;
    const blob = new Blob([reportMarkdown], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${activeRun || "strix"}_渗透测试报告.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const copyMarkdown = async () => {
    try {
      await navigator.clipboard.writeText(reportMarkdown);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard fallback */
    }
  };

  const downloadStandaloneHtml = () => {
    if (!reportMarkdown) return;
    const reportElem = document.getElementById("strix-rendered-report");
    const reportHtml = reportElem ? reportElem.innerHTML : reportMarkdown;

    const fullHtml = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>安全渗透测试评估报告 - ${activeRun || "Strix"}</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.6;
      color: #1e293b;
      max-width: 900px;
      margin: 40px auto;
      padding: 0 20px;
      background: #ffffff;
    }
    h1, h2, h3 { color: #0f172a; margin-top: 1.5em; }
    h1 { border-bottom: 2px solid #0f172a; padding-bottom: 10px; }
    h2 { border-left: 4px solid #10b981; padding-left: 12px; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    th, td { border: 1px solid #cbd5e1; padding: 10px 12px; text-align: left; }
    th { background: #f8fafc; font-weight: 600; }
    tr:nth-child(even) td { background: #f8fafc; }
    blockquote { border-left: 4px solid #64748b; background: #f8fafc; padding: 10px 16px; margin: 16px 0; color: #475569; }
    pre { background: #f1f5f9; padding: 14px; border-radius: 6px; overflow-x: auto; font-size: 13px; }
    code { font-family: monospace; background: #f1f5f9; padding: 2px 6px; border-radius: 4px; }
    .header-badge { display: inline-block; padding: 4px 10px; background: #fee2e2; color: #991b1b; border-radius: 4px; font-weight: bold; font-size: 12px; margin-bottom: 12px; }
  </style>
</head>
<body>
  <div class="header-badge">内部机密 · CONFIDENTIAL</div>
  ${reportHtml}
</body>
</html>`;

    const blob = new Blob([fullHtml], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${activeRun || "strix"}_渗透测试报告.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const printReport = () => {
    setViewMode("rendered");
    setTimeout(() => {
      window.print();
    }, 150);
  };

  return (
    <div className="mx-auto max-w-4xl space-y-5 report-print-container">
      {/* Back button (hidden when printing) */}
      <button
        onClick={() => onExit("overview")}
        className="no-print cursor-pointer inline-flex items-center gap-1.5 text-sm text-[#888] transition-colors hover:text-white"
      >
        <ArrowLeft className="h-4 w-4" />
        返回渗透概览
      </button>

      {/* Top Action Bar (hidden when printing) */}
      <div className="no-print flex flex-wrap items-center justify-between gap-4 border-b border-[#222] pb-4">
        <div className="flex items-center gap-2.5">
          <FileText className="h-6 w-6 text-emerald-400" aria-hidden="true" />
          <div>
            <h1 className="text-xl font-semibold text-white">安全渗透评估报告</h1>
            <p className="text-xs text-[#888]">专业排版 · 支持一键导出为完整 PDF 或独立 HTML 报告</p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* View mode toggle */}
          <div className="flex items-center rounded-lg border border-[#333] bg-[#111] p-0.5">
            <button
              onClick={() => setViewMode("rendered")}
              className={`cursor-pointer inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                viewMode === "rendered"
                  ? "bg-emerald-500 text-black font-semibold"
                  : "text-[#888] hover:text-white"
              }`}
            >
              <Eye className="h-3.5 w-3.5" />
              精美排版
            </button>
            <button
              onClick={() => setViewMode("raw")}
              className={`cursor-pointer inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                viewMode === "raw"
                  ? "bg-emerald-500 text-black font-semibold"
                  : "text-[#888] hover:text-white"
              }`}
            >
              <Code className="h-3.5 w-3.5" />
              Markdown 源码
            </button>
          </div>

          <button
            onClick={copyMarkdown}
            disabled={loading || !reportMarkdown}
            className="cursor-pointer inline-flex items-center gap-1.5 rounded-lg border border-[#333] bg-[#111] px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-[#222] disabled:opacity-50"
            title="复制 Markdown 原文到剪贴板"
          >
            {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
            {copied ? "已复制" : "复制"}
          </button>

          <button
            onClick={downloadMarkdown}
            disabled={loading || !reportMarkdown}
            className="cursor-pointer inline-flex items-center gap-1.5 rounded-lg border border-[#333] bg-[#111] px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-[#222] disabled:opacity-50"
            title="下载 .md 文件"
          >
            <Download className="h-3.5 w-3.5 text-blue-400" />
            .MD
          </button>

          <button
            onClick={downloadStandaloneHtml}
            disabled={loading || !reportMarkdown}
            className="cursor-pointer inline-flex items-center gap-1.5 rounded-lg border border-[#333] bg-[#111] px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-[#222] disabled:opacity-50"
            title="下载独立离线 HTML 报告"
          >
            <Globe className="h-3.5 w-3.5 text-purple-400" />
            .HTML
          </button>

          <button
            onClick={printReport}
            disabled={loading}
            className="cursor-pointer inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-4 py-1.5 text-xs font-semibold text-black transition-opacity hover:opacity-90 disabled:opacity-50 shadow-md shadow-emerald-500/10"
            title="通过浏览器将已排版页面另存为 PDF"
          >
            <Printer className="h-3.5 w-3.5" />
            存为 PDF / 打印
          </button>
        </div>
      </div>

      {/* Main Report Container */}
      <div
        className="w-full rounded-2xl bg-[#0a0a0a] p-6 sm:p-8 report-print-container"
        style={{ border: "1px solid #222" }}
      >
        {/* Safe notice banner (hidden in print) */}
        <div className="no-print mb-6 flex items-start gap-2.5 rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-3.5 py-2.5">
          <ShieldCheck className="mt-0.5 h-4 w-4 flex-shrink-0 text-emerald-400" aria-hidden="true" />
          <p className="text-xs text-emerald-200">
            <strong>本地私有化报告导出</strong>：数据完全保留在本机服务器，直接由前端渲染排版为专业文档。打印或另存为 PDF 时将自动应用高对比度 A4 商务报告规范。
          </p>
        </div>

        {error && (
          <div className="mb-4 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2">
            <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-red-400" aria-hidden="true" />
            <p className="text-xs text-red-300">{error}</p>
          </div>
        )}

        {loading ? (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <Loader2 className="h-8 w-8 animate-spin text-emerald-400" />
            <p className="mt-3 text-sm text-[#888]">正在读取并渲染安全评估报告...</p>
          </div>
        ) : (
          <div>
            {/* Formal Report Cover Card (Header for both screen and print) */}
            <div className="mb-8 rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5 print:p-0 print:border-none print:mb-6">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#222] pb-3 print:border-slate-300">
                <div className="flex items-center gap-2">
                  <div className="flex h-7 w-7 items-center justify-center rounded-md bg-emerald-500/20 text-emerald-400 print:bg-slate-100 print:text-slate-900">
                    <ShieldCheck className="h-4 w-4" />
                  </div>
                  <div>
                    <span className="text-sm font-semibold text-white print:text-slate-900">
                      STRIX AUTONOMOUS PENTEST REPORT
                    </span>
                    <span className="block text-[11px] text-[#666] print:text-slate-500">
                      企业级自主渗透测试与安全合规审计评估报告
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span className="inline-flex items-center gap-1 rounded bg-red-500/10 px-2 py-0.5 text-[11px] font-semibold text-red-400 border border-red-500/20 print:bg-slate-100 print:text-red-700 print:border-slate-300">
                    <Lock className="h-3 w-3" />
                    内部机密 · CONFIDENTIAL
                  </span>
                </div>
              </div>

              <div className="mt-3 grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div>
                  <span className="block text-[#666] print:text-slate-500">评估目标 (Target)</span>
                  <span className="font-mono font-medium text-white print:text-slate-800 break-all">
                    {activeRun?.split("_")[0] || "Target Asset"}
                  </span>
                </div>
                <div>
                  <span className="block text-[#666] print:text-slate-500">报告批次 (Run ID)</span>
                  <span className="font-mono text-[#aaa] print:text-slate-700">{activeRun || "--"}</span>
                </div>
                <div>
                  <span className="block text-[#666] print:text-slate-500">评估引擎 (Engine)</span>
                  <span className="font-medium text-emerald-400 print:text-emerald-700">Strix Autonomous v1.3</span>
                </div>
                <div>
                  <span className="block text-[#666] print:text-slate-500">审计范围 (Scope)</span>
                  <span className="font-medium text-white print:text-slate-800">授权网络与应用渗透</span>
                </div>
              </div>
            </div>

            {/* Document Body */}
            {viewMode === "rendered" ? (
              <div id="strix-rendered-report" className="prose-markdown report-print-body leading-relaxed text-[#ddd] text-sm">
                <ReactMarkdown
                  remarkPlugins={[remarkGfm]}
                  rehypePlugins={[rehypeCodeMeta]}
                  components={{
                    ...mdComponents,
                    h1: ({ children }) => (
                      <h1 className="text-2xl font-bold text-white mt-8 mb-4 pb-2 border-b border-[#222] flex items-center gap-2 print:text-slate-900 print:border-slate-300">
                        {children}
                      </h1>
                    ),
                    h2: ({ children }) => (
                      <h2 className="text-lg font-semibold text-white mt-6 mb-3 pl-3 border-l-4 border-emerald-500 print:text-slate-900 print:border-emerald-600">
                        {children}
                      </h2>
                    ),
                    h3: ({ children }) => (
                      <h3 className="text-base font-medium text-emerald-300 mt-5 mb-2 print:text-slate-800">
                        {children}
                      </h3>
                    ),
                    table: ({ children }) => (
                      <div className="my-5 overflow-x-auto rounded-lg border border-[#222] print:border-slate-300 print:overflow-visible">
                        <table className="w-full border-collapse text-left text-xs">{children}</table>
                      </div>
                    ),
                    th: ({ children }) => (
                      <th className="border-b border-[#222] bg-[rgba(255,255,255,0.04)] px-3.5 py-2.5 font-semibold text-[#ccc] print:bg-slate-100 print:text-slate-900 print:border-slate-300">
                        {children}
                      </th>
                    ),
                    td: ({ children }) => (
                      <td className="border-b border-[#1a1a1a] px-3.5 py-2 text-[#aaa] print:text-slate-700 print:border-slate-200">
                        {children}
                      </td>
                    ),
                    blockquote: ({ children }) => (
                      <blockquote className="my-4 rounded-r-lg border-l-4 border-emerald-500/80 bg-[rgba(16,185,129,0.05)] px-4 py-2.5 text-xs text-[#aaa] print:bg-slate-50 print:text-slate-700 print:border-slate-400">
                        {children}
                      </blockquote>
                    ),
                    p: ({ children }) => <p className="my-3 leading-relaxed text-[#ccc] print:text-slate-700">{children}</p>,
                    ul: ({ children }) => <ul className="my-3 pl-5 list-disc space-y-1 text-[#bbb] print:text-slate-700">{children}</ul>,
                    ol: ({ children }) => <ol className="my-3 pl-5 list-decimal space-y-1 text-[#bbb] print:text-slate-700">{children}</ol>,
                    li: ({ children }) => <li className="leading-relaxed">{children}</li>,
                    hr: () => <hr className="my-6 border-[#222] print:border-slate-300" />,
                  }}
                >
                  {reportMarkdown}
                </ReactMarkdown>
              </div>
            ) : (
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs text-[#888]">
                  <span>原始 Markdown 代码（适合复制到文档中心或 Issue）</span>
                  <span className="font-mono text-[#555]">{reportMarkdown.length} 字符</span>
                </div>
                <pre className="max-h-[650px] overflow-y-auto rounded-lg border border-[#222] bg-[#0c0c0c] p-4 font-mono text-xs leading-relaxed text-[#ddd] whitespace-pre-wrap">
                  {reportMarkdown}
                </pre>
              </div>
            )}

            {/* Print Footer */}
            <div className="report-print-footer print:block hidden text-center text-xs text-slate-400 pt-8 mt-8 border-t border-slate-200">
              <p>本报告由 Strix 自主安全渗透测试平台自动化生成 · 仅供授权安全合规团队评估与加固使用 · 严禁未授权传播</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
