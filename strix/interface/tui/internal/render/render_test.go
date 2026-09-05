package render

import (
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func tool(name string, args map[string]any, result any, status string) map[string]any {
	data := map[string]any{"tool_name": name, "status": status}
	if args != nil {
		data["args"] = args
	}
	if result != nil {
		data["result"] = result
	}
	return data
}

func requireContains(t *testing.T, output string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}

func TestChatUserMessage(t *testing.T) {
	out := Chat(map[string]any{"role": "user", "content": "hello\nworld"})
	requireContains(t, out, "You:", "hello", "world")
}

func TestChatAssistantMarkdown(t *testing.T) {
	out := Chat(map[string]any{"role": "assistant", "content": "# Heading\n\nSome **bold** text"})
	requireContains(t, out, "Heading", "bold")
}

func TestExecCommandHighlightsCommand(t *testing.T) {
	out := Tool(tool("exec_command", map[string]any{"cmd": "for f in *.py; do echo \"$f\"; done"}, nil, "running"))
	if !strings.Contains(out, "\x1b[38;5;") {
		t.Fatalf("expected syntax-highlighted command:\n%q", out)
	}
}

func TestApplyPatchHighlightsCode(t *testing.T) {
	out := Tool(tool("apply_patch", map[string]any{
		"patch": "*** Update File: src/app.py\n-import os\n+import sys\n+def main():\n+    return sys.argv",
	}, nil, "completed"))
	if !strings.Contains(out, "\x1b[38;5;") {
		t.Fatalf("expected syntax-highlighted patch lines:\n%q", out)
	}
	lines := strings.Split(out, "\n")
	if len(lines) != 5 {
		t.Fatalf("diff line structure must survive highlighting, got %d lines:\n%q", len(lines), out)
	}
}

func TestToolDispatchCoversKnownTools(t *testing.T) {
	cases := []struct {
		name  string
		data  map[string]any
		wants []string
	}{
		{
			"exec_command",
			tool("exec_command", map[string]any{"cmd": "ls -la"}, nil, "running"),
			[]string{"ls -la"},
		},
		{
			"write_stdin",
			tool("write_stdin", map[string]any{"chars": "y", "session_id": 3}, nil, "completed"),
			[]string{"y", "session #3"},
		},
		{
			"apply_patch",
			tool("apply_patch", map[string]any{
				"file_path": "src/app.py",
				"patch":     "*** Update File: src/app.py\n+new line",
			}, nil, "completed"),
			[]string{"src/app.py"},
		},
		{
			"view_image",
			tool("view_image", map[string]any{"path": "shot.png"}, nil, "completed"),
			[]string{"shot.png"},
		},
		{
			"create_vulnerability_report",
			tool("create_vulnerability_report",
				map[string]any{"title": "SQL injection in login", "target": "https://x.test"},
				map[string]any{"severity": "critical", "cvss_score": 9.8},
				"completed"),
			[]string{"Vulnerability Report", "SQL injection in login", "CRITICAL", "9.8"},
		},
		{
			"create_dependency_report",
			tool("create_dependency_report",
				map[string]any{"package_name": "requests", "installed_version": "2.0.0"},
				nil, "completed"),
			[]string{"requests"},
		},
		{
			"list_reports",
			tool("list_reports", nil, map[string]any{
				"success":         true,
				"total_count":     2,
				"severity_counts": map[string]any{"critical": 1, "low": 1},
				"reports": []any{
					map[string]any{"id": "VULN-1", "title": "SQLi", "severity": "critical", "by_you": true},
					map[string]any{"id": "VULN-2", "title": "Weak header", "severity": "low", "agent_name": "recon"},
				},
			}, "completed"),
			[]string{"reports", "(2)", "CRITICAL", "VULN-1", "SQLi", "(you)", "LOW", "VULN-2", "(recon)"},
		},
		{
			"list_reports empty",
			tool("list_reports", nil, map[string]any{"success": true, "total_count": 0}, "completed"),
			[]string{"reports", "(0)", "No reports filed yet"},
		},
		{
			"get_report",
			tool("get_report", nil, map[string]any{
				"success": true,
				"report": map[string]any{
					"id": "VULN-1", "title": "SQLi", "severity": "high", "target": "https://x.test",
				},
			}, "completed"),
			[]string{"report read", "HIGH", "VULN-1", "SQLi", "https://x.test"},
		},
		{
			"get_report error",
			tool("get_report", nil, map[string]any{"success": false, "error": "not found"}, "failed"),
			[]string{"report read", "not found"},
		},
		{
			"respond_to_user",
			tool("respond_to_user", map[string]any{"message": "Here is the answer"}, nil, "completed"),
			[]string{"Here is the answer", "waiting for your reply"},
		},
		{
			"finish_scan",
			tool("finish_scan", map[string]any{"executive_summary": "All done"}, nil, "completed"),
			[]string{"Penetration test completed", "All done"},
		},
		{
			"think",
			tool("think", map[string]any{"thought": "checking auth flow"}, nil, "running"),
			[]string{"Thinking", "checking auth flow"},
		},
		{
			"web_search",
			tool("web_search", map[string]any{"query": "CVE-2024-1234"}, nil, "running"),
			[]string{"Searching the web", "CVE-2024-1234"},
		},
		{
			"load_skill",
			tool("load_skill", map[string]any{"skills": []any{"sqli"}}, nil, "completed"),
			[]string{"sqli"},
		},
		{
			"create_note",
			tool("create_note", map[string]any{"title": "Recon findings"}, nil, "completed"),
			[]string{"Recon findings"},
		},
		{
			"create_todo",
			tool("create_todo", nil, map[string]any{
				"success": true,
				"todos": []any{
					map[string]any{"id": 1, "title": "Check login", "status": "pending"},
				},
			}, "completed"),
			[]string{"Check login"},
		},
		{
			"create_agent",
			tool("create_agent", map[string]any{"name": "ReconAgent", "task": "map the site"}, nil, "running"),
			[]string{"spawning", "ReconAgent", "map the site"},
		},
		{
			"wait_for_agents",
			tool("wait_for_agents", map[string]any{"reason": "results needed"}, nil, "running"),
			[]string{"waiting", "results needed"},
		},
		{
			"stop_agent",
			tool("stop_agent", map[string]any{"target_agent_id": "agent-2"}, nil, "completed"),
			[]string{"stopping", "agent-2"},
		},
		{
			"view_agent_graph",
			tool("view_agent_graph", nil, nil, "completed"),
			[]string{"viewing agents graph"},
		},
		{
			"list_requests",
			tool("list_requests", map[string]any{"httpql_filter": "host:example.com"}, nil, "completed"),
			[]string{"host:example.com"},
		},
		{
			"unknown tool falls back to generic",
			tool("brand_new_tool", map[string]any{"alpha": "1"}, "done", "completed"),
			[]string{"brand_new_tool", "alpha", "Done"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireContains(t, Tool(tc.data), tc.wants...)
		})
	}
}

func TestGenericToolOmitsRawResult(t *testing.T) {
	// The generic renderer shows tool name, args, and a status line only, never
	// the raw result payload.
	long := strings.Repeat("x", 5000)
	out := ansi.Strip(Tool(tool("db_query", map[string]any{"query": "select 1"}, long, "completed")))

	requireContains(t, out, "db_query", "query", "Done")
	if strings.Contains(out, "Result:") || strings.Contains(out, strings.Repeat("x", 20)) {
		t.Fatalf("generic result body must not be rendered:\n%s", out)
	}
}

func TestMcpToolLeadsWithActionAndNamesTheServer(t *testing.T) {
	// call_mcp is the dispatch tool; the connection and the server's own tool
	// name are tagged onto the event from its arguments.
	data := tool("call_mcp", map[string]any{"path": "/etc/hosts"}, "file body", "completed")
	data["mcp_connection"] = "local_fs"
	data["mcp_tool"] = "read_file"

	out := ansi.Strip(Tool(data))

	// The action leads; the server is context that trails it.
	if !strings.HasPrefix(out, mcpIcon+"read_file") {
		t.Fatalf("MCP render must lead with the tool's own name:\n%s", out)
	}
	requireContains(t, out, "local_fs", "path", "/etc/hosts", "Done")
	// Untrusted server output stays off the terminal, as for the generic render.
	if strings.Contains(out, "file body") {
		t.Fatalf("MCP result body must not be rendered:\n%s", out)
	}
}

func TestMcpToolWithoutTaggedToolFallsBackToDispatchName(t *testing.T) {
	// A call_mcp whose underlying tool could not be read still renders as an MCP
	// row, falling back to the dispatch tool name.
	data := tool("call_mcp", nil, nil, "running")
	data["mcp_connection"] = "local_fs"

	requireContains(t, ansi.Strip(Tool(data)), mcpIcon+"call_mcp", "local_fs", "In progress")
}

func TestMcpDescribeInspectsConnection(t *testing.T) {
	// describe_mcp inspects a connection; the connection is the subject and the
	// dispatch tool name is not shown as if it were a server tool.
	data := tool("describe_mcp", nil, nil, "completed")
	data["mcp_connection"] = "local_fs"

	out := ansi.Strip(Tool(data))
	requireContains(t, out, mcpIcon, "Inspecting MCP server", "local_fs", "Done")
	if strings.Contains(out, "describe_mcp") {
		t.Fatalf("describe_mcp must read as inspecting the connection, not name the dispatch tool:\n%s", out)
	}
}

func TestMcpListMarksDeadConnectionsOffline(t *testing.T) {
	// list_mcps carries a per-connection dead flag; a dead connection reads as
	// offline in the inventory while a live one shows normally.
	result := map[string]any{
		"connections": []any{
			map[string]any{"name": "supabase", "tool_count": float64(3), "dead": false},
			map[string]any{"name": "vercel", "tool_count": float64(1), "dead": true},
		},
	}
	data := tool("list_mcps", nil, result, "completed")

	out := ansi.Strip(Tool(data))
	requireContains(t, out, "Listing MCP servers", "supabase", "vercel", "offline")
	if strings.Count(out, "offline") != 1 {
		t.Fatalf("only the dead connection should read offline:\n%s", out)
	}
}

func TestCollapseToolShellPreviewAndExpand(t *testing.T) {
	lines := make([]string, 16)
	for i := range lines {
		lines[i] = fmt.Sprintf("line %d", i)
	}
	full := strings.Join(lines, "\n")

	collapsed, expandable := CollapseTool(full, "exec_command", false)
	if !expandable {
		t.Fatal("long shell output should be expandable")
	}
	got := strings.Split(ansi.Strip(collapsed), "\n")
	if len(got) != 11 || !strings.Contains(got[10], "+6 lines — click to expand") {
		t.Fatalf("collapsed shell preview wrong: %q", got)
	}

	expanded, expandable := CollapseTool(full, "exec_command", true)
	if !expandable || !strings.Contains(ansi.Strip(expanded), full) ||
		!strings.Contains(ansi.Strip(expanded), "click to collapse") {
		t.Fatalf("expanded render wrong: %q", expanded)
	}
}

func TestCollapseToolOnlyOutputHeavyTools(t *testing.T) {
	full := "🧠 Thinking\n  a long private thought\n  spanning lines"
	if out, expandable := CollapseTool(full, "think", false); expandable || out != full {
		t.Fatal("think must never collapse")
	}
	if _, expandable := CollapseTool("short", "exec_command", false); expandable {
		t.Fatal("short output must not be expandable")
	}
	if out, expandable := CollapseTool(full, "respond_to_user", false); expandable || out != full {
		t.Fatal("respond_to_user must never collapse")
	}
}
