package render

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// statusIcon ports BaseToolRenderer.status_icon.
func statusIcon(status string) (string, lipgloss.Style) {
	switch status {
	case "running":
		return "● In progress...", Col(AmberY)
	case "completed":
		return "✓ Done", Col(Green)
	case "failed":
		return "✗ Failed", Col(SevCrit)
	case "error":
		return "✗ Error", Col(SevCrit)
	}
	return "○ Unknown", Dim()
}

// renderGenericTool ports registry._render_default_tool_widget.
func renderGenericTool(name string, args map[string]any, result any, status string) string {
	var b strings.Builder
	b.WriteString(Dim().Render("→ Using tool ") + Bold(Blue).Render(name) + "\n")
	for _, k := range SortedKeys(args) {
		b.WriteString("  " + Dim().Render(k) + ": " + StringValue(args[k]) + "\n")
	}
	if (status == "completed" || status == "failed" || status == "error") && result != nil {
		b.WriteString(lipgloss.NewStyle().Bold(true).Render("Result: ") + StringValue(result))
	} else {
		icon, style := statusIcon(status)
		b.WriteString(style.Render(icon))
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

func Tool(data map[string]any) string {
	name := StringValue(data["tool_name"])
	status := StringValue(data["status"])
	args, _ := data["args"].(map[string]any)
	if args == nil {
		args = map[string]any{}
	}
	result := data["result"]

	switch name {
	case "exec_command":
		return renderExecCommand(args, result, status)
	case "write_stdin":
		return renderWriteStdin(args, result, status)
	case "apply_patch":
		return renderApplyPatch(args, result, status)
	case "view_image":
		return renderViewImage(args, result)
	case "create_vulnerability_report":
		return renderVulnerabilityReport(args, result)
	case "create_dependency_report":
		return renderDependencyReport(args, result)
	case "list_reports":
		return renderListReports(result)
	case "get_report":
		return renderGetReport(result)
	case "respond_to_user":
		return renderRespondToUser(args)
	case "finish_scan":
		return renderFinishScan(args)
	case "think":
		return renderThink(args)
	case "web_search":
		return renderWebSearch(args)
	case "load_skill":
		return renderLoadSkill(args, result)
	case "create_note", "delete_note", "update_note", "list_notes", "get_note":
		return renderNote(name, args, result)
	case "create_todo", "list_todos", "update_todo", "mark_todo_done", "mark_todo_pending", "delete_todo":
		return renderTodo(name, result)
	case "view_agent_graph", "create_agent", "send_message_to_agent", "agent_finish", "wait_for_agents", "stop_agent":
		return renderAgentGraphTool(name, args, result)
	case "list_requests", "view_request", "repeat_request", "list_sitemap", "view_sitemap_entry", "scope_rules":
		return renderProxyTool(name, args, result, status)
	}
	return renderGenericTool(name, args, result, status)
}
