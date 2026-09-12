package render

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// Agents graph (agents_graph_renderer.py)
// ---------------------------------------------------------------------------

func renderAgentGraphTool(name string, args map[string]any, result any) string {
	var b strings.Builder
	switch name {
	case "view_agent_graph":
		b.WriteString(Col(Lavender).Render("◇ ") + Dim().Render("viewing agents graph"))
	case "create_agent":
		agentName := StringValue(args["name"])
		if agentName == "" {
			agentName = "Agent"
		}
		b.WriteString(Col(Lavender).Render("◈ ") + Dim().Render("spawning ") + Bold(Lavender).Render(agentName))
		if task := StringValue(args["task"]); task != "" {
			b.WriteString("\n  " + Dim().Render(task))
		}
	case "send_message_to_agent":
		b.WriteString(Col(InfoBlue).Render("→ "))
		if target := StringValue(args["target_agent_id"]); target != "" {
			b.WriteString(Dim().Render("to " + target))
		} else {
			b.WriteString(Dim().Render("sending message"))
		}
		if msg := StringValue(args["message"]); msg != "" {
			b.WriteString("\n  " + Dim().Render(msg))
		}
	case "agent_finish":
		success := true
		if v, ok := args["success"].(bool); ok {
			success = v
		}
		if success {
			b.WriteString(Col(Green).Render("◆ ") + Bold(Green).Render("Agent completed"))
		} else {
			b.WriteString(Col(Red).Render("◆ ") + Bold(Red).Render("Agent failed"))
		}
		if summary := StringValue(args["result_summary"]); summary != "" {
			b.WriteString("\n  " + lipgloss.NewStyle().Bold(true).Render(summary))
			if findings, ok := args["findings"].([]any); ok {
				for _, f := range findings {
					b.WriteString("\n  • " + Dim().Render(StringValue(f)))
				}
			}
		} else {
			b.WriteString("\n  " + Dim().Render("Completing task..."))
		}
	case "wait_for_agents":
		b.WriteString(Col(Gray).Render("○ ") + Dim().Render("waiting"))
		if reason := StringValue(args["reason"]); reason != "" {
			b.WriteString("\n  " + Dim().Render(reason))
		}
	case "stop_agent":
		b.WriteString(Col(Red).Render("◼ ") + Dim().Render("stopping"))
		if target := StringValue(args["target_agent_id"]); target != "" {
			b.WriteString(Bold(Red).Render(" " + target))
		}
		cascade := true
		if v, ok := args["cascade"].(bool); ok {
			cascade = v
		}
		if cascade {
			b.WriteString(Dim().Italic(true).Render(" + descendants"))
		}
		if reason := StringValue(args["reason"]); reason != "" {
			b.WriteString("\n  " + Dim().Render(reason))
		}
		if m, ok := result.(map[string]any); ok {
			if s, hs := m["success"].(bool); hs && !s {
				if e := StringValue(m["error"]); e != "" {
					b.WriteString("\n  " + Col(Red).Render(e))
				}
			}
		}
	}
	return b.String()
}
