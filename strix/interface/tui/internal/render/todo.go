package render

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// Todos (todo_renderer.py)
// ---------------------------------------------------------------------------

var todoMarkers = map[string]string{"pending": "[ ]", "in_progress": "[~]", "done": "[•]"}

var todoTitles = map[string]struct {
	title   string
	color   lipgloss.Color
	loading string
	errMsg  string
}{
	"create_todo":       {"Todo", Lavender, "Creating...", "Failed to create todo"},
	"list_todos":        {"Todos", Lavender, "Loading...", "Unable to list todos"},
	"update_todo":       {"Todo Updated", Lavender, "Updating...", "Failed to update todo"},
	"mark_todo_done":    {"Todo Completed", Lavender, "Marking done...", "Failed to mark todo done"},
	"mark_todo_pending": {"Todo Reopened", AmberY, "Reopening...", "Failed to reopen todo"},
	"delete_todo":       {"Todo Removed", Slate, "Removing...", "Failed to remove todo"},
}

func renderTodo(name string, result any) string {
	meta := todoTitles[name]
	var b strings.Builder
	b.WriteString("📋 " + Bold(meta.color).Render(meta.title))
	if s, ok := result.(string); ok && strings.TrimSpace(s) != "" {
		b.WriteString("\n  " + Dim().Render(strings.TrimSpace(s)))
		return b.String()
	}
	if m, ok := result.(map[string]any); ok {
		if truthy(m["success"]) {
			formatTodoLines(&b, m)
		} else {
			errMsg := StringValue(m["error"])
			if errMsg == "" {
				errMsg = meta.errMsg
			}
			b.WriteString("\n  " + Col(Red).Render(errMsg))
		}
	} else {
		b.WriteString("\n  " + Dim().Render(meta.loading))
	}
	return b.String()
}

func formatTodoLines(b *strings.Builder, result map[string]any) {
	todos, ok := result["todos"].([]any)
	if !ok || len(todos) == 0 {
		b.WriteString("\n  " + Dim().Render("No todos"))
		return
	}
	for _, t := range todos {
		todo, _ := t.(map[string]any)
		status := StringValue(todo["status"])
		marker := todoMarkers[status]
		if marker == "" {
			marker = todoMarkers["pending"]
		}
		title := strings.TrimSpace(StringValue(todo["title"]))
		if title == "" {
			title = "(untitled)"
		}
		b.WriteString("\n  " + marker + " ")
		switch status {
		case "done":
			b.WriteString(Dim().Strikethrough(true).Render(title))
		case "in_progress":
			b.WriteString(lipgloss.NewStyle().Italic(true).Render(title))
		default:
			b.WriteString(title)
		}
	}
}
