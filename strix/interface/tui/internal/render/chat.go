package render

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// Chat messages
// ---------------------------------------------------------------------------

// renderUserMessage ports UserMessageRenderer._format_user_message.
func renderUserMessage(content string) string {
	bar := Col(Blue).Render("▍")
	var b strings.Builder
	b.WriteString(bar + " " + lipgloss.NewStyle().Bold(true).Render("You:"))
	for _, line := range strings.Split(content, "\n") {
		b.WriteString("\n" + bar + " " + line)
	}
	return b.String()
}

// renderChat renders a chat event (assistant markdown or user message).
func Chat(data map[string]any) string {
	role, _ := data["role"].(string)
	content := StripControls(StringValue(data["content"]))
	if role == "user" {
		return renderUserMessage(content)
	}
	return renderAssistantMarkdown(content)
}
