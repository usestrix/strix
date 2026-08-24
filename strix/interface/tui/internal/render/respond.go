package render

import "strings"

// ---------------------------------------------------------------------------
// Direct replies (respond_renderer.py)
// ---------------------------------------------------------------------------

// renderRespondToUser shows the reply as the agent's own prose, since
// respond_to_user carries the message the user is meant to read.
func renderRespondToUser(args map[string]any) string {
	var b strings.Builder
	if message := StringValue(args["message"]); message != "" {
		b.WriteString(renderAssistantMarkdown(message) + "\n\n")
	}
	b.WriteString(Col(Gray).Render("○ ") + Dim().Render("waiting for your reply"))
	return b.String()
}
