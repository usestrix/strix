package render

import "strings"

// ---------------------------------------------------------------------------
// Handing the turn to the user
// ---------------------------------------------------------------------------

// renderWaitForUser marks the agent parked for the user's reply. The call
// carries no text: whatever the agent had to say was already shown as its
// own prose.
func renderWaitForUser() string {
	return Col(Gray).Render("○ ") + Dim().Render("waiting for your reply")
}

// renderRespondToUser renders the retired respond_to_user call from recorded
// runs, whose message argument was the reply the user meant to read.
func renderRespondToUser(args map[string]any) string {
	var b strings.Builder
	if message := StringValue(args["message"]); message != "" {
		b.WriteString(renderAssistantMarkdown(message) + "\n\n")
	}
	b.WriteString(renderWaitForUser())
	return b.String()
}
