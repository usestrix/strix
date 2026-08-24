package render

import (
	"strings"
)

// ---------------------------------------------------------------------------
// MCP tools (tools from the servers the user connected)
// ---------------------------------------------------------------------------

const mcpIcon = "🔌 "

// renderMcpTool renders a call to a tool from one of the user's MCP servers.
//
// Its own icon and color so a call that left Strix for a server the user
// connected is obvious while scrolling a transcript. The action leads and the
// server trails: the model-facing name is the connection name and the tool name
// stuck together, so leading with the whole name buries the part a reader wants
// behind a connection name that can be long or opaque.
//
// The result is deliberately not rendered, for the same reason
// renderGenericTool leaves it out: an MCP result is whatever an outside server
// chose to return, often multi-kilobyte JSON, and it floods the screen. The full
// result is in the event data, the run log, and the `strix view` viewer.
func renderMcpTool(connection, toolName string, args map[string]any, status string) string {
	var b strings.Builder
	b.WriteString(mcpIcon + Bold(Mint).Render(toolName))
	b.WriteString(Dim().Render("  via MCP server ") + Col(Slate).Render(connection) + "\n")
	for _, k := range SortedKeys(args) {
		b.WriteString("  " + Dim().Render(k) + ": " + StringValue(args[k]) + "\n")
	}
	icon, style := statusIcon(status)
	b.WriteString(style.Render(icon))
	return b.String()
}
