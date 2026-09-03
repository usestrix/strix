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

// renderMcpInspect renders describe_mcp: a request to inspect one connection's
// catalog rather than a call to a tool on it. There is no underlying tool, so
// the connection is the whole subject and leads. Same icon and colors as a tool
// call so the two read as one family while scrolling a transcript.
func renderMcpInspect(connection, status string) string {
	var b strings.Builder
	b.WriteString(mcpIcon + Dim().Render("Inspecting MCP server ") + Bold(Mint).Render(connection) + "\n")
	icon, style := statusIcon(status)
	b.WriteString(style.Render(icon))
	return b.String()
}

// renderMcpList renders list_mcps: the inventory of connections the run may
// reach, not a call to any of them, so no connection leads and the event
// carries no connection tag. Unlike the other MCP results, the names are worth
// showing: Strix assembled them itself from the run's registered connections,
// so they are short and never an outside server's payload.
func renderMcpList(result any, status string) string {
	var b strings.Builder
	b.WriteString(mcpIcon + Dim().Render("Listing MCP servers") + "\n")
	for _, conn := range mcpConnectionEntries(result) {
		b.WriteString("  " + Col(Slate).Render(conn.name))
		if conn.dead {
			b.WriteString(Dim().Render(" · ") + Col(Red).Render("offline"))
		}
		b.WriteString("\n")
	}
	icon, style := statusIcon(status)
	b.WriteString(style.Render(icon))
	return b.String()
}

// mcpListEntry is one connection read out of a list_mcps result: its display
// name and whether its live session has died.
type mcpListEntry struct {
	name string
	dead bool
}

// mcpConnectionEntries reads the connections out of a list_mcps result, which is
// {"connections": [{"name": ..., "dead": ...}, ...]}. Anything else (still
// running, or a result bounded down to a string) yields no entries, and the
// header plus status stand alone.
func mcpConnectionEntries(result any) []mcpListEntry {
	resultMap, _ := result.(map[string]any)
	connections, _ := resultMap["connections"].([]any)
	var entries []mcpListEntry
	for _, raw := range connections {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if name := strings.TrimSpace(StringValue(entry["name"])); name != "" {
			dead, _ := entry["dead"].(bool)
			entries = append(entries, mcpListEntry{name: name, dead: dead})
		}
	}
	return entries
}
