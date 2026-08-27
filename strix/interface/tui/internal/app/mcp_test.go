package app

import (
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
)

func mcpModel(t *testing.T) Model {
	t.Helper()
	m := New(nil)
	m.width, m.height = 130, 40
	m.showSplash = false
	m.handleEnvelope(stateEnvelope(t, 1, protocol.Snapshot{
		ScanState: "running",
		Connections: []protocol.Connection{
			{Name: "supabase", ToolCount: 3, Dead: false},
			{Name: "vercel", ToolCount: 1, Dead: true},
		},
	}))
	return m
}

func TestMcpPanelShowsHealthyAndOffline(t *testing.T) {
	m := mcpModel(t)
	out := ansi.Strip(m.mcpConnectionsView(40, 6))
	for _, want := range []string{"MCP Connections (2)", "supabase", "3 tools", "vercel", "offline"} {
		if !strings.Contains(out, want) {
			t.Fatalf("panel missing %q:\n%s", want, out)
		}
	}
}

// A roster longer than the panel height shows a window of rows rather than every
// connection, while the header keeps the full count.
func TestMcpPanelWindowsLargeRosterAndCountsAll(t *testing.T) {
	m := New(nil)
	m.width, m.height = 130, 40
	m.showSplash = false
	conns := make([]protocol.Connection, 0, 12)
	for i := 0; i < 12; i++ {
		conns = append(conns, protocol.Connection{Name: fmt.Sprintf("conn-%02d", i), ToolCount: 2})
	}
	m.snapshot.Connections = conns

	// rows = 6 → one header line + five roster rows.
	out := ansi.Strip(m.mcpConnectionsView(40, 6))
	if !strings.Contains(out, "MCP Connections (12)") {
		t.Fatalf("header did not carry the full connection count:\n%s", out)
	}
	if !strings.Contains(out, "conn-00") {
		t.Fatalf("top of the roster was not rendered:\n%s", out)
	}
	if strings.Contains(out, "conn-11") {
		t.Fatalf("a roster past the panel height should be windowed, not fully drawn:\n%s", out)
	}
	if got := strings.Count(out, "\n") + 1; got != 6 {
		t.Fatalf("panel rendered %d lines, want 6 (header + five rows)", got)
	}

	// Scrolling the roster brings the tail into view while the header count holds.
	m.mcpOffset = 7
	scrolled := ansi.Strip(m.mcpConnectionsView(40, 6))
	if !strings.Contains(scrolled, "conn-11") || !strings.Contains(scrolled, "MCP Connections (12)") {
		t.Fatalf("scrolled window did not reveal the tail with the count intact:\n%s", scrolled)
	}
}

func TestMcpPanelHeightReservedFromAgentBudget(t *testing.T) {
	m := mcpModel(t)
	_, _, mcpHeight, _ := m.sidebarHeights()
	if mcpHeight <= 0 {
		t.Fatalf("connections present but no panel height was reserved: %d", mcpHeight)
	}

	empty := New(nil)
	empty.width, empty.height = 130, 40
	empty.showSplash = false
	empty.handleEnvelope(stateEnvelope(t, 1, protocol.Snapshot{ScanState: "running"}))
	if _, _, emptyHeight, _ := empty.sidebarHeights(); emptyHeight != 0 {
		t.Fatalf("no connections should leave the panel absent, got height %d", emptyHeight)
	}
}

func TestMcpInUseReadsRunningConnectionTaggedCalls(t *testing.T) {
	m := mcpModel(t)
	m.handleEnvelope(bootstrapEnvelope(t, "events", 1,
		protocol.Event{ID: "e1", Type: "tool", AgentID: "a1", Data: map[string]any{
			"tool_name": "call_mcp", "mcp_connection": "supabase", "status": "running",
		}},
		protocol.Event{ID: "e2", Type: "tool", AgentID: "a1", Data: map[string]any{
			"tool_name": "call_mcp", "mcp_connection": "vercel", "status": "completed",
		}},
	))
	inUse := m.mcpInUse()
	if !inUse["supabase"] {
		t.Fatalf("a running connection-tagged call should mark the connection in use")
	}
	if inUse["vercel"] {
		t.Fatalf("a completed call must not mark the connection in use")
	}
}
