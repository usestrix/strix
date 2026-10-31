package app

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
)

func TestParkedWaitSpins(t *testing.T) {
	model := New(nil)
	model.width, model.height, model.showSplash, model.ready = 130, 30, false, true
	model.snapshot = protocol.Snapshot{
		Agents: []protocol.Agent{{ID: "one", Name: "Agent", Status: "waiting"}},
		Events: []protocol.Event{{ID: "1", AgentID: "one", Type: "tool", Data: map[string]any{"tool_name": "wait_for_agents"}}},
	}
	model.resizeViewport()
	before := ansi.Strip(model.View())
	model.sweepFrame += 2
	if after := ansi.Strip(model.View()); strings.Contains(before, "○ waiting") || before == after {
		t.Fatalf("wait line did not spin:\n%s", before)
	}
}
