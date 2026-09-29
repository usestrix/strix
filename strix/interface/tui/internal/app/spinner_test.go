package app

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
)

func TestWaitSpinsOnlyWhileTheAgentIsParkedOnIt(t *testing.T) {
	wait := func(id string) protocol.Event {
		return protocol.Event{ID: id, AgentID: "one", Type: "tool", Timestamp: id, Data: map[string]any{"tool_name": "wait_for_agents"}}
	}
	for _, tc := range []struct {
		status string
		waits  int
		want   []string // per wait line: "spin" or "○"
	}{
		{"waiting", 1, []string{"spin"}},
		{"running", 1, []string{"○"}},
		{"waiting", 2, []string{"○", "spin"}},
	} {
		model := New(nil)
		model.width, model.height, model.showSplash, model.ready = 130, 30, false, true
		model.snapshot = protocol.Snapshot{Agents: []protocol.Agent{{ID: "one", Name: "Agent", Status: tc.status}}}
		for i := range tc.waits {
			model.snapshot.Events = append(model.snapshot.Events, wait(string(rune('1'+i))))
		}
		model.resizeViewport()
		lines := func() (out []string) {
			for _, line := range strings.Split(ansi.Strip(model.View()), "\n") {
				if strings.Contains(line, "waiting") {
					out = append(out, line)
				}
			}
			return out
		}
		before := lines()
		model.sweepFrame += 2
		after := lines()
		if len(before) != len(tc.want) {
			t.Fatalf("%+v: waiting lines = %q", tc, before)
		}
		for i, want := range tc.want {
			still := strings.Contains(before[i], "○ waiting") && before[i] == after[i]
			if spins := !strings.Contains(before[i], "○") && before[i] != after[i]; (want == "spin") != spins || (want == "○") != still {
				t.Fatalf("%+v: line %d want %s, got %q then %q", tc, i, want, before[i], after[i])
			}
		}
	}
}
