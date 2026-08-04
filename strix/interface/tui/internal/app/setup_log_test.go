package app

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/usestrix/strix/tui/internal/protocol"
	"github.com/usestrix/strix/tui/internal/render"
)

// Retrying a launch that cannot succeed yet must not fill the log with copies of
// the same two lines.
func TestSetupLogCollapsesRepeatedAttempts(t *testing.T) {
	m := New(nil)
	m.snapshot.SetupMode = true
	for range 4 {
		m.setupMsg("Verifying model connection...", render.Col(amber))
		m.setupMsg("No model configured. Set STRIX_LLM first.", render.Col(red))
	}
	if got := len(m.setupLog); got != 2 {
		t.Fatalf("setup log holds %d lines after 4 identical attempts, want 2: %#v", got, m.setupLog)
	}
	// The newest line stays last so the log still reads chronologically.
	if !strings.Contains(m.setupLog[1], "No model configured") {
		t.Fatalf("most recent line is not last: %#v", m.setupLog)
	}
	m.setupMsg("\u2713 Added target: https://example.com", render.Col(green))
	if got := len(m.setupLog); got != 3 {
		t.Fatalf("a distinct line did not append: %#v", m.setupLog)
	}
}

// The same collapse must hold for the path a real misconfiguration takes: a
// failing setup.start arriving as a command_result.
func TestRepeatedSetupStartFailureLogsOnce(t *testing.T) {
	model, _ := newCommandTestModel(t)
	model.snapshot.SetupMode = true
	model.client.pending = map[string]string{}
	model.client.pendingByKey = map[string]string{}
	model.client.requestKeyByID = map[string]string{}
	for i := range 3 {
		requestID := "req-" + string(rune('a'+i))
		model.client.pending[requestID] = "setup.start"
		model.client.pendingByKey["setup.start"] = requestID
		model.client.requestKeyByID[requestID] = "setup.start"
		payload, err := json.Marshal(protocol.CommandResult{
			OK:      false,
			Command: "setup.start",
			Error: &protocol.CommandError{
				Code:    "invalid_state",
				Message: "No model configured. Set STRIX_LLM first.",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		model.handleEnvelope(protocol.Envelope{
			Version: protocol.Version, Type: "command_result", RequestID: requestID, Payload: payload,
		})
	}
	if got := len(model.setupLog); got != 1 {
		t.Fatalf("three identical launch failures logged %d lines, want 1: %#v", got, model.setupLog)
	}
}
