package app

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
)

func approvalModel(t *testing.T) Model {
	t.Helper()
	m := New(nil)
	m.width, m.height = 160, 45
	m.showSplash = false
	root := "root"
	m.snapshot.Agents = []protocol.Agent{
		{ID: "root", Name: "Strix", Status: "running"},
		{ID: "validator", Name: "SQLi validation agent", ParentID: &root, Status: "running"},
	}
	m.snapshot.Events = []protocol.Event{{ID: "chat", Type: "chat", AgentID: "validator", Data: map[string]any{
		"role": "assistant", "content": "Validating the database findings. Waiting for your approval before changing data.",
	}}}
	now := time.Date(2026, 1, 1, 20, 42, 0, 0, time.UTC)
	m.handleEnvelope(stateEnvelope(t, 1, protocol.Snapshot{
		ScanState: "running", Targets: []string{"shop.example.com pentest"},
		PendingApprovals: []protocol.Approval{{
			ID: "approval-1", AgentID: "validator", AgentName: "SQLi validation agent", Tool: "exec_command",
			Summary: `psql "$DATABASE_URL" -c 'DROP TABLE users;'`, Risk: 0.99, Category: "deletes_data",
			ExpiresAt: now.Add(252 * time.Second).Format(time.RFC3339),
		}},
	}))
	m.approvalNow = now
	m.selectedAgent = 1
	m.resizeViewport()
	return m
}

func TestApprovalPromptRenderAndDefaultBlock(t *testing.T) {
	m := approvalModel(t)
	m.snapshot.PendingApprovals = append(m.snapshot.PendingApprovals, protocol.Approval{ID: "second"})
	out := ansi.Strip(m.View())
	for _, want := range []string{
		"△ Run this command?", "SQLi validation agent", "DROP TABLE users;", "Deletes data",
		"Risk 99%", "blocks in 4:12", "Allow", "Block", "1 of 2", "←/→ choose · enter confirm · esc block",
		"waiting for approval",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	if m.modalChoice != 1 {
		t.Fatal("Block must be selected by default")
	}
}

func TestApprovalKeys(t *testing.T) {
	for _, tc := range []struct {
		name     string
		keys     []tea.KeyType
		approved bool
	}{
		{"default blocks", []tea.KeyType{tea.KeyEnter}, false},
		{"right allows", []tea.KeyType{tea.KeyRight, tea.KeyEnter}, true},
		{"escape blocks", []tea.KeyType{tea.KeyEsc}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := approvalModel(t)
			connection := &recordingConn{}
			m.client = newClient(connection)
			var command tea.Cmd
			for _, key := range tc.keys {
				next, cmd := m.Update(tea.KeyMsg{Type: key})
				m = next.(Model)
				command = cmd
			}
			envelope := commandFromCmd(t, command, connection)
			var payload struct {
				ID       string `json:"approval_id"`
				Approved bool   `json:"approved"`
			}
			if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
				t.Fatal(err)
			}
			if envelope.Type != "approval.decide" || payload.ID != "approval-1" || payload.Approved != tc.approved {
				t.Fatalf("unexpected decision: %s %+v", envelope.Type, payload)
			}
			if !m.approvalSending {
				t.Fatal("decision should suppress repeated submissions")
			}
		})
	}
}

func TestApprovalCountdownAndRemoteResolution(t *testing.T) {
	m := approvalModel(t)
	next, cmd := m.Update(approvalTickMsg(m.approvalNow.Add(time.Second)))
	m = next.(Model)
	if cmd == nil || !strings.Contains(ansi.Strip(m.approvalView()), "blocks in 4:11") {
		t.Fatal("countdown did not tick")
	}
	m.handleEnvelope(stateEnvelope(t, 2, protocol.Snapshot{ScanState: "running"}))
	if m.modal == modalApproval || strings.Contains(ansi.Strip(m.View()), "Run this command?") {
		t.Fatal("remote resolution must remove the prompt")
	}
}

func TestApprovalVariantsAndNextRequestResetsChoice(t *testing.T) {
	m := approvalModel(t)
	for tool, title := range map[string]string{"repeat_request": "Send this request?", "call_mcp": "Run this tool?"} {
		m.snapshot.PendingApprovals[0].Tool = tool
		if !strings.Contains(ansi.Strip(m.approvalView()), title) {
			t.Fatalf("missing title for %s", tool)
		}
	}
	m.modalChoice = 0
	m.snapshot.PendingApprovals[0].ID = "next"
	m.syncApprovalPrompt()
	if m.modalChoice != 1 || m.approvalID != "next" {
		t.Fatal("next approval must reset to Block")
	}
	m.snapshot.PendingApprovals[0].Summary = strings.Repeat("long-command-", 100)
	if !strings.Contains(ansi.Strip(m.approvalView()), "[summary truncated]") {
		t.Fatal("long summaries must be bounded")
	}
}

func TestApprovalCountAndSidebarBeyondProjectedRequests(t *testing.T) {
	m := approvalModel(t)
	m.snapshot.PendingApprovalCount = 20
	if !strings.Contains(ansi.Strip(m.approvalView()), "1 of 20") {
		t.Fatal("must show total count, not just the bounded projection size")
	}
	m.snapshot.Agents = nil
	for i := 0; i < 40; i++ {
		m.snapshot.Agents = append(m.snapshot.Agents, protocol.Agent{
			ID: fmt.Sprint(i), Name: fmt.Sprintf("agent-%02d", i), ApprovalPending: true,
		})
	}
	m.selectedAgent = 39
	m.ensureAgentVisible()
	out := ansi.Strip(m.agentsView(40, m.agentPageSize()))
	if !strings.Contains(out, "agent-39") || !strings.Contains(out, "waiting for approval") {
		t.Fatalf("pending rows must scroll with their agents:\n%s", out)
	}
}
