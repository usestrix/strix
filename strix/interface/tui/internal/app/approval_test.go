package app

import (
	"encoding/json"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
)

func approval(requestID, action, reason string) *protocol.SafetyApproval {
	return approvalFor("agent-1", requestID, action, reason)
}

func approvalFor(agentID, requestID, action, reason string) *protocol.SafetyApproval {
	return &protocol.SafetyApproval{AgentID: agentID, RequestID: requestID, Action: action, Reason: reason}
}

func approvalSet(items ...*protocol.SafetyApproval) []protocol.SafetyApproval {
	result := make([]protocol.SafetyApproval, 0, len(items))
	for _, item := range items {
		result = append(result, *item)
	}
	return result
}

func approvalAgents() []protocol.Agent {
	return []protocol.Agent{
		{ID: "agent-1", Name: "Agent One", Status: "running"},
		{ID: "agent-2", Name: "Agent Two", Status: "running"},
	}
}

func TestSafetyApprovalPromptFollowsSnapshotAndDefaultsToDeny(t *testing.T) {
	model := New(nil)
	model.width, model.height = 130, 40
	model.ready = true
	model.showSplash = false
	model.snapshot.Agents = approvalAgents()

	model.handleEnvelope(stateEnvelope(t, 1, protocol.Snapshot{
		ScanState:        "running",
		PendingApprovals: approvalSet(approval("approval-1", `{"cmd":"Run  exploit"}`, "This changes target state")),
	}))
	if model.modal != modalSafetyApproval || model.modalChoice != 1 {
		t.Fatalf("approval did not open fail-closed: modal=%v choice=%d", model.modal, model.modalChoice)
	}
	view := ansi.Strip(model.safetyApprovalView())
	for _, want := range []string{`Run  exploit`, "This changes target state", "Approve", "Deny"} {
		if !strings.Contains(view, want) {
			t.Fatalf("approval prompt is missing %q: %s", want, view)
		}
	}
	if rows := strings.Count(view, "\n") + 1; rows > 8 {
		t.Fatalf("approval prompt should stay compact, got %d rows:\n%s", rows, view)
	}

	// A newly dequeued request reuses the modal but must reset to Deny.
	model.modalChoice = 0
	model.handleEnvelope(stateEnvelope(t, 2, protocol.Snapshot{
		ScanState:        "running",
		PendingApprovals: approvalSet(approval("approval-2", "Write file", "This changes the workspace")),
	}))
	if model.modal != modalSafetyApproval || model.modalChoice != 1 || model.safetyApprovalID != "approval-2" {
		t.Fatalf("next approval did not reset: modal=%v choice=%d id=%q", model.modal, model.modalChoice, model.safetyApprovalID)
	}

	model.handleEnvelope(stateEnvelope(t, 3, protocol.Snapshot{ScanState: "running"}))
	if model.modal != modalNone {
		t.Fatalf("cleared approval left modal open: %v", model.modal)
	}
}

func TestSafetyApprovalExpandsAndOmitsInternalIdentifiers(t *testing.T) {
	model := New(nil)
	model.width, model.height = 130, 40
	model.ready = true
	model.snapshot.Agents = approvalAgents()
	model.snapshot.PendingApprovals = []protocol.SafetyApproval{{
		AgentID: "agent-1", RequestID: "req-1", ToolName: "exec_command", Risk: "high",
		Digest: "deadbeefcafef00d",
		Action: "curl -X POST https://target.example/api -d @payload.json",
		Reason: "The request writes to the target and may change its state.",
	}}
	model.openModal(modalSafetyApproval)

	collapsed := ansi.Strip(model.safetyApprovalView())
	for _, leak := range []string{"deadbeefcafef00d", "req-1", "agent-1"} {
		if strings.Contains(collapsed, leak) {
			t.Fatalf("collapsed prompt leaked internal id %q: %s", leak, collapsed)
		}
	}
	for _, want := range []string{"HIGH", "exec_command", "expand"} {
		if !strings.Contains(collapsed, want) {
			t.Fatalf("collapsed prompt missing %q: %s", want, collapsed)
		}
	}
	if strings.Contains(collapsed, "Command") {
		t.Fatalf("collapsed prompt should not show the expanded labels: %s", collapsed)
	}

	updated, _ := model.updateModal(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	model = updated.(Model)
	if !model.safetyApprovalExpanded {
		t.Fatal("e did not expand the prompt")
	}
	expanded := ansi.Strip(model.safetyApprovalView())
	for _, want := range []string{"Command", "Why", "payload.json", "change its state", "collapse"} {
		if !strings.Contains(expanded, want) {
			t.Fatalf("expanded prompt missing %q: %s", want, expanded)
		}
	}
	if strings.Contains(expanded, "deadbeefcafef00d") {
		t.Fatalf("expanded prompt leaked the digest: %s", expanded)
	}
}

func TestSafetyApprovalExpandedScrollsWithVerticalKeys(t *testing.T) {
	model := New(nil)
	model.width, model.height = 80, 14
	model.ready = true
	model.snapshot.Agents = approvalAgents()
	model.snapshot.PendingApprovals = []protocol.SafetyApproval{{
		AgentID: "agent-1", RequestID: "r", ToolName: "exec_command", Risk: "high",
		Action: "echo hi",
		Reason: strings.Repeat("This is a long reason line that wraps repeatedly. ", 40),
	}}
	model.openModal(modalSafetyApproval)
	updated, _ := model.updateModal(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	model = updated.(Model)

	maxScroll := model.clampApprovalScroll(1 << 20)
	if maxScroll == 0 {
		t.Fatalf("expected long content to scroll (viewport=%d)", model.approvalViewportHeight())
	}

	choiceBefore := model.modalChoice
	updated, _ = model.updateModal(tea.KeyMsg{Type: tea.KeyDown})
	model = updated.(Model)
	if model.safetyApprovalScroll != 1 {
		t.Fatalf("down did not scroll the detail: %d", model.safetyApprovalScroll)
	}
	if model.modalChoice != choiceBefore {
		t.Fatal("down moved button focus instead of scrolling while expanded")
	}

	updated, _ = model.updateModal(tea.KeyMsg{Type: tea.KeyEnd})
	model = updated.(Model)
	if model.safetyApprovalScroll != maxScroll {
		t.Fatalf("end did not jump to the bottom: %d != %d", model.safetyApprovalScroll, maxScroll)
	}

	// Horizontal keys still move between the buttons while expanded.
	updated, _ = model.updateModal(tea.KeyMsg{Type: tea.KeyLeft})
	model = updated.(Model)
	if model.modalChoice == choiceBefore {
		t.Fatal("left did not move button focus while expanded")
	}
}

func TestScrollWindow(t *testing.T) {
	lines := []string{"a", "b", "c", "d", "e"}
	if w, above, below := scrollWindow(lines, 0, 10); len(w) != 5 || above || below {
		t.Fatalf("fit case: %v above=%v below=%v", w, above, below)
	}
	if w, above, below := scrollWindow(lines, 0, 2); w[0] != "a" || above || !below {
		t.Fatalf("top window: %v above=%v below=%v", w, above, below)
	}
	if w, above, below := scrollWindow(lines, 1, 2); w[0] != "b" || !above || !below {
		t.Fatalf("middle window: %v above=%v below=%v", w, above, below)
	}
	if w, above, below := scrollWindow(lines, 99, 2); w[0] != "d" || !above || below {
		t.Fatalf("clamped-bottom window: %v above=%v below=%v", w, above, below)
	}
}

func TestSafetyApprovalKeyboardSendsExactPayload(t *testing.T) {
	for _, tc := range []struct {
		name     string
		key      tea.KeyMsg
		choice   int
		approved bool
	}{
		{name: "approve selected", key: tea.KeyMsg{Type: tea.KeyEnter}, choice: 0, approved: true},
		{name: "deny default", key: tea.KeyMsg{Type: tea.KeyEnter}, choice: 1, approved: false},
		{name: "escape denies", key: tea.KeyMsg{Type: tea.KeyEsc}, choice: 0, approved: false},
		{name: "approve shortcut", key: tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}}, choice: 1, approved: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connection := &recordingConn{}
			model := New(&Client{conn: connection})
			model.width, model.height = 130, 40
			model.snapshot.Agents = approvalAgents()
			model.snapshot.PendingApprovals = approvalSet(approval("approval-exact", "Action", "Reason"))
			model.openModal(modalSafetyApproval)
			model.modalChoice = tc.choice

			updated, cmd := model.updateModal(tc.key)
			model = updated.(Model)
			envelope := commandFromCmd(t, cmd, connection)
			if envelope.Type != "safety.resolve" {
				t.Fatalf("command = %q, want safety.resolve", envelope.Type)
			}
			var payload struct {
				RequestID string `json:"request_id"`
				Approved  bool   `json:"approved"`
			}
			if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
				t.Fatal(err)
			}
			if payload.RequestID != "approval-exact" || payload.Approved != tc.approved {
				t.Fatalf("payload = %#v, want id=%q approved=%v", payload, "approval-exact", tc.approved)
			}
			if model.modal != modalSafetyApproval {
				t.Fatalf("approval closed before backend state cleared it: %v", model.modal)
			}
		})
	}
}

func TestSafetyApprovalMouseButtonsSendPayload(t *testing.T) {
	for _, tc := range []struct {
		label    string
		approved bool
	}{
		{label: "Approve", approved: true},
		{label: "Deny", approved: false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			connection := &recordingConn{}
			model := New(&Client{conn: connection})
			model.width, model.height = 130, 40
			model.ready = true
			model.snapshot.Agents = approvalAgents()
			model.snapshot.PendingApprovals = approvalSet(approval("approval-mouse", "Action", "Reason"))
			model.openModal(modalSafetyApproval)
			view := model.modalView()
			left, top, _, _ := model.cornerViewBounds(view)
			x, y := -1, -1
			for row, line := range strings.Split(view, "\n") {
				plain := ansi.Strip(line)
				if index := strings.Index(plain, tc.label); index >= 0 {
					x = left + ansi.StringWidth(plain[:index])
					y = top + row
					break
				}
			}
			if x < 0 {
				t.Fatalf("button %q was not rendered", tc.label)
			}

			updated, cmd := model.updateModalMouse(tea.MouseMsg{
				X: x, Y: y, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress,
			})
			model = updated.(Model)
			envelope := commandFromCmd(t, cmd, connection)
			var payload struct {
				RequestID string `json:"request_id"`
				Approved  bool   `json:"approved"`
			}
			if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
				t.Fatal(err)
			}
			if payload.RequestID != "approval-mouse" || payload.Approved != tc.approved {
				t.Fatalf("payload = %#v", payload)
			}
		})
	}
}

func TestSafetyApproveAllSendsDangerousPayload(t *testing.T) {
	for _, tc := range []struct {
		name   string
		key    tea.KeyMsg
		choice int
	}{
		{name: "shortcut", key: tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'A'}}, choice: 1},
		{name: "enter on button", key: tea.KeyMsg{Type: tea.KeyEnter}, choice: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connection := &recordingConn{}
			model := New(&Client{conn: connection})
			model.width, model.height = 130, 40
			model.snapshot.Agents = approvalAgents()
			model.snapshot.PendingApprovals = approvalSet(approval("approval-all", "Action", "Reason"))
			model.openModal(modalSafetyApproval)
			model.modalChoice = tc.choice

			updated, cmd := model.updateModal(tc.key)
			model = updated.(Model)
			envelope := commandFromCmd(t, cmd, connection)
			if envelope.Type != "safety.resolve" {
				t.Fatalf("command = %q, want safety.resolve", envelope.Type)
			}
			var payload struct {
				RequestID  string `json:"request_id"`
				Approved   bool   `json:"approved"`
				ApproveAll bool   `json:"approve_all"`
			}
			if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
				t.Fatal(err)
			}
			if payload.RequestID != "approval-all" || !payload.Approved || !payload.ApproveAll {
				t.Fatalf("payload = %#v, want approved and approve_all", payload)
			}
		})
	}
}

func TestSafetyApproveAllMouseButtonSendsDangerousPayload(t *testing.T) {
	connection := &recordingConn{}
	model := New(&Client{conn: connection})
	model.width, model.height = 130, 40
	model.ready = true
	model.snapshot.Agents = approvalAgents()
	model.snapshot.PendingApprovals = approvalSet(approval("approval-all-mouse", "Action", "Reason"))
	model.openModal(modalSafetyApproval)
	view := model.modalView()
	left, top, _, _ := model.cornerViewBounds(view)
	x, y := -1, -1
	for row, line := range strings.Split(view, "\n") {
		plain := ansi.Strip(line)
		if index := strings.Index(plain, "Approve All"); index >= 0 {
			x = left + ansi.StringWidth(plain[:index])
			y = top + row
			break
		}
	}
	if x < 0 {
		t.Fatal("Approve All button was not rendered")
	}

	updated, cmd := model.updateModalMouse(tea.MouseMsg{
		X: x, Y: y, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress,
	})
	_ = updated.(Model)
	envelope := commandFromCmd(t, cmd, connection)
	var payload struct {
		RequestID  string `json:"request_id"`
		Approved   bool   `json:"approved"`
		ApproveAll bool   `json:"approve_all"`
	}
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.RequestID != "approval-all-mouse" || !payload.Approved || !payload.ApproveAll {
		t.Fatalf("payload = %#v, want approved and approve_all", payload)
	}
}

func TestSafetyApprovalDoesNotTrapQuitKeys(t *testing.T) {
	for _, key := range []tea.KeyMsg{
		{Type: tea.KeyCtrlC},
		{Type: tea.KeyCtrlQ},
	} {
		connection := &recordingConn{}
		model := New(&Client{conn: connection})
		model.snapshot.Agents = approvalAgents()
		model.snapshot.PendingApprovals = approvalSet(approval("approval-quit", "Action", "Reason"))
		model.openModal(modalSafetyApproval)

		updated, _ := model.updateModal(key)
		model = updated.(Model)
		if model.modal != modalQuit || model.modalChoice != 1 {
			t.Fatalf("quit key did not open fail-closed quit confirmation: modal=%v choice=%d", model.modal, model.modalChoice)
		}
		model.handleEnvelope(stateEnvelope(t, 1, protocol.Snapshot{
			ScanState:        "running",
			PendingApprovals: approvalSet(approval("approval-quit", "Action", "Reason")),
		}))
		if model.modal != modalQuit {
			t.Fatalf("state refresh displaced quit confirmation: modal=%v", model.modal)
		}

		// Declining quit must restore the still-pending approval.
		updated, _ = model.updateModal(tea.KeyMsg{Type: tea.KeyEnter})
		model = updated.(Model)
		if model.modal != modalSafetyApproval || model.modalChoice != 1 {
			t.Fatalf("declining quit did not restore approval: modal=%v choice=%d", model.modal, model.modalChoice)
		}
	}
}

func TestQueuedSafetyResolutionsUseDistinctPendingKeys(t *testing.T) {
	first := pendingKey("safety.resolve", json.RawMessage(`{"request_id":"approval-1","approved":true}`))
	opposite := pendingKey("safety.resolve", json.RawMessage(`{"request_id":"approval-1","approved":false}`))
	second := pendingKey("safety.resolve", json.RawMessage(`{"request_id":"approval-2","approved":true}`))
	if first != opposite {
		t.Fatal("opposite answers for one safety request use different pending keys")
	}
	if first == second {
		t.Fatal("queued safety resolutions share one pending command key")
	}
}

func TestSafetyApprovalDisablesApproveWhenExactContentDoesNotFit(t *testing.T) {
	connection := &recordingConn{}
	model := New(&Client{conn: connection})
	model.width, model.height = 32, 10
	model.snapshot.Agents = approvalAgents()
	model.snapshot.PendingApprovals = approvalSet(approval("approval-small", strings.Repeat("x", 300), strings.Repeat("reason ", 20)))
	model.openModal(modalSafetyApproval)
	model.modalChoice = 0

	if model.safetyApprovalFits() {
		t.Fatal("oversized approval unexpectedly fits the terminal")
	}
	if view := ansi.Strip(model.safetyApprovalView()); !strings.Contains(view, "Approval is disabled") {
		t.Fatalf("small-terminal warning missing: %s", view)
	}
	updated, cmd := model.updateModal(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if cmd != nil {
		t.Fatal("approval command was sent without displaying exact content")
	}
	if !strings.Contains(model.errorText, "Resize the terminal") {
		t.Fatalf("missing resize guidance: %q", model.errorText)
	}
}

func TestSafetyApprovalFollowsSelectedOwnerAndAllowsKeyboardNavigation(t *testing.T) {
	model := New(nil)
	model.width, model.height = 130, 40
	model.ready = true
	model.showSplash = false
	model.snapshot.Agents = approvalAgents()
	model.snapshot.PendingApprovals = approvalSet(approvalFor("agent-2", "approval-owner", "Action", "Reason"))

	model.syncSafetyApprovalPrompt()
	if model.modal != modalNone {
		t.Fatalf("approval appeared for unselected owner: %v", model.modal)
	}
	model.focus = focusAgents
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyDown})
	model = updated.(Model)
	if model.modal != modalSafetyApproval || model.modalChoice != 1 {
		t.Fatalf("selected owner did not open approval: modal=%v choice=%d", model.modal, model.modalChoice)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyUp})
	model = updated.(Model)
	if model.selectedAgent != 0 || model.modal != modalNone {
		t.Fatalf("keyboard navigation stayed trapped: selected=%d modal=%v", model.selectedAgent, model.modal)
	}

	model.selectedAgent = 1
	model.syncSafetyApprovalPrompt()
	if model.modalChoice != 1 {
		t.Fatalf("reopened approval did not default to deny: %d", model.modalChoice)
	}
}

func TestConcurrentApprovalsRemainVisibleOnTheirOwnerScreens(t *testing.T) {
	model := New(nil)
	model.width, model.height = 130, 40
	model.ready = true
	model.showSplash = false
	model.snapshot.Agents = approvalAgents()
	model.snapshot.PendingApprovals = approvalSet(
		approvalFor("agent-1", "approval-agent-1", "First action", "First reason"),
		approvalFor("agent-2", "approval-agent-2", "Second action", "Second reason"),
	)

	model.syncSafetyApprovalPrompt()
	if pending := model.pendingApprovalForSelectedAgent(); pending == nil || pending.RequestID != "approval-agent-1" {
		t.Fatalf("agent one approval missing: %#v", pending)
	}
	view := ansi.Strip(model.agentsView(60, 10))
	for _, name := range []string{"Agent One", "Agent Two"} {
		lineFound := false
		for _, line := range strings.Split(view, "\n") {
			if strings.Contains(line, name) {
				lineFound = true
				if !strings.Contains(line, "🟡") {
					t.Fatalf("%s is missing approval indicator: %q", name, line)
				}
			}
		}
		if !lineFound {
			t.Fatalf("agent row not found for %s", name)
		}
	}

	model.selectedAgent = 1
	model.syncSafetyApprovalPrompt()
	if pending := model.pendingApprovalForSelectedAgent(); pending == nil || pending.RequestID != "approval-agent-2" {
		t.Fatalf("agent two approval missing: %#v", pending)
	}
	if model.safetyApprovalID != "approval-agent-2" || model.modalChoice != 1 {
		t.Fatalf("agent two prompt did not activate: id=%q choice=%d", model.safetyApprovalID, model.modalChoice)
	}
}

func TestSafetyApprovalAllowsMouseAgentSelection(t *testing.T) {
	model := New(nil)
	model.width, model.height = 130, 40
	model.ready = true
	model.showSplash = false
	model.snapshot.Agents = approvalAgents()
	model.snapshot.PendingApprovals = approvalSet(approvalFor("agent-2", "approval-mouse-owner", "Action", "Reason"))
	model.selectedAgent = 1
	model.syncSafetyApprovalPrompt()
	_, _, chatWidth, _ := model.layout()
	viewerHeight := model.viewerHeight()

	updated, _ := model.Update(tea.MouseMsg{
		X: chatWidth + 2, Y: viewerHeight + 2, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress,
	})
	model = updated.(Model)
	if model.selectedAgent != 0 || model.modal != modalNone {
		t.Fatalf("mouse navigation stayed trapped: selected=%d modal=%v", model.selectedAgent, model.modal)
	}
}

func TestApprovalOwnerUsesYellowAgentIndicator(t *testing.T) {
	model := New(nil)
	model.snapshot.Agents = approvalAgents()
	model.snapshot.PendingApprovals = approvalSet(approvalFor("agent-2", "approval-dot", "Action", "Reason"))
	view := ansi.Strip(model.agentsView(60, 10))

	for _, line := range strings.Split(view, "\n") {
		if strings.Contains(line, "Agent Two") && !strings.Contains(line, "🟡") {
			t.Fatalf("approval owner is missing yellow indicator: %q", line)
		}
		if strings.Contains(line, "Agent One") && strings.Contains(line, "🟡") {
			t.Fatalf("non-owner received yellow indicator: %q", line)
		}
	}
}

func TestNarrowLayoutSelectsApprovalOwner(t *testing.T) {
	model := New(nil)
	model.width, model.height = 80, 30
	model.snapshot.Agents = approvalAgents()
	model.snapshot.PendingApprovals = approvalSet(approvalFor("agent-2", "approval-narrow", "Action", "Reason"))

	model.syncSafetyApprovalPrompt()
	if model.selectedAgentID() != "agent-2" || model.modal != modalSafetyApproval {
		t.Fatalf("narrow layout did not reveal owner: selected=%q modal=%v", model.selectedAgentID(), model.modal)
	}
}

func TestCollapsedApprovalOwnerIsRevealed(t *testing.T) {
	parent := "agent-1"
	model := New(nil)
	model.width, model.height = 130, 40
	model.snapshot.Agents = []protocol.Agent{
		{ID: parent, Name: "Parent", Status: "running"},
		{ID: "agent-2", Name: "Child", ParentID: &parent, Status: "running"},
	}
	model.collapsedAgents[parent] = true
	model.snapshot.PendingApprovals = approvalSet(approvalFor("agent-2", "approval-child", "Action", "Reason"))

	model.syncSafetyApprovalPrompt()
	if model.collapsedAgents[parent] {
		t.Fatal("pending approval owner remained hidden under collapsed parent")
	}
	if view := ansi.Strip(model.agentsView(60, 10)); !strings.Contains(view, "🟡 Child") {
		t.Fatalf("revealed child is missing yellow indicator: %s", view)
	}
}

func TestApprovalArrowKeysStillChangeChoiceOutsideAgentFocus(t *testing.T) {
	model := New(nil)
	model.width, model.height = 130, 40
	model.ready = true
	model.showSplash = false
	model.snapshot.Agents = approvalAgents()
	model.snapshot.PendingApprovals = approvalSet(approval("approval-choice", "Action", "Reason"))
	model.focus = focusInput
	model.openModal(modalSafetyApproval)
	model.modalChoice = 1

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyUp})
	model = updated.(Model)
	if model.modalChoice != 0 {
		t.Fatalf("approval choice did not change: %d", model.modalChoice)
	}
}

func TestResizeToNarrowRevealsPendingOwner(t *testing.T) {
	model := New(nil)
	model.width, model.height = 130, 40
	model.ready = true
	model.showSplash = false
	model.snapshot.Agents = approvalAgents()
	model.snapshot.PendingApprovals = approvalSet(approvalFor("agent-2", "approval-resize", "Action", "Reason"))
	model.syncSafetyApprovalPrompt()
	if model.modal != modalNone {
		t.Fatal("wide layout unexpectedly selected the owner")
	}

	updated, _ := model.Update(tea.WindowSizeMsg{Width: 80, Height: 30})
	model = updated.(Model)
	if model.selectedAgentID() != "agent-2" || model.modal != modalSafetyApproval {
		t.Fatalf("resize did not reveal owner: selected=%q modal=%v", model.selectedAgentID(), model.modal)
	}
}

func TestClosingHelpRevealsApprovalThatArrivedBehindIt(t *testing.T) {
	model := New(nil)
	model.width, model.height = 130, 40
	model.ready = true
	model.showSplash = false
	model.snapshot.Agents = approvalAgents()
	model.openModal(modalHelp)
	model.snapshot.PendingApprovals = approvalSet(approval("approval-help", "Action", "Reason"))
	model.syncSafetyApprovalPrompt()
	if model.modal != modalHelp {
		t.Fatal("approval displaced help modal")
	}

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	model = updated.(Model)
	if model.modal != modalSafetyApproval {
		t.Fatalf("approval did not appear after help closed: %v", model.modal)
	}
}

func TestMalformedParentCycleDoesNotHangApprovalReveal(t *testing.T) {
	self := "agent-cycle"
	model := New(nil)
	model.width, model.height = 130, 40
	model.snapshot.Agents = []protocol.Agent{
		{ID: self, Name: "Cycle", ParentID: &self, Status: "running"},
	}
	model.snapshot.PendingApprovals = approvalSet(approvalFor(self, "approval-cycle", "Action", "Reason"))

	model.syncSafetyApprovalPrompt()
	if model.modal != modalSafetyApproval {
		t.Fatalf("cycle owner approval was not shown: %v", model.modal)
	}
}
