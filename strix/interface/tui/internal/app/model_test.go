package app

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
)

type recordingConn struct{ bytes.Buffer }

func (c *recordingConn) Close() error { return nil }

func commandFromCmd(t *testing.T, cmd tea.Cmd, connection *recordingConn) protocol.Envelope {
	t.Helper()
	if cmd == nil {
		t.Fatal("expected command")
	}
	msg := cmd()
	if sent, ok := msg.(sentMsg); !ok || sent.err != nil {
		t.Fatalf("command failed: %#v", msg)
	}
	raw := connection.Bytes()
	if len(raw) < 4 {
		t.Fatalf("short command frame: %d bytes", len(raw))
	}
	size := int(binary.BigEndian.Uint32(raw[:4]))
	if len(raw) != size+4 {
		t.Fatalf("command frame size = %d, want %d", len(raw), size+4)
	}
	var envelope protocol.Envelope
	if err := json.Unmarshal(raw[4:], &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func newCommandTestModel(t *testing.T) (Model, *recordingConn) {
	t.Helper()
	connection := &recordingConn{}
	return New(&Client{conn: connection}), connection
}

func handleCommandResult(t *testing.T, model *Model, command string, result any) tea.Cmd {
	t.Helper()
	resultPayload, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(protocol.CommandResult{OK: true, Command: command, Result: resultPayload})
	if err != nil {
		t.Fatal(err)
	}
	if model.client == nil {
		model.client = newClient(&recordingConn{})
	}
	if model.client.pending == nil {
		model.client.pending = map[string]string{}
		model.client.pendingByKey = map[string]string{}
		model.client.requestKeyByID = map[string]string{}
	}
	requestID := fmt.Sprintf("test-%d", len(model.client.pending)+1)
	model.client.pending[requestID] = command
	model.client.pendingByKey[command] = requestID
	model.client.requestKeyByID[requestID] = command
	return model.handleEnvelope(protocol.Envelope{Version: protocol.Version, Type: "command_result", RequestID: requestID, Payload: payload})
}

func stateEnvelope(t *testing.T, revision int, state protocol.Snapshot) protocol.Envelope {
	t.Helper()
	payload, err := json.Marshal(protocol.StateUpdate{Revision: revision, State: state})
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Envelope{Version: protocol.Version, Type: "state", Payload: payload}
}

func rawJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func bootstrapEnvelope(t *testing.T, collection string, revision int, items ...any) protocol.Envelope {
	t.Helper()
	rawItems := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		rawItems = append(rawItems, rawJSON(t, item))
	}
	payload := protocol.CollectionBootstrap{
		Collection: collection, Revision: revision, Cursor: 0, NextCursor: len(rawItems), Done: true, Items: rawItems,
	}
	return protocol.Envelope{Version: protocol.Version, Type: "collection_bootstrap", Payload: rawJSON(t, payload)}
}

func TestBackendDisconnectBecomesFatalUnlessUserIsQuitting(t *testing.T) {
	model := New(nil)
	updated, cmd := model.Update(wireErrMsg{err: fmt.Errorf("socket closed")})
	result := updated.(Model)
	if cmd == nil || result.FatalError() == nil {
		t.Fatalf("backend disconnect was not fatal: cmd=%v error=%v", cmd, result.FatalError())
	}

	model = New(nil)
	model.quitting = true
	updated, _ = model.Update(wireErrMsg{err: fmt.Errorf("socket closed")})
	if quitting := updated.(Model); quitting.FatalError() != nil {
		t.Fatalf("intentional quit became fatal: %v", quitting.FatalError())
	}
}

func TestCollectionBootstrapChunksAndVersionedDelta(t *testing.T) {
	model := New(nil)
	first := protocol.Event{ID: "event-1", Version: 0, Type: "chat", AgentID: "agent", Data: map[string]any{"content": "one"}}
	second := protocol.Event{ID: "event-2", Version: 0, Type: "chat", AgentID: "agent", Data: map[string]any{"content": "two"}}

	firstChunk := protocol.CollectionBootstrap{
		Collection: "events", Revision: 1, Cursor: 0, NextCursor: 1, Items: []json.RawMessage{rawJSON(t, first)},
	}
	model.handleEnvelope(protocol.Envelope{Version: protocol.Version, Type: "collection_bootstrap", Payload: rawJSON(t, firstChunk)})
	if len(model.snapshot.Events) != 0 {
		t.Fatal("partial bootstrap mutated installed events")
	}
	lastChunk := protocol.CollectionBootstrap{
		Collection: "events", Revision: 1, Cursor: 1, NextCursor: 2, Done: true, Items: []json.RawMessage{rawJSON(t, second)},
	}
	model.handleEnvelope(protocol.Envelope{Version: protocol.Version, Type: "collection_bootstrap", Payload: rawJSON(t, lastChunk)})
	if len(model.snapshot.Events) != 2 || model.collectionRevisions["events"] != 1 {
		t.Fatalf("bootstrap was not installed: %#v revisions=%#v", model.snapshot.Events, model.collectionRevisions)
	}

	first.Version = 1
	first.Data["content"] = "updated"
	delta := protocol.CollectionDelta{
		Collection: "events", BaseRevision: 1, Revision: 2, Cursor: 0, NextCursor: 1, Done: true,
		Operations: []protocol.CollectionOperation{{Op: "upsert", Item: rawJSON(t, first)}},
	}
	model.handleEnvelope(protocol.Envelope{Version: protocol.Version, Type: "collection_delta", Payload: rawJSON(t, delta)})
	if model.snapshot.Events[0].Version != 1 || model.snapshot.Events[0].Data["content"] != "updated" || model.collectionRevisions["events"] != 2 {
		t.Fatalf("delta was not applied: %#v", model.snapshot.Events[0])
	}

	deleteDelta := protocol.CollectionDelta{
		Collection: "events", BaseRevision: 2, Revision: 3, Cursor: 0, NextCursor: 1, Done: true,
		Operations: []protocol.CollectionOperation{{Op: "delete", ID: "event-2"}},
	}
	model.handleEnvelope(protocol.Envelope{Version: protocol.Version, Type: "collection_delta", Payload: rawJSON(t, deleteDelta)})
	if len(model.snapshot.Events) != 1 || model.snapshot.Events[0].ID != "event-1" || model.collectionRevisions["events"] != 3 {
		t.Fatalf("delete delta was not applied: %#v", model.snapshot.Events)
	}
}

func TestCollectionMismatchRequestsOneResync(t *testing.T) {
	connection := &recordingConn{}
	model := New(newClient(connection))
	model.collectionRevisions["events"] = 4
	bad := protocol.CollectionDelta{
		Collection: "events", BaseRevision: 2, Revision: 3, Cursor: 0, NextCursor: 0, Done: true,
	}

	cmd := model.handleEnvelope(protocol.Envelope{Version: protocol.Version, Type: "collection_delta", Payload: rawJSON(t, bad)})
	if cmd == nil {
		t.Fatal("revision mismatch did not request a resync")
	}
	message := cmd()
	if sent, ok := message.(sentMsg); !ok || sent.err != nil || sent.command != "collection.resync" {
		t.Fatalf("resync send = %#v", message)
	}
	if retry := model.handleEnvelope(protocol.Envelope{Version: protocol.Version, Type: "collection_delta", Payload: rawJSON(t, bad)}); retry != nil {
		t.Fatal("same mismatch submitted more than one resync")
	}
	if model.collectionRevisions["events"] != 4 {
		t.Fatal("mismatched delta mutated collection revision")
	}
}

func TestAgentsCollectionPreservesSelectedIDAcrossUpsertsAndDeletes(t *testing.T) {
	model := New(nil)
	model.handleEnvelope(bootstrapEnvelope(t, "agents", 1,
		protocol.Agent{ID: "root", Name: "Root", Status: "running"},
		protocol.Agent{ID: "selected", Name: "Selected", Status: "running"},
		protocol.Agent{ID: "other", Name: "Other", Status: "waiting"},
	))
	model.selectedAgent = 1

	updated := protocol.Agent{ID: "selected", Name: "Selected updated", Status: "budget_paused"}
	delta := protocol.CollectionDelta{
		Collection: "agents", BaseRevision: 1, Revision: 2, Cursor: 0, NextCursor: 2, Done: true,
		Operations: []protocol.CollectionOperation{
			{Op: "delete", ID: "root"},
			{Op: "upsert", Item: rawJSON(t, updated)},
		},
	}
	model.handleEnvelope(protocol.Envelope{Version: protocol.Version, Type: "collection_delta", Payload: rawJSON(t, delta)})
	if got := model.snapshot.Agents[model.selectedAgent].ID; got != "selected" {
		t.Fatalf("selected agent changed to %q after delta", got)
	}
	if model.snapshot.Agents[model.selectedAgent].Status != "budget_paused" {
		t.Fatalf("agent upsert was not applied: %#v", model.snapshot.Agents[model.selectedAgent])
	}

	deleteSelected := protocol.CollectionDelta{
		Collection: "agents", BaseRevision: 2, Revision: 3, Cursor: 0, NextCursor: 1, Done: true,
		Operations: []protocol.CollectionOperation{{Op: "delete", ID: "selected"}},
	}
	model.handleEnvelope(protocol.Envelope{Version: protocol.Version, Type: "collection_delta", Payload: rawJSON(t, deleteSelected)})
	if len(model.snapshot.Agents) != 1 || model.snapshot.Agents[model.selectedAgent].ID != "other" {
		t.Fatalf("selected-agent delete did not fall back safely: %#v", model.snapshot.Agents)
	}
}

// Typing a slash must not surface a command list; the start screen takes prompts
// and targets only.
func TestSetupOffersNoSlashCommands(t *testing.T) {
	model := New(nil)
	model.width, model.height = 100, 50
	model.showSplash = false
	model.handleEnvelope(stateEnvelope(t, 1, protocol.Snapshot{SetupMode: true, ScanState: "setup"}))

	model.input.SetValue("/")
	model.resizeViewport()
	view := ansi.Strip(model.View())
	for _, gone := range []string{"/target", "/start", "/clear", "/prompt", "/quit", "/help"} {
		if strings.Contains(view, gone) {
			t.Fatalf("a slash command menu still appears for %q: %s", gone, view)
		}
	}
}

func TestSetupUsesDedicatedStartScreen(t *testing.T) {
	model := New(nil)
	model.width, model.height = 130, 34
	model.showSplash = false
	state := protocol.Snapshot{
		SetupMode:    true,
		ScanState:    "setup",
		Model:        "gpt-5.4",
		Targets:      []string{"/workspace/source", "https://example.com"},
		Instruction:  "focus on access control",
		ScanMode:     "quick",
		MaxBudgetUSD: floatPointer(12.5),
		MaxTurns:     275,
		ScopeMode:    "diff",
		DiffBase:     "origin/main",
		Agents:       []protocol.Agent{{ID: "hidden", Name: "SETUP_SHOULD_HIDE_AGENT", Status: "running"}},
	}
	model.handleEnvelope(stateEnvelope(t, 1, state))

	view := model.View()
	for _, want := range []string{
		"gpt-5.4",
		"/workspace/source",
		"https://example.com",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("start screen is missing %q: %s", want, view)
		}
	}
	if strings.Contains(view, "SETUP_SHOULD_HIDE_AGENT") {
		t.Fatalf("live scan sidebar appeared on the start screen: %s", view)
	}
}

func floatPointer(value float64) *float64 { return &value }

func TestStartedSnapshotTransitionsToLiveView(t *testing.T) {
	model := New(nil)
	model.width, model.height = 130, 34
	model.showSplash = false
	model.handleEnvelope(stateEnvelope(t, 1, protocol.Snapshot{SetupMode: true, ScanState: "setup"}))
	if view := model.View(); !strings.Contains(view, setupPlaceholder) {
		t.Fatalf("setup snapshot did not show the start screen: %s", view)
	}

	runningState := protocol.Snapshot{
		SetupMode:   false,
		ScanStarted: true,
		ScanState:   "running",
	}
	model.handleEnvelope(stateEnvelope(t, 2, runningState))
	model.handleEnvelope(bootstrapEnvelope(t, "agents", 1, protocol.Agent{ID: "one", Name: "LIVE_AGENT", Status: "running"}))
	view := model.View()
	if !strings.Contains(view, "LIVE_AGENT") || !strings.Contains(view, "Send a message") || strings.Contains(view, "Configure your pentest") {
		t.Fatalf("started snapshot did not switch to the live view: %s", view)
	}
	if model.input.Placeholder != "Send a message" {
		t.Fatalf("live input placeholder was not updated: %q", model.input.Placeholder)
	}
}

func TestSetupStartScreenFitsNarrowTerminal(t *testing.T) {
	model := New(nil)
	model.width, model.height = 40, 18
	model.showSplash = false
	model.handleEnvelope(stateEnvelope(t, 1, protocol.Snapshot{SetupMode: true, ScanState: "setup"}))
	model.input.SetValue("/")
	model.resizeViewport()

	view := ansi.Strip(model.viewInner())
	// A narrow terminal falls back to the plain wordmark, but the launch screen
	// never gives up its identity entirely.
	topRow := ansi.Strip(strings.SplitN(wordmark(), "\n", 2)[0])
	if !strings.Contains(view, topRow) && !strings.Contains(view, "STRIX") {
		t.Fatalf("narrow start screen logo is missing: %s", view)
	}
	lines := strings.Split(view, "\n")
	if len(lines) > model.height {
		t.Fatalf("start screen height %d exceeds terminal height %d", len(lines), model.height)
	}
	for _, line := range lines {
		if width := lipgloss.Width(line); width > model.width {
			t.Fatalf("start screen line width %d exceeds terminal width %d: %q", width, model.width, ansi.Strip(line))
		}
	}
}

// A leading slash is ordinary prompt text now: there are no commands to match,
// so it must reach the scan as written rather than being rejected.
func TestLeadingSlashIsPromptTextNotACommand(t *testing.T) {
	connection := &recordingConn{}
	model := New(&Client{conn: connection})
	model.snapshot = protocol.Snapshot{SetupMode: true}
	model.focus = focusInput
	model.input.SetValue("/etc/passwd is world readable, check it")

	updated, cmd := model.updateMain(tea.KeyMsg{Type: tea.KeyEnter})
	result := updated.(Model)
	if cmd == nil {
		t.Fatal("enter did not submit")
	}
	types := commandTypes(drainCommands(t, cmd, connection))
	if !contains(types, "setup.start") {
		t.Fatalf("a slash-leading prompt did not launch a scan: %v", types)
	}
	// The path is read as a target and the sentence as the instruction.
	if !contains(types, "setup.add_target") || !contains(types, "setup.set_instruction") {
		t.Fatalf("slash-leading prompt was not split into target and instruction: %v", types)
	}
	for _, line := range result.setupLog {
		if strings.Contains(ansi.Strip(line), "Unknown command") {
			t.Fatalf("a slash-leading prompt was treated as a command: %#v", result.setupLog)
		}
	}
}

// The composer is cleared on submit and the prompt is not echoed into the log.
func TestSubmittedPromptIsNotEchoedInOutput(t *testing.T) {
	model := New(nil)
	model.snapshot.SetupMode = true
	updated, _ := model.submitSetupPrompt("secret instruction")
	result := updated.(Model)
	if content := result.setupContent(); strings.Contains(content, "secret instruction") {
		t.Fatalf("submitted prompt leaked into output: %s", content)
	}
}

func TestStateMessagesRenderOnce(t *testing.T) {
	model := New(nil)
	message := protocol.Message{ID: "setup-1", Text: "Replace the rejected key", Level: "warning"}
	model.handleEnvelope(stateEnvelope(t, 1, protocol.Snapshot{SetupMode: true, Messages: []protocol.Message{message}}))
	model.handleEnvelope(stateEnvelope(t, 2, protocol.Snapshot{SetupMode: true, Messages: []protocol.Message{message}}))
	if len(model.setupLog) != 1 || !strings.Contains(ansi.Strip(model.setupLog[0]), message.Text) {
		t.Fatalf("setup message was not rendered exactly once: %#v", model.setupLog)
	}
}

func TestMouseActivatesQuitPromptButtons(t *testing.T) {
	model := New(nil)
	model.width, model.height = 100, 30
	model.modal = modalQuit
	view := model.modalView()
	left, top, _, _ := model.centeredViewBounds(view)

	buttonPosition := func(label string) (int, int) {
		t.Helper()
		for row, line := range strings.Split(view, "\n") {
			plain := ansi.Strip(line)
			if index := strings.Index(plain, label); index >= 0 {
				return left + ansi.StringWidth(plain[:index]), top + row
			}
		}
		t.Fatalf("button %q not found", label)
		return 0, 0
	}

	x, y := buttonPosition("No")
	updated, cmd := model.updateMouse(tea.MouseMsg{X: x, Y: y, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
	result := updated.(Model)
	if result.modal != modalNone || result.quitting || cmd != nil {
		t.Fatalf("No did not dismiss quit prompt: modal=%v quitting=%v cmd=%v", result.modal, result.quitting, cmd)
	}

	model.modal = modalQuit
	view = model.modalView()
	left, top, _, _ = model.centeredViewBounds(view)
	x, y = buttonPosition("Yes")
	updated, cmd = model.updateMouse(tea.MouseMsg{X: x, Y: y, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
	result = updated.(Model)
	if !result.quitting || cmd == nil {
		t.Fatalf("Yes did not confirm quit: quitting=%v cmd=%v", result.quitting, cmd)
	}
}

func TestModalKeepsBackgroundVisible(t *testing.T) {
	model := New(nil)
	model.width, model.height = 130, 30
	model.showSplash = false
	model.ready = true
	model.snapshot = protocol.Snapshot{Agents: []protocol.Agent{{ID: "one", Name: "UNIQUE_AGENT", Status: "running"}}}
	model.resizeViewport()
	model.modal = modalHelp
	view := model.View()
	if !strings.Contains(view, "UNIQUE_AGENT") {
		t.Fatalf("modal overlay hid the background agent tree")
	}
	if !strings.Contains(view, "Strix Help") {
		t.Fatalf("modal content missing")
	}
}

func TestChatWrapsWithinChatWidth(t *testing.T) {
	model := New(nil)
	model.width, model.height = 130, 30
	model.showSplash = false
	model.ready = true
	long := strings.Repeat("word ", 200)
	model.snapshot = protocol.Snapshot{
		Agents: []protocol.Agent{{ID: "one", Name: "Agent", Status: "running"}},
		Events: []protocol.Event{{ID: "1", AgentID: "one", Type: "chat", Data: map[string]any{"role": "assistant", "content": long}}},
	}
	model.resizeViewport()
	for _, line := range strings.Split(model.chatContent(), "\n") {
		if lipgloss.Width(line) > model.viewport.Width {
			t.Fatalf("chat line width %d exceeds viewport width %d", lipgloss.Width(line), model.viewport.Width)
		}
	}
}

func TestSnapshotRendersSelectedAgentEventsOnly(t *testing.T) {
	model := New(nil)
	model.width, model.height = 100, 30
	model.showSplash = false
	model.ready = true
	model.snapshot = protocol.Snapshot{
		SetupMode: false,
		Agents:    []protocol.Agent{{ID: "one", Name: "Agent One", Status: "running"}, {ID: "two", Name: "Agent Two", Status: "waiting"}},
		Events: []protocol.Event{
			{ID: "1", AgentID: "one", Type: "chat", Data: map[string]any{"role": "assistant", "content": "first"}},
			{ID: "2", AgentID: "two", Type: "chat", Data: map[string]any{"role": "assistant", "content": "second"}},
		},
	}
	model.refreshViewport()
	view := model.View()
	if !strings.Contains(view, "first") || strings.Contains(view, "second") {
		t.Fatalf("incorrect selected-agent events: %s", view)
	}
}

func TestVulnerabilityDetailScrollsWithoutHidingFooter(t *testing.T) {
	model := New(nil)
	model.width, model.height = 130, 40
	model.snapshot.Vulnerabilities = []map[string]any{{
		"title":       "Long finding",
		"severity":    "high",
		"description": strings.Repeat("detail line\n", 100),
	}}
	model.openModal(modalVulnerability)

	view := model.modalView()
	if !strings.Contains(view, "Done") {
		t.Fatalf("finding footer is not visible before scrolling: %s", view)
	}
	_, wantHeight := model.vulnerabilityDialogSize()
	if got := len(strings.Split(view, "\n")); got != wantHeight {
		t.Fatalf("finding dialog height = %d, want %d", got, wantHeight)
	}

	updated, _ := model.updateModal(tea.KeyMsg{Type: tea.KeyPgDown})
	model = updated.(Model)
	if model.modal != modalVulnerability || model.vulnViewport.YOffset == 0 {
		t.Fatalf("page down dismissed or did not scroll finding: modal=%v offset=%d", model.modal, model.vulnViewport.YOffset)
	}
	if view = model.modalView(); !strings.Contains(view, "Done") {
		t.Fatalf("finding footer disappeared after scrolling: %s", view)
	}

	before := model.vulnViewport.YOffset
	modalLeft, modalTop, _, _ := model.centeredViewBounds(model.modalView())
	updated, _ = model.updateModalMouse(tea.MouseMsg{X: modalLeft + 4, Y: modalTop + 3, Button: tea.MouseButtonWheelDown})
	model = updated.(Model)
	if model.vulnViewport.YOffset <= before {
		t.Fatalf("mouse wheel did not scroll finding: before=%d after=%d", before, model.vulnViewport.YOffset)
	}
	updated, _ = model.updateModal(tea.KeyMsg{Type: tea.KeyEsc})
	if updated.(Model).modal != modalNone {
		t.Fatal("escape did not close finding detail")
	}
}

func TestVulnerabilityCopySupportsKeyboardAndMouse(t *testing.T) {
	originalWriteClipboard := writeClipboard
	t.Cleanup(func() { writeClipboard = originalWriteClipboard })
	var copied []string
	writeClipboard = func(value string) error {
		copied = append(copied, value)
		return nil
	}

	newModel := func() Model {
		model := New(nil)
		model.width, model.height = 130, 40
		model.snapshot.Vulnerabilities = []map[string]any{{
			"title": "Copy me", "severity": "high", "description": "Finding detail",
		}}
		model.openModal(modalVulnerability)
		return model
	}

	model := newModel()
	// Tab moves between the buttons; the arrows step between reports.
	updated, _ := model.updateModal(tea.KeyMsg{Type: tea.KeyTab})
	model = updated.(Model)
	updated, cmd := model.updateModal(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if cmd == nil || model.modal != modalVulnerability {
		t.Fatalf("keyboard Copy did not keep the detail open: modal=%v cmd=%v", model.modal, cmd)
	}
	updated, _ = model.Update(cmd())
	model = updated.(Model)
	if len(copied) != 1 || !strings.Contains(copied[0], "Copy me") || !strings.Contains(copied[0], "Finding detail") {
		t.Fatalf("keyboard Copy wrote unexpected report: %#v", copied)
	}
	if !model.vulnerabilityCopied || !strings.Contains(ansi.Strip(model.modalView()), "Copied!") {
		t.Fatal("successful keyboard Copy was not reflected in the dialog")
	}

	model = newModel()
	view := model.modalView()
	left, top, _, _ := model.centeredViewBounds(view)
	copyX, copyY := -1, -1
	for row, line := range strings.Split(view, "\n") {
		plain := ansi.Strip(line)
		if index := strings.Index(plain, "Copy"); index >= 0 {
			copyX, copyY = left+ansi.StringWidth(plain[:index]), top+row
		}
	}
	if copyX < 0 {
		t.Fatal("Copy button was not rendered")
	}
	updated, cmd = model.updateModalMouse(tea.MouseMsg{
		X: copyX, Y: copyY, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress,
	})
	model = updated.(Model)
	if cmd == nil || model.reportFocus != reportCopy {
		t.Fatalf("mouse Copy was not activated: focus=%q cmd=%v", model.reportFocus, cmd)
	}
	cmd()
	if len(copied) != 2 {
		t.Fatalf("mouse Copy calls = %d, want 2", len(copied))
	}
}

func TestVulnerabilitySelectionStaysVisible(t *testing.T) {
	model := New(nil)
	model.width, model.height = 130, 30
	model.focus = focusVulnerabilities
	for i := 0; i < 20; i++ {
		model.snapshot.Vulnerabilities = append(model.snapshot.Vulnerabilities, map[string]any{
			"title": fmt.Sprintf("Finding %02d", i),
		})
	}
	for range 15 {
		updated, _ := model.updateMain(tea.KeyMsg{Type: tea.KeyDown})
		model = updated.(Model)
	}

	view := ansi.Strip(model.vulnerabilitiesView(30, 10))
	if !strings.Contains(view, "Finding 15") || strings.Contains(view, "Finding 00") {
		t.Fatalf("selected finding was not kept in the visible window: %s", view)
	}
}

func TestVulnerabilityListSupportsWheelAndPageNavigation(t *testing.T) {
	model := New(nil)
	model.width, model.height = 130, 30
	for i := 0; i < 20; i++ {
		model.snapshot.Vulnerabilities = append(model.snapshot.Vulnerabilities, map[string]any{
			"title": fmt.Sprintf("Finding %02d", i),
		})
	}
	_, _, chatWidth, _ := model.layout()
	_, _, agentHeight := model.sidebarHeights()
	pageItems := model.vulnerabilityPageItems()

	updated, _ := model.updateMouse(tea.MouseMsg{
		X: chatWidth + 2, Y: model.viewerHeight() + agentHeight + 1, Button: tea.MouseButtonWheelDown,
	})
	model = updated.(Model)
	if model.focus != focusVulnerabilities || model.vulnOffset != 3 || model.selectedVuln != 3 {
		t.Fatalf("wheel scroll did not focus and advance list: focus=%v offset=%d selected=%d", model.focus, model.vulnOffset, model.selectedVuln)
	}

	updated, _ = model.updateMain(tea.KeyMsg{Type: tea.KeyPgDown})
	model = updated.(Model)
	if model.selectedVuln != 3+pageItems {
		t.Fatalf("page down selected %d", model.selectedVuln)
	}
	updated, _ = model.updateMain(tea.KeyMsg{Type: tea.KeyEnd})
	model = updated.(Model)
	if model.selectedVuln != 19 {
		t.Fatalf("end selected %d, want 19", model.selectedVuln)
	}
	view := ansi.Strip(model.vulnerabilitiesView(30, model.vulnerabilityPageSize()))
	if !strings.Contains(view, "Finding 19") || strings.Contains(view, "Finding 00") {
		t.Fatalf("end did not scroll the final finding into view: %s", view)
	}
}

func TestAgentTreeWheelScrollSurvivesSnapshot(t *testing.T) {
	model := New(nil)
	model.width, model.height = 130, 30
	model.ready = true
	for i := 0; i < 40; i++ {
		model.snapshot.Agents = append(model.snapshot.Agents, protocol.Agent{
			ID: fmt.Sprintf("agent-%02d", i), Name: fmt.Sprintf("Agent %02d", i), Status: "running",
		})
	}
	_, _, chatWidth, _ := model.layout()

	updated, _ := model.updateMouse(tea.MouseMsg{
		X: chatWidth + 2, Y: model.viewerHeight() + 2, Button: tea.MouseButtonWheelDown,
	})
	model = updated.(Model)
	if model.focus != focusAgents || model.agentOffset != 3 || model.selectedAgent != 3 {
		t.Fatalf("wheel scroll did not advance tree: focus=%v offset=%d selected=%d", model.focus, model.agentOffset, model.selectedAgent)
	}

	model.handleEnvelope(stateEnvelope(t, 1, model.snapshot))
	if model.agentOffset != 3 || model.selectedAgent != 3 {
		t.Fatalf("snapshot reset manual tree scroll: offset=%d selected=%d", model.agentOffset, model.selectedAgent)
	}
}

func TestVulnerabilityDetailFitsNarrowTerminal(t *testing.T) {
	model := New(nil)
	model.width, model.height = 32, 15
	model.snapshot.Vulnerabilities = []map[string]any{{
		"title":       "Narrow finding",
		"description": strings.Repeat("long detail ", 50),
	}}
	model.openModal(modalVulnerability)
	view := model.modalView()

	if !strings.Contains(view, "Done") {
		t.Fatalf("finding footer is missing in narrow terminal: %s", view)
	}
	if got := len(strings.Split(view, "\n")); got > model.height {
		t.Fatalf("finding dialog height %d exceeds terminal height %d", got, model.height)
	}
	for _, line := range strings.Split(view, "\n") {
		if got := lipgloss.Width(line); got > model.width {
			t.Fatalf("finding dialog width %d exceeds terminal width %d", got, model.width)
		}
	}
}

func TestAgentTreeUsesDepthFirstOrderAndStableSelectionPosition(t *testing.T) {
	parentRoot := "root"
	parentA := "a"
	model := New(nil)
	model.snapshot.Agents = []protocol.Agent{
		{ID: "root", Name: "Root", Status: "running"},
		{ID: "a", ParentID: &parentRoot, Name: "Agent A", Status: "running"},
		{ID: "b", ParentID: &parentRoot, Name: "Agent B", Status: "running"},
		{ID: "a-child", ParentID: &parentA, Name: "Agent A Child", Status: "running"},
	}

	entries := agentTreeEntries(model.snapshot.Agents, nil)
	var order []string
	for _, entry := range entries {
		order = append(order, model.snapshot.Agents[entry.index].ID)
	}
	if got, want := strings.Join(order, ","), "root,a,a-child,b"; got != want {
		t.Fatalf("agent tree order = %q, want %q", got, want)
	}
	if view := ansi.Strip(model.agentsView(50, 10)); !strings.Contains(view, "▼") {
		t.Fatalf("expanded agent does not show its toggle: %s", view)
	}
	// A leaf carries no toggle at all, so its icon sits where a parent's
	// toggle would be.
	for _, line := range strings.Split(ansi.Strip(model.agentsView(50, 10)), "\n") {
		if strings.Contains(line, "Agent B") && !strings.HasSuffix(line, "└─ ⚪ Agent B") {
			t.Fatalf("leaf row reserved toggle space: %q", line)
		}
	}

	model.selectedAgent = 1
	selectedView := ansi.Strip(model.agentsView(50, 10))
	model.selectedAgent = 2
	unselectedView := ansi.Strip(model.agentsView(50, 10))
	lineFor := func(view, label string) string {
		t.Helper()
		for _, line := range strings.Split(view, "\n") {
			if strings.Contains(line, label) {
				return line
			}
		}
		t.Fatalf("agent row %q not found in %s", label, view)
		return ""
	}
	if selected, unselected := strings.Index(lineFor(selectedView, "Agent A"), "Agent A"), strings.Index(lineFor(unselectedView, "Agent A"), "Agent A"); selected != unselected {
		t.Fatalf("selection moved agent label from column %d to %d", unselected, selected)
	}

	// The cursor is a filled block behind the label; no row carries a gutter
	// accent, which would indent every node past the panel padding.
	if strings.ContainsAny(selectedView, "┃") {
		t.Fatalf("agent rows drew a gutter accent: %s", selectedView)
	}

	model.focus = focusAgents
	model.selectedAgent = 1
	updated, _ := model.updateMain(tea.KeyMsg{Type: tea.KeyDown})
	result := updated.(Model)
	if got := result.snapshot.Agents[result.selectedAgent].ID; got != "a-child" {
		t.Fatalf("down selected %q, want depth-first child", got)
	}

	updated, _ = model.updateMain(tea.KeyMsg{Type: tea.KeyEnter})
	result = updated.(Model)
	collapsed := agentTreeEntries(result.snapshot.Agents, result.collapsedAgents)
	for _, entry := range collapsed {
		if result.snapshot.Agents[entry.index].ID == "a-child" {
			t.Fatal("collapsed parent still rendered its child")
		}
	}
	if view := ansi.Strip(result.agentsView(50, 10)); !strings.Contains(view, "▶") {
		t.Fatalf("collapsed agent does not show its toggle: %s", view)
	}
}

func TestAgentClickUsesRenderedWindowAfterResize(t *testing.T) {
	model := New(nil)
	model.width, model.height = 130, 20
	for i := range 20 {
		model.snapshot.Agents = append(model.snapshot.Agents, protocol.Agent{
			ID: fmt.Sprintf("agent-%02d", i), Name: fmt.Sprintf("Agent %02d", i), Status: "running",
		})
	}
	model.selectedAgent = 15
	model.ensureAgentVisible()
	if model.agentOffset == 0 {
		t.Fatal("test setup did not scroll the agent tree")
	}

	model.height = 60
	model.ensureAgentVisible()
	_, _, chatWidth, _ := model.layout()
	updated, _ := model.updateMouse(tea.MouseMsg{X: chatWidth + 1, Y: model.viewerHeight() + 2, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
	result := updated.(Model)
	if result.selectedAgent != 0 {
		t.Fatalf("click selected snapshot index %d instead of first rendered agent", result.selectedAgent)
	}
}

func TestFindingTitlesWrapAndViewerCTAIsClickable(t *testing.T) {
	model := New(nil)
	model.width, model.height = 130, 30
	model.snapshot.Vulnerabilities = []map[string]any{{
		"title": "A finding title that is intentionally long enough to wrap onto multiple lines",
	}}

	view := ansi.Strip(model.vulnerabilitiesView(model.vulnerabilityListWidth(), 10))
	if strings.Count(view, "\n") < 1 || strings.Contains(view, "…") {
		t.Fatalf("finding title was not wrapped: %s", view)
	}
	if cta := ansi.Strip(model.viewerView(40)); !strings.Contains(cta, "Watch live in browser") {
		t.Fatalf("viewer CTA is missing: %s", cta)
	}

	_, _, chatWidth, _ := model.layout()
	_, cmd := model.updateMouse(tea.MouseMsg{
		X: chatWidth + 2, Y: 1, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress,
	})
	if cmd == nil {
		t.Fatal("clicking viewer CTA did not send viewer.open")
	}
}

func TestRunningViewerShowsCompleteWrappedURL(t *testing.T) {
	model := New(nil)
	model.width, model.height = 130, 30
	url := "http://127.0.0.1:43123/?token=abcdefghijklmnopqrstuvwxyz0123456789"
	model.snapshot.ViewerStatus = "running"
	model.snapshot.ViewerURL = &url

	view := ansi.Strip(model.viewerView(18))
	if !strings.Contains(view, "Viewer running") {
		t.Fatalf("viewer status is missing: %s", view)
	}
	urlLines := strings.Split(strings.SplitN(view, "\n", 2)[1], "\n")
	for i := range urlLines {
		urlLines[i] = strings.TrimRight(urlLines[i], " ")
	}
	if got := strings.Join(urlLines, ""); got != url {
		t.Fatalf("wrapped viewer URL = %q, want %q", got, url)
	}
	if want := strings.Count(model.viewerView(model.viewerContentWidth()), "\n") + 3; model.viewerHeight() != want {
		t.Fatalf("viewer height = %d, want %d", model.viewerHeight(), want)
	}
}

func TestVerticalScrollbarThumbTracksScrollOffset(t *testing.T) {
	top := strings.Split(ansi.Strip(verticalScrollbar(6, 24, 6, 0, thumbResting)), "\n")
	bottom := strings.Split(ansi.Strip(verticalScrollbar(6, 24, 6, 18, thumbResting)), "\n")

	// The track is blank, so only the thumb is drawn.
	if top[0] != "█" || top[5] != " " {
		t.Fatalf("top scrollbar is incorrect: %#v", top)
	}
	if bottom[0] != " " || bottom[5] != "█" {
		t.Fatalf("bottom scrollbar is incorrect: %#v", bottom)
	}
	if full := verticalScrollbar(4, 4, 4, 0, thumbResting); full != "" {
		t.Fatalf("non-overflowing scrollbar should be hidden: %q", full)
	}
	withoutBar := ansi.Strip(withVerticalScrollbar("content", 12, 2, 2, 2, 0, thumbResting))
	if strings.ContainsAny(withoutBar, "█") {
		t.Fatalf("non-overflowing panel rendered a scrollbar: %q", withoutBar)
	}
}

// The bar takes exactly one column, so a scrolling panel keeps the rest.
func TestVerticalScrollbarOccupiesOneColumn(t *testing.T) {
	rows := strings.Split(withVerticalScrollbar("content", 12, 2, 24, 2, 0, thumbResting), "\n")
	for _, row := range rows {
		if width := ansi.StringWidth(row); width != 12 {
			t.Fatalf("scrolling panel row width = %d, want 12", width)
		}
	}
	if !strings.Contains(ansi.Strip(rows[0]), "█") {
		t.Fatalf("thumb missing from the first row: %q", rows[0])
	}
}

func TestPanelPaddingResetsLeakingLineBackground(t *testing.T) {
	leaky := "\x1b[48;2;82;82;82mstyled"
	body := fixedPanelBody(leaky, 12, 1)
	want := "styled\x1b[0m" + blackBG
	if !strings.Contains(body, want) {
		t.Fatalf("panel padding did not reset the source background: %q", body)
	}
	if width := ansi.StringWidth(body); width != 12 {
		t.Fatalf("fixed panel body width = %d, want 12", width)
	}
}

func TestMainTraceTreeAndFindingsRenderScrollbars(t *testing.T) {
	model := New(nil)
	model.width, model.height = 150, 35
	model.ready = true
	for i := 0; i < 40; i++ {
		model.snapshot.Agents = append(model.snapshot.Agents, protocol.Agent{
			ID: fmt.Sprintf("agent-%02d", i), Name: fmt.Sprintf("Agent %02d", i), Status: "running",
		})
	}
	for i := 0; i < 20; i++ {
		model.snapshot.Vulnerabilities = append(model.snapshot.Vulnerabilities, map[string]any{
			"title": fmt.Sprintf("Finding %02d", i),
		})
	}
	model.resizeViewport()
	model.viewportContent = strings.Repeat("trace line\n", 100)
	model.viewport.SetContent(model.viewportContent)
	model.viewport.SetYOffset(10)

	view := ansi.Strip(model.mainView())
	if count := strings.Count(view, "█"); count < 3 {
		t.Fatalf("expected scroll thumbs in trace, tree, and findings; found %d\n%s", count, view)
	}
}

func TestMainScrollbarsSupportClickAndDrag(t *testing.T) {
	model := New(nil)
	model.width, model.height = 150, 35
	model.ready = true
	for i := 0; i < 40; i++ {
		model.snapshot.Agents = append(model.snapshot.Agents, protocol.Agent{
			ID: fmt.Sprintf("agent-%02d", i), Name: fmt.Sprintf("Agent %02d", i), Status: "running",
		})
	}
	for i := 0; i < 20; i++ {
		model.snapshot.Vulnerabilities = append(model.snapshot.Vulnerabilities, map[string]any{
			"title": fmt.Sprintf("Finding %02d", i),
		})
	}
	model.resizeViewport()
	model.viewportContent = strings.Repeat("trace line\n", 100)
	model.viewport.SetContent(model.viewportContent)
	showSidebar, _, chatWidth, chatHeight := model.layout()
	viewerHeight := model.viewerHeight()
	_, vulnHeight, agentHeight := model.sidebarHeights()
	if !showSidebar {
		t.Fatal("test requires sidebar")
	}

	updated, _ := model.updateMouse(tea.MouseMsg{
		X: chatWidth - 2, Y: chatHeight - 2, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress,
	})
	model = updated.(Model)
	if model.draggingScrollbar != scrollbarTrace || model.viewport.YOffset == 0 {
		t.Fatalf("trace scrollbar click failed: drag=%v offset=%d", model.draggingScrollbar, model.viewport.YOffset)
	}
	updated, _ = model.updateMouse(tea.MouseMsg{X: chatWidth - 2, Y: 1, Action: tea.MouseActionMotion})
	model = updated.(Model)
	if model.viewport.YOffset != 0 {
		t.Fatalf("trace scrollbar drag did not reach top: %d", model.viewport.YOffset)
	}
	updated, _ = model.updateMouse(tea.MouseMsg{Action: tea.MouseActionRelease})
	model = updated.(Model)
	if model.draggingScrollbar != scrollbarNone {
		t.Fatal("trace scrollbar remained captured after release")
	}

	updated, _ = model.updateMouse(tea.MouseMsg{
		X: model.width - 3, Y: viewerHeight + agentHeight - 3,
		Button: tea.MouseButtonLeft, Action: tea.MouseActionPress,
	})
	model = updated.(Model)
	if model.draggingScrollbar != scrollbarAgents || model.agentOffset == 0 {
		t.Fatalf("agent scrollbar click failed: drag=%v offset=%d", model.draggingScrollbar, model.agentOffset)
	}
	updated, _ = model.updateMouse(tea.MouseMsg{Action: tea.MouseActionRelease})
	model = updated.(Model)

	updated, _ = model.updateMouse(tea.MouseMsg{
		X: model.width - 3, Y: viewerHeight + agentHeight + vulnHeight - 2,
		Button: tea.MouseButtonLeft, Action: tea.MouseActionPress,
	})
	model = updated.(Model)
	if model.draggingScrollbar != scrollbarFindings || model.vulnOffset == 0 {
		t.Fatalf("findings scrollbar click failed: drag=%v offset=%d", model.draggingScrollbar, model.vulnOffset)
	}
}

func TestTerminalSnapshotWithoutAgentsDoesNotKeepLoading(t *testing.T) {
	tests := []struct {
		state string
		error string
		want  string
	}{
		{state: "failed", error: "authentication rejected", want: "Scan failed"},
		{state: "stopped", want: "Scan stopped"},
		{state: "completed", want: "Scan completed"},
		{state: "preparing", want: "Preparing scan..."},
	}

	for _, tt := range tests {
		t.Run(tt.state, func(t *testing.T) {
			model := New(nil)
			model.viewport.Width, model.viewport.Height = 80, 20
			model.snapshot.ScanState = tt.state
			if tt.error != "" {
				model.snapshot.Error = &tt.error
			}

			content := model.chatContent()
			if !strings.Contains(content, tt.want) || strings.Contains(content, "Loading...") {
				t.Fatalf("terminal state rendered incorrectly: %s", content)
			}
			if tt.error != "" && !strings.Contains(content, tt.error) {
				t.Fatalf("failure detail was not rendered: %s", content)
			}
		})
	}
}

func TestCrashedAndBudgetPausedAgentStatusParity(t *testing.T) {
	model := New(nil)
	model.width = 100
	model.snapshot.Agents = []protocol.Agent{
		{ID: "crashed", Name: "Crashed agent", Status: "crashed", ErrorMessage: "provider failed"},
		{ID: "paused", Name: "Paused agent", Status: "budget_paused"},
	}

	tree := ansi.Strip(model.agentsView(50, 10))
	if !strings.Contains(tree, "🔴 Crashed agent") || !strings.Contains(tree, "⏸ Paused agent") {
		t.Fatalf("agent status icons do not match Textual: %s", tree)
	}
	crashed := ansi.Strip(model.statusView(100))
	if !strings.Contains(crashed, "provider failed") || !strings.Contains(crashed, "Send message to resume") {
		t.Fatalf("crashed status lacks recovery guidance: %s", crashed)
	}
	model.selectedAgent = 1
	paused := ansi.Strip(model.statusView(100))
	if !strings.Contains(paused, "Budget limit reached") || !strings.Contains(paused, "Send a message to continue") || !strings.Contains(paused, "ctrl-q") {
		t.Fatalf("budget-paused status lacks Textual guidance: %s", paused)
	}
}

func TestStatusRowShowsPausedWhileAwaitingApproval(t *testing.T) {
	model := New(nil)
	model.width = 100
	model.snapshot.Agents = []protocol.Agent{{ID: "agent-1", Name: "Agent", Status: "running"}}
	model.snapshot.Events = []protocol.Event{{ID: "e1", AgentID: "agent-1", Type: "reasoning"}}

	running := ansi.Strip(model.statusView(100))
	if !strings.Contains(running, "stop") {
		t.Fatalf("a working agent should offer the stop hint: %s", running)
	}

	model.snapshot.PendingApprovals = approvalSet(approval("approval-1", "Action", "Reason"))
	paused := ansi.Strip(model.statusView(100))
	if !strings.Contains(paused, "paused") || !strings.Contains(paused, "awaiting your approval") {
		t.Fatalf("status should show the agent is paused for approval: %s", paused)
	}
	// The stop hint is wrong while a prompt is open (esc denies, not stops).
	if strings.Contains(paused, "esc") && strings.Contains(paused, "stop") {
		t.Fatalf("paused status must not keep the misleading esc-stop hint: %s", paused)
	}
}

func TestStatusRowShowsHazardFlagWhenSafetyDisabled(t *testing.T) {
	model := New(nil)
	model.width = 100
	model.snapshot.Agents = []protocol.Agent{{ID: "a", Name: "Agent", Status: "running"}}

	if before := ansi.Strip(model.statusView(100)); strings.Contains(before, "review off") {
		t.Fatalf("hazard flag shown before review was disabled: %s", before)
	}
	model.snapshot.SafetyDisabled = true
	after := ansi.Strip(model.statusView(100))
	if !strings.Contains(after, "review off") {
		t.Fatalf("status row lacks the disabled-review hazard flag: %s", after)
	}
}

func TestStopDialogAndCommandAreLimitedToActiveAgents(t *testing.T) {
	tests := []struct {
		status string
		active bool
	}{
		{status: "running", active: true},
		{status: "waiting", active: true},
		{status: "budget_paused", active: true},
		{status: "completed"},
		{status: "failed"},
		{status: "crashed"},
		{status: "stopped"},
	}
	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			model := New(nil)
			model.snapshot.Agents = []protocol.Agent{{ID: "agent", Name: "Agent", Status: tt.status}}
			updated, _ := model.updateMain(tea.KeyMsg{Type: tea.KeyEsc})
			result := updated.(Model)
			if got := result.modal == modalStop; got != tt.active {
				t.Fatalf("stop dialog shown=%v, want %v", got, tt.active)
			}
		})
	}

	model, connection := newCommandTestModel(t)
	model.snapshot.Agents = []protocol.Agent{{ID: "agent", Name: "Agent", Status: "running"}}
	model.modal, model.modalChoice = modalStop, 0
	model.snapshot.Agents[0].Status = "completed"
	updated, cmd := model.updateModal(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil || updated.(Model).modal != modalNone || connection.Len() != 0 {
		t.Fatal("terminal status submitted a stale agent.stop command")
	}
}

func TestBudgetPauseShowsOneWarningToastUntilResumed(t *testing.T) {
	model := New(nil)
	model.snapshot.Agents = []protocol.Agent{{ID: "root", Name: "Strix", Status: "budget_paused"}}
	if cmd := model.notifyBudgetPause(); cmd == nil {
		t.Fatal("expected a toast command on first budget pause")
	}
	if !strings.Contains(model.toast, "Budget limit reached") {
		t.Fatalf("toast %q missing budget warning", model.toast)
	}
	if cmd := model.notifyBudgetPause(); cmd != nil {
		t.Fatal("budget toast should fire once per pause")
	}
	model.snapshot.Agents[0].Status = "running"
	if cmd := model.notifyBudgetPause(); cmd != nil {
		t.Fatal("no toast expected while running")
	}
	model.snapshot.Agents[0].Status = "budget_paused"
	if cmd := model.notifyBudgetPause(); cmd == nil {
		t.Fatal("expected the toast to re-arm after resuming")
	}
}

func TestStatsViewShowsSubscription(t *testing.T) {
	model := New(nil)
	model.snapshot.Model = "gpt-5"
	model.snapshot.Subscription = true
	model.snapshot.Usage = map[string]any{"total_tokens": float64(1200), "cost": 3.5}
	stats := ansi.Strip(model.statsView())
	if !strings.Contains(stats, "ChatGPT subscription") {
		t.Fatalf("stats missing subscription line: %q", stats)
	}
	if strings.Contains(stats, "$") {
		t.Fatalf("subscription runs must not show a cost: %q", stats)
	}
}

func TestVulnerabilityMarkdownReport(t *testing.T) {
	report := vulnerabilityMarkdownReport(map[string]any{
		"title":             "SQLi in login",
		"severity":          "high",
		"cvss":              8.1,
		"description":       "Injectable parameter.",
		"poc_script_code":   "```python\nprint('x')\n```",
		"remediation_steps": "Use bound parameters.",
	})
	for _, want := range []string{
		"# SQLi in login", "**Severity:** HIGH", "**CVSS:** 8.1",
		"## Description", "```python\nprint('x')\n```", "## Remediation",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q:\n%s", want, report)
		}
	}
}

func TestChatContentCachesBlocksUntilEventChanges(t *testing.T) {
	model := New(nil)
	model.width, model.height = 120, 30
	model.showSplash = false
	model.ready = true
	event := protocol.Event{
		ID: "1", AgentID: "one", Type: "tool", Version: 1,
		Data: map[string]any{
			"tool_name": "exec_command",
			"args":      map[string]any{"cmd": "ls -la"},
			"result":    "one\ntwo",
			"status":    "completed",
		},
	}
	model.snapshot = protocol.Snapshot{
		Agents: []protocol.Agent{{ID: "one", Name: "Agent", Status: "running"}},
		Events: []protocol.Event{event},
	}
	model.resizeViewport()
	first := model.chatContent()
	if model.chatContent() != first {
		t.Fatal("cached render changed without an event change")
	}

	updated := event
	updated.Version = 2
	updated.Data = map[string]any{
		"tool_name": "exec_command",
		"args":      map[string]any{"cmd": "whoami"},
		"result":    "root",
		"status":    "completed",
	}
	model.snapshot.Events = []protocol.Event{updated}
	next := model.chatContent()
	if !strings.Contains(ansi.Strip(next), "whoami") {
		t.Fatalf("new event version was served from cache: %q", ansi.Strip(next))
	}
}

func TestChatContentRerendersOnWidthAndExpansionChange(t *testing.T) {
	model := New(nil)
	model.width, model.height = 120, 30
	model.showSplash = false
	model.ready = true
	model.snapshot = protocol.Snapshot{
		Agents: []protocol.Agent{{ID: "one", Name: "Agent", Status: "running"}},
		Events: []protocol.Event{{
			ID: "1", AgentID: "one", Type: "tool", Version: 1,
			Data: map[string]any{
				"tool_name": "exec_command",
				"args":      map[string]any{"cmd": "seq 40"},
				"result":    strings.Repeat("output line\n", 40),
				"status":    "completed",
			},
		}},
	}
	model.resizeViewport()
	collapsed := model.chatContent()
	model.expandedEvents["1"] = true
	expanded := model.chatContent()
	if strings.Count(expanded, "\n") <= strings.Count(collapsed, "\n") {
		t.Fatal("expanding an event was served from cache")
	}
	model.width = 80
	model.resizeViewport()
	narrow := model.chatContent()
	for _, line := range strings.Split(narrow, "\n") {
		if lipgloss.Width(line) > model.viewport.Width {
			t.Fatalf("stale wrapped width after resize: %d > %d", lipgloss.Width(line), model.viewport.Width)
		}
	}
}

// A model or backend failure can be a wrapped exception hundreds of columns
// wide and several lines long. The status row is one line of the chat column, so
// an oversized one widens the whole column - JoinHorizontal pads every row to the
// widest - which pushed the sidebar off screen and wrapped the frame.
func TestLongErrorDoesNotBreakTheFrame(t *testing.T) {
	model := New(nil)
	model.width, model.height = 120, 24
	model.showSplash = false
	model.handleEnvelope(stateEnvelope(t, 1, protocol.Snapshot{ScanState: "running"}))
	bootstrap := protocol.CollectionBootstrap{
		Collection: "agents", Revision: 1, Cursor: 0, NextCursor: 1, Done: true,
		Items: []json.RawMessage{rawJSON(t, protocol.Agent{ID: "a0", Name: "Strix", Status: "running"})},
	}
	model.handleEnvelope(protocol.Envelope{
		Version: protocol.Version, Type: "collection_bootstrap", Payload: rawJSON(t, bootstrap),
	})
	model.errorText = "litellm.APIConnectionError: OpenrouterException - Connection error " +
		"while calling https://openrouter.ai/api/v1/chat/completions: HTTPSConnectionPool" +
		"(host='openrouter.ai', port=443): Max retries exceeded\nTraceback (most recent " +
		"call last):\n  File \"/x/y.py\", line 42, in send\n    raise err"
	model.resizeViewport()

	lines := strings.Split(model.View(), "\n")
	if len(lines) > model.height {
		t.Fatalf("frame is %d rows in a %d-row terminal", len(lines), model.height)
	}
	for i, line := range lines {
		if width := ansi.StringWidth(line); width > model.width {
			t.Fatalf("row %d is %d columns in a %d-column terminal", i, width, model.width)
		}
	}
	// The sidebar has to survive: its panels are the right edge of the frame.
	if !strings.Contains(ansi.Strip(model.View()), "Strix") {
		t.Fatal("the agent tree was pushed out of the frame")
	}
}

func TestStatusMessageFlattensAndKeepsItsHint(t *testing.T) {
	row := ansi.Strip(statusMessage("boom\nsecond line\twith tabs", red, " · Send message to resume", 60))

	if strings.Contains(row, "\n") || strings.Contains(row, "\t") {
		t.Fatalf("status row is not a single line: %q", row)
	}
	if !strings.HasSuffix(row, " · Send message to resume") {
		t.Fatalf("the hint was lost: %q", row)
	}
	if !strings.Contains(row, "boom second line with tabs") {
		t.Fatalf("the message was mangled: %q", row)
	}
	// A message far too long for the row keeps the hint readable.
	long := ansi.Strip(statusMessage(strings.Repeat("x", 500), red, " · Send message to resume", 60))
	if width := ansi.StringWidth(long); width > 60 {
		t.Fatalf("status message is %d columns, want at most 60", width)
	}
	if !strings.HasSuffix(long, " · Send message to resume") {
		t.Fatalf("the hint was clipped away: %q", long)
	}
}

// The status row must be exactly as wide as the column it sits in, at every
// terminal size. A narrow terminal cannot fit the quit hint alongside any status
// text, and keeping it anyway made the row wider than the terminal.
func TestStatusRowIsExactlyItsWidth(t *testing.T) {
	quitHint := lipgloss.NewStyle().Foreground(white).Render("ctrl-q") +
		lipgloss.NewStyle().Foreground(dim).Render(" quit")
	longMessage := lipgloss.NewStyle().Foreground(red).Render(strings.Repeat("boom ", 40))

	for width := 1; width <= 60; width++ {
		for _, testCase := range []struct {
			name        string
			left, right string
		}{
			{"empty", "", ""},
			{"hint only", "", quitHint},
			{"long message and hint", longMessage, quitHint},
			{"long message alone", longMessage, ""},
		} {
			row := composeStatusRow(testCase.left, testCase.right, width)
			if got := ansi.StringWidth(row); got != width {
				t.Fatalf("%s at width %d rendered %d columns: %q",
					testCase.name, width, got, ansi.Strip(row))
			}
			if strings.Contains(row, "\n") {
				t.Fatalf("%s at width %d spans rows", testCase.name, width)
			}
		}
	}
	if row := composeStatusRow("x", "y", 0); row != "" {
		t.Fatalf("a zero-width row should be empty, got %q", row)
	}
}

// A running scan in a narrow terminal must not wrap the frame.
func TestNarrowTerminalKeepsTheFrameIntact(t *testing.T) {
	for _, width := range []int{8, 10, 13, 14, 20, 40} {
		model := New(nil)
		model.width, model.height = width, 20
		model.showSplash = false
		model.handleEnvelope(stateEnvelope(t, 1, protocol.Snapshot{ScanState: "running"}))
		bootstrap := protocol.CollectionBootstrap{
			Collection: "agents", Revision: 1, Cursor: 0, NextCursor: 1, Done: true,
			Items: []json.RawMessage{rawJSON(t, protocol.Agent{ID: "a0", Name: "Strix", Status: "running"})},
		}
		model.handleEnvelope(protocol.Envelope{
			Version: protocol.Version, Type: "collection_bootstrap", Payload: rawJSON(t, bootstrap),
		})
		model.errorText = strings.Repeat("connection failed ", 20)
		model.resizeViewport()

		for i, line := range strings.Split(model.View(), "\n") {
			if got := ansi.StringWidth(line); got > width {
				t.Fatalf("at width %d row %d is %d columns", width, i, got)
			}
		}
	}
}
