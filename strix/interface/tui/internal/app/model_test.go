package app

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
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
	if command == "models.list" {
		if listing, ok := result.(protocol.ModelsResult); ok && listing.ListingID == "" {
			listing.ListingID = "test-listing"
			listing.NextCursor = 1
			listing.Done = true
			result = listing
		}
	}
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

func TestUnknownAndMismatchedCommandResultsCannotClosePersistencePicker(t *testing.T) {
	client := newClient(&recordingConn{})
	model := New(client)
	model.picker = pickerModel
	client.pending["request-1"] = "setup.select_model"
	client.pendingByKey["setup.select_model"] = "request-1"
	client.requestKeyByID["request-1"] = "setup.select_model"
	result := rawJSON(t, protocol.CommandResult{
		OK: true, Command: "setup.select_model", Result: rawJSON(t, map[string]string{"model": "openai/gpt-5"}),
	})

	model.handleEnvelope(protocol.Envelope{Version: protocol.Version, Type: "command_result", RequestID: "unknown", Payload: json.RawMessage(`not-json`)})
	if model.errorText != "" {
		t.Fatal("malformed unknown result mutated model error state")
	}
	model.handleEnvelope(protocol.Envelope{Version: protocol.Version, Type: "command_result", RequestID: "unknown", Payload: result})
	if model.picker != pickerModel {
		t.Fatal("unknown result closed persistence picker")
	}
	mismatched := rawJSON(t, protocol.CommandResult{OK: true, Command: "models.list", Result: rawJSON(t, map[string]any{})})
	model.handleEnvelope(protocol.Envelope{Version: protocol.Version, Type: "command_result", RequestID: "request-1", Payload: mismatched})
	if model.picker != pickerModel || client.pending["request-1"] == "" {
		t.Fatal("mismatched result mutated picker or pending request")
	}
	model.handleEnvelope(protocol.Envelope{Version: protocol.Version, Type: "command_result", RequestID: "request-1", Payload: result})
	if model.picker != pickerNone || client.pending["request-1"] != "" {
		t.Fatal("correlated success did not close picker and resolve request")
	}
}

func TestSetupCommandsAppearAboveInputAndFilter(t *testing.T) {
	model := New(nil)
	model.width, model.height = 100, 50
	model.showSplash = false
	model.handleEnvelope(stateEnvelope(t, 1, protocol.Snapshot{SetupMode: true, ScanState: "setup"}))

	if view := model.View(); strings.Contains(view, "/provider") {
		t.Fatalf("setup commands appeared before slash was typed: %s", view)
	}
	model.input.SetValue("/")
	view := model.View()
	if !strings.Contains(view, "/provider") || !strings.Contains(view, "/target") {
		t.Fatalf("all setup commands were not recommended for bare slash: %s", view)
	}
	model.input.SetValue("/mo")
	view = model.View()
	if !strings.Contains(view, "/mode") || strings.Contains(view, "/provider") || strings.Contains(view, "/target") {
		t.Fatalf("setup command recommendations were not filtered: %s", view)
	}
}

func TestSetupCommandListIncludesFreshRunControls(t *testing.T) {
	commands := make(map[string]bool, len(setupCommands))
	for _, command := range setupCommands {
		commands[strings.Fields(command[0])[0]] = true
	}
	for _, command := range []string{"/budget", "/turns", "/scope", "/mount", "/target-list", "/prompt-file"} {
		if !commands[command] {
			t.Fatalf("setup command list is missing %s", command)
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
		Model:        "openai/gpt-5.4",
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
		"openai/gpt-5.4",
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
	if view := model.View(); !strings.Contains(view, "Type / to configure your scan") {
		t.Fatalf("setup snapshot did not show the start screen: %s", view)
	}

	runningState := protocol.Snapshot{
		SetupMode:   false,
		ScanStarted: true,
		ScanState:   "running",
	}
	model.openPicker(pickerProvider)
	model.handleEnvelope(stateEnvelope(t, 2, runningState))
	model.handleEnvelope(bootstrapEnvelope(t, "agents", 1, protocol.Agent{ID: "one", Name: "LIVE_AGENT", Status: "running"}))
	view := model.View()
	if !strings.Contains(view, "LIVE_AGENT") || !strings.Contains(view, "Send a message") || strings.Contains(view, "Configure your pentest") {
		t.Fatalf("started snapshot did not switch to the live view: %s", view)
	}
	if model.input.Placeholder != "Send a message" {
		t.Fatalf("live input placeholder was not updated: %q", model.input.Placeholder)
	}
	if model.picker != pickerNone {
		t.Fatalf("setup picker remained open after scan start: %v", model.picker)
	}
}

func TestDelayedSetupResultCannotReopenPickerAfterScanStart(t *testing.T) {
	client := newClient(&recordingConn{})
	model := New(client)
	model.snapshot = protocol.Snapshot{ScanStarted: true, ScanState: "running"}
	client.pending["request-1"] = "models.list"
	client.pendingByKey["models.list"] = "request-1"
	client.requestKeyByID["request-1"] = "models.list"
	result := rawJSON(t, protocol.CommandResult{
		OK: true, Command: "models.list", Result: rawJSON(t, protocol.ModelsResult{
			ListingID: "listing", Cursor: 0, NextCursor: 1, Done: true,
			Groups: []protocol.ModelGroup{{Provider: "openai", Models: []string{"openai/gpt-5"}}},
		}),
	})

	model.handleEnvelope(protocol.Envelope{
		Version: protocol.Version, Type: "command_result", RequestID: "request-1", Payload: result,
	})

	if model.picker != pickerNone || len(model.options) != 0 {
		t.Fatalf("delayed setup result reopened picker: picker=%v options=%#v", model.picker, model.options)
	}
}

func TestSetupStartScreenFitsNarrowTerminal(t *testing.T) {
	model := New(nil)
	model.width, model.height = 40, 18
	model.showSplash = false
	model.handleEnvelope(stateEnvelope(t, 1, protocol.Snapshot{SetupMode: true, ScanState: "setup"}))
	model.input.SetValue("/")
	model.resizeViewport()

	view := model.viewInner()
	if !strings.Contains(view, "STRIX") {
		t.Fatalf("compact start screen logo is missing: %s", view)
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

func TestModelCommandUsesAggregateRequestWithoutChangingSnapshotProvider(t *testing.T) {
	model, connection := newCommandTestModel(t)
	provider := "anthropic"
	state := protocol.Snapshot{
		SetupMode: true,
		ScanState: "setup",
		Provider:  &provider,
		Model:     "anthropic/claude-sonnet-4",
	}
	model.handleEnvelope(stateEnvelope(t, 1, state))

	if model.configProvider != "" {
		t.Fatalf("snapshot provider leaked into configuration state: %q", model.configProvider)
	}
	updated, cmd := model.submitSetup("/model")
	result := updated.(Model)
	envelope := commandFromCmd(t, cmd, connection)
	if envelope.Type != "models.list" || string(envelope.Payload) != "{}" {
		t.Fatalf("/model request = %s %s", envelope.Type, envelope.Payload)
	}
	if len(result.setupLog) != 0 {
		t.Fatalf("/model reported a setup error: %#v", result.setupLog)
	}
	if result.snapshot.Provider == nil || *result.snapshot.Provider != provider || result.snapshot.Model != "anthropic/claude-sonnet-4" {
		t.Fatalf("/model changed the snapshot selection: %#v", result.snapshot)
	}
}

func TestModeCommandOpensPickerAndUpdatesSetupSummary(t *testing.T) {
	model := New(nil)
	model.snapshot.SetupMode = true
	model.snapshot.ScanMode = "deep"

	updated, cmd := model.submitSetup("/mode")
	model = updated.(Model)
	if cmd != nil || model.picker != pickerScanMode {
		t.Fatalf("/mode did not open mode picker: picker=%v cmd=%v", model.picker, cmd)
	}
	if got := strings.Join(model.filtered, ","); got != "quick,standard,deep" {
		t.Fatalf("mode options = %q", got)
	}

	handleCommandResult(t, &model, "setup.set_mode", map[string]string{"mode": "standard"})
	if model.snapshot.ScanMode != "standard" {
		t.Fatalf("mode result was not applied: %q", model.snapshot.ScanMode)
	}
}

func TestModeCommandAcceptsInlineValue(t *testing.T) {
	model := New(nil)
	model.snapshot.SetupMode = true

	_, cmd := model.submitSetup("/mode quick")

	if cmd == nil {
		t.Fatal("/mode quick did not send the mode command")
	}
}

func TestAdditionalSetupCommandsSendBackendRequests(t *testing.T) {
	tests := []struct {
		input   string
		command string
		payload map[string]any
	}{
		{"/budget 5.5", "setup.set_budget", map[string]any{"budget": 5.5}},
		{"/budget off", "setup.set_budget", map[string]any{"budget": nil}},
		{"/turns 250", "setup.set_max_turns", map[string]any{"turns": float64(250)}},
		{"/scope diff origin/main", "setup.set_scope", map[string]any{"mode": "diff", "base": "origin/main"}},
		{"/mount /workspace/source", "setup.add_mount", map[string]any{"path": "/workspace/source"}},
		{"/target-list targets.txt", "setup.load_target_list", map[string]any{"path": "targets.txt"}},
		{"/prompt-file prompt.txt", "setup.load_instruction_file", map[string]any{"path": "prompt.txt"}},
	}

	for _, test := range tests {
		t.Run(test.command+test.input, func(t *testing.T) {
			model, connection := newCommandTestModel(t)
			model.snapshot.SetupMode = true
			_, cmd := model.submitSetup(test.input)
			envelope := commandFromCmd(t, cmd, connection)
			if envelope.Type != test.command {
				t.Fatalf("command = %q, want %q", envelope.Type, test.command)
			}
			var payload map[string]any
			if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(payload, test.payload) {
				t.Fatalf("payload = %#v, want %#v", payload, test.payload)
			}
		})
	}
}

func TestAdditionalSetupCommandResultsUpdateSummaryState(t *testing.T) {
	model := New(nil)
	handleCommandResult(t, &model, "setup.set_budget", map[string]any{"budget": 7.25})
	handleCommandResult(t, &model, "setup.set_max_turns", map[string]any{"turns": 333})
	handleCommandResult(t, &model, "setup.set_scope", map[string]any{"mode": "diff", "base": "origin/main"})

	if model.snapshot.MaxBudgetUSD == nil || *model.snapshot.MaxBudgetUSD != 7.25 {
		t.Fatalf("budget result was not applied: %#v", model.snapshot.MaxBudgetUSD)
	}
	if model.snapshot.MaxTurns != 333 {
		t.Fatalf("turn result was not applied: %d", model.snapshot.MaxTurns)
	}
	if model.snapshot.ScopeMode != "diff" || model.snapshot.DiffBase != "origin/main" {
		t.Fatalf("scope result was not applied: %q %q", model.snapshot.ScopeMode, model.snapshot.DiffBase)
	}
}

func TestAdditionalSetupCommandsRejectInvalidInlineValues(t *testing.T) {
	for _, command := range []string{"/budget 0", "/budget NaN", "/turns 0", "/turns nope", "/scope invalid"} {
		model := New(nil)
		model.snapshot.SetupMode = true
		updated, cmd := model.submitSetup(command)
		result := updated.(Model)
		if cmd != nil || len(result.setupLog) == 0 {
			t.Fatalf("invalid command %q was sent or did not report an error", command)
		}
	}
}

func TestSetupCommandKeyboardSelectionSubmits(t *testing.T) {
	model := New(nil)
	model.snapshot.SetupMode = true
	model.focus = focusInput
	model.input.SetValue("/")

	updated, _ := model.updateMain(tea.KeyMsg{Type: tea.KeyDown})
	model = updated.(Model)
	if model.commandCursor != 1 {
		t.Fatalf("down did not select the next command: %d", model.commandCursor)
	}
	updated, cmd := model.updateMain(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if model.input.Value() != "" || cmd == nil {
		t.Fatalf("enter did not submit selected /model command: value=%q cmd=%v", model.input.Value(), cmd)
	}
}

func TestEnterSubmitsTopFilteredSetupCommand(t *testing.T) {
	model := New(nil)
	model.snapshot.SetupMode = true
	model.focus = focusInput
	model.input.SetValue("/he")

	updated, cmd := model.updateMain(tea.KeyMsg{Type: tea.KeyEnter})
	result := updated.(Model)
	if cmd != nil || result.input.Value() != "" {
		t.Fatalf("enter did not submit top result: value=%q cmd=%v", result.input.Value(), cmd)
	}
	if len(result.setupLog) != 0 {
		t.Fatalf("selected /help should not be echoed: %#v", result.setupLog)
	}
}

func TestSubmittedSetupCommandIsNotEchoedInOutput(t *testing.T) {
	model := New(nil)
	model.snapshot.SetupMode = true
	updated, _ := model.submitSetup("/prompt secret instruction")
	result := updated.(Model)
	content := result.setupContent()
	if strings.Contains(content, "/prompt") || strings.Contains(content, "> secret instruction") {
		t.Fatalf("submitted slash command leaked into output: %s", content)
	}
}

func TestEmptyPickerSubmitDoesNotSelect(t *testing.T) {
	model := New(nil)
	model.picker = pickerProvider
	model.options = []string{"openai"}
	model.pickerInput.SetValue("not-a-provider")
	model.filterOptions()
	updated, cmd := model.updatePicker(tea.KeyMsg{Type: tea.KeyEnter})
	result := updated.(Model)
	if cmd != nil || result.picker != pickerProvider {
		t.Fatal("empty search submit selected or closed the picker")
	}
}

func TestAggregateModelsFlattenInProviderOrderAndSearchLabelAndID(t *testing.T) {
	model := New(nil)
	model.snapshot.Model = "openai/gpt-5"
	handleCommandResult(t, &model, "models.list", protocol.ModelsResult{Groups: []protocol.ModelGroup{
		{Provider: "openai", Label: "OpenAI", Models: []string{"openai/gpt-5"}},
		{Provider: "custom-local", Label: "Local GPU", Models: []string{"custom-local/qwen"}, AllowManual: true},
		{Provider: "broken", Label: "Broken Cloud", Error: "authentication failed"},
	}})

	if model.picker != pickerModel || len(model.options) != 3 {
		t.Fatalf("aggregate models did not open a three-row picker: picker=%v options=%#v", model.picker, model.options)
	}
	rows := []string{
		model.modelOptionLabel(model.options[0]),
		model.modelOptionLabel(model.options[1]),
		model.modelOptionLabel(model.options[2]),
	}
	if !strings.Contains(rows[0], "→ OpenAI  openai/gpt-5") ||
		!strings.Contains(rows[1], "Local GPU  custom-local/qwen") ||
		!strings.Contains(rows[2], "Local GPU  Enter model ID...") {
		t.Fatalf("unexpected flattened model rows: %#v", rows)
	}
	if content := ansi.Strip(model.setupContent()); !strings.Contains(content, "Broken Cloud: authentication failed") {
		t.Fatalf("group error was not surfaced: %s", content)
	}

	model.pickerInput.SetValue("local gpu")
	model.filterOptions()
	if len(model.filtered) != 2 {
		t.Fatalf("provider label search returned %d rows: %#v", len(model.filtered), model.filtered)
	}
	model.pickerInput.SetValue("qwen")
	model.filterOptions()
	if len(model.filtered) != 1 || model.modelOptions[model.filtered[0]].model != "custom-local/qwen" {
		t.Fatalf("model ID search returned %#v", model.filtered)
	}
}

func TestPagedModelsAccumulateSplitGroupsAndOpenPickerOnlyWhenDone(t *testing.T) {
	model, connection := newCommandTestModel(t)
	first := protocol.ModelsResult{
		ListingID: "listing-1", Cursor: 0, NextCursor: 1,
		Groups: []protocol.ModelGroup{{Provider: "openai", Label: "OpenAI", Models: []string{"openai/one"}}},
	}
	cmd := handleCommandResult(t, &model, "models.list", first)
	if model.picker != pickerNone || len(model.options) != 0 || cmd == nil {
		t.Fatalf("partial model page became visible: picker=%v options=%#v cmd=%v", model.picker, model.options, cmd)
	}
	request := commandFromCmd(t, cmd, connection)
	if request.Type != "models.list" || !strings.Contains(string(request.Payload), `"cursor":1`) || !strings.Contains(string(request.Payload), `"listing_id":"listing-1"`) {
		t.Fatalf("next model page request = %#v", request)
	}

	second := protocol.ModelsResult{
		ListingID: "listing-1", Cursor: 1, NextCursor: 2, Done: true,
		Groups: []protocol.ModelGroup{{Provider: "openai", Label: "OpenAI", Models: []string{"openai/two"}, AllowManual: true}},
	}
	payload := rawJSON(t, protocol.CommandResult{OK: true, Command: "models.list", Result: rawJSON(t, second)})
	model.handleEnvelope(protocol.Envelope{
		Version: protocol.Version, Type: "command_result", RequestID: request.RequestID, Payload: payload,
	})
	if model.picker != pickerModel || len(model.options) != 3 {
		t.Fatalf("completed model listing was not installed: picker=%v options=%#v", model.picker, model.options)
	}
	if got := model.modelOptions[model.options[1]].model; got != "openai/two" {
		t.Fatalf("split provider group was not merged: %q", got)
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

func TestModelSelectionSendsProviderFromGroup(t *testing.T) {
	model, connection := newCommandTestModel(t)
	snapshotProvider := "anthropic"
	model.snapshot.Provider = &snapshotProvider
	model.snapshot.Model = "anthropic/claude"
	handleCommandResult(t, &model, "models.list", protocol.ModelsResult{Groups: []protocol.ModelGroup{
		{Provider: "openai", Label: "OpenAI", Models: []string{"openai/gpt-5"}},
	}})

	_, cmd := model.selectPickerOption(0)
	envelope := commandFromCmd(t, cmd, connection)
	var payload struct {
		Provider string `json:"provider"`
		Model    string `json:"model"`
	}
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if envelope.Type != "setup.select_model" || payload.Provider != "openai" || payload.Model != "openai/gpt-5" {
		t.Fatalf("model selection sent %s %#v", envelope.Type, payload)
	}
	if model.snapshot.Provider == nil || *model.snapshot.Provider != snapshotProvider || model.snapshot.Model != "anthropic/claude" {
		t.Fatalf("model picker changed snapshot selection: %#v", model.snapshot)
	}
}

func TestMouseSelectsAggregateModelWithoutChangingOptionGeometry(t *testing.T) {
	model, connection := newCommandTestModel(t)
	model.width, model.height = 100, 30
	handleCommandResult(t, &model, "models.list", protocol.ModelsResult{Groups: []protocol.ModelGroup{
		{Provider: "openai", Label: "OpenAI", Models: []string{"openai/gpt-5"}},
		{Provider: "anthropic", Label: "Anthropic", Models: []string{"anthropic/claude"}},
	}})

	_, top, _, _ := model.centeredViewBounds(model.pickerView())
	updated, cmd := model.updateMouse(tea.MouseMsg{
		X: model.width / 2, Y: top + 9, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress,
	})
	model = updated.(Model)
	if model.picker != pickerModel {
		t.Fatalf("model picker closed before correlated success: %v", model.picker)
	}
	envelope := commandFromCmd(t, cmd, connection)
	var payload map[string]string
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["provider"] != "anthropic" || payload["model"] != "anthropic/claude" {
		t.Fatalf("mouse selected wrong aggregate model: %#v", payload)
	}
}

func TestManualModelSentinelScopesAndPrefixesCustomProviderOnce(t *testing.T) {
	model, connection := newCommandTestModel(t)
	handleCommandResult(t, &model, "models.list", protocol.ModelsResult{Groups: []protocol.ModelGroup{
		{Provider: "custom-local", Label: "Local GPU", AllowManual: true},
	}})

	updated, cmd := model.selectPickerOption(0)
	model = updated.(Model)
	if cmd != nil || model.picker != pickerManualModel || model.manualModelProvider != "custom-local" {
		t.Fatalf("manual sentinel did not open scoped entry: picker=%v provider=%q cmd=%v", model.picker, model.manualModelProvider, cmd)
	}
	model.pickerInput.SetValue("custom-local/custom-local/qwen-2.5")
	updated, cmd = model.updatePicker(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	envelope := commandFromCmd(t, cmd, connection)
	var payload map[string]string
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["provider"] != "custom-local" || payload["model"] != "custom-local/qwen-2.5" {
		t.Fatalf("manual model payload = %#v", payload)
	}
	if model.picker != pickerManualModel {
		t.Fatalf("manual model picker closed before correlated success: %v", model.picker)
	}
}

func TestEmptyAggregateModelsDirectsToProvider(t *testing.T) {
	model := New(nil)
	handleCommandResult(t, &model, "models.list", protocol.ModelsResult{Providers: []protocol.Provider{
		{Name: "anthropic", Label: "Anthropic", State: "missing", Detail: "needs key"},
		{Name: "__add_custom__", Label: "+ Add custom provider", Configured: true},
	}})

	if model.picker != pickerProvider {
		t.Fatalf("empty models did not open provider picker: %v", model.picker)
	}
	if len(model.options) != 2 || model.options[0] != "anthropic" {
		t.Fatalf("provider options = %#v", model.options)
	}
}

func TestPickerInputDoesNotMirrorMainInput(t *testing.T) {
	model := New(nil)
	model.input.SetValue("main draft")
	model.openPicker(pickerAPIKey)

	updated, _ := model.updatePicker(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("secret")})
	result := updated.(Model)
	if result.input.Value() != "main draft" {
		t.Fatalf("picker changed main input: %q", result.input.Value())
	}
	if result.pickerInput.Value() != "secret" {
		t.Fatalf("API key was not entered in picker input: %q", result.pickerInput.Value())
	}
}

func TestAPIKeyIsClearedWhilePickerWaitsForCorrelatedResult(t *testing.T) {
	model, connection := newCommandTestModel(t)
	model.picker = pickerAPIKey
	model.configProvider = "anthropic"
	model.pickerInput.SetValue("super-secret")

	updated, cmd := model.updatePicker(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	envelope := commandFromCmd(t, cmd, connection)
	if model.pickerInput.Value() != "" {
		t.Fatal("submitted API key remained in the input field")
	}
	if model.picker != pickerAPIKey {
		t.Fatal("API key picker closed before correlated success")
	}
	if !strings.Contains(string(envelope.Payload), "super-secret") {
		t.Fatal("API key was not sent to the backend")
	}
}

func TestAddCustomProviderPickerAcceptsOptionalAPIKey(t *testing.T) {
	model := New(nil)
	model.options = []string{"openai", "__add_custom__"}
	model.providerLabels = map[string]string{"__add_custom__": "+ Add custom provider"}
	model.openPicker(pickerProvider)

	updated, cmd := model.selectPickerOption(1)
	model = updated.(Model)
	if cmd != nil || model.picker != pickerCustomKind {
		t.Fatalf("custom option did not open compatibility picker: picker=%v cmd=%v", model.picker, cmd)
	}
	updated, _ = model.selectPickerOption(2)
	model = updated.(Model)
	if model.picker != pickerCustomName || model.customKind != "vllm" {
		t.Fatalf("vLLM compatibility was not selected: picker=%v kind=%q", model.picker, model.customKind)
	}
	model.pickerInput.SetValue("Local GPU")
	updated, _ = model.updatePicker(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	model.pickerInput.SetValue("http://localhost:8000")
	updated, _ = model.updatePicker(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	updated, cmd = model.updatePicker(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if cmd == nil || model.picker != pickerCustomAPIKey {
		t.Fatalf("empty optional key was not submitted: picker=%v cmd=%v", model.picker, cmd)
	}
}

func TestProviderPickerFiltersCustomDisplayName(t *testing.T) {
	model := New(nil)
	model.options = []string{"openai", "custom-123", "__add_custom__"}
	model.providerLabels = map[string]string{
		"custom-123":     "Local GPU",
		"__add_custom__": "+ Add custom provider",
	}
	model.openPicker(pickerProvider)
	model.pickerInput.SetValue("local gpu")
	model.filterOptions()

	if len(model.filtered) != 1 || model.filtered[0] != "custom-123" {
		t.Fatalf("custom display name was not searchable: %#v", model.filtered)
	}
}

func TestProviderConfigurationUsesBackendStatusWithoutChangingSelection(t *testing.T) {
	model := New(nil)
	selectedProvider := "anthropic"
	model.snapshot.Provider = &selectedProvider
	model.snapshot.Model = "anthropic/claude"
	handleCommandResult(t, &model, "providers.list", protocol.ProvidersResult{Providers: []protocol.Provider{
		{Name: "openai", Label: "OpenAI", Configured: true, State: "external", Detail: "authenticated by environment"},
	}})

	if label := model.providerOptionLabel("openai"); !strings.Contains(label, "◇ OpenAI") || !strings.Contains(label, "authenticated by environment") {
		t.Fatalf("provider label did not use backend state/detail: %q", label)
	}
	updated, cmd := model.selectPickerOption(0)
	model = updated.(Model)
	if cmd == nil || model.configProvider != "openai" {
		t.Fatalf("provider was not selected for configuration: provider=%q cmd=%v", model.configProvider, cmd)
	}
	if model.snapshot.Provider == nil || *model.snapshot.Provider != selectedProvider || model.snapshot.Model != "anthropic/claude" {
		t.Fatalf("provider configuration changed selected model/provider: %#v", model.snapshot)
	}

	handleCommandResult(t, &model, "setup.select_provider", map[string]any{
		"name": "openai", "label": "OpenAI", "configured": true,
		"state": "external", "detail": "authenticated by environment",
	})
	if message := ansi.Strip(model.setupContent()); !strings.Contains(message, "authenticated by environment") {
		t.Fatalf("provider result did not report backend detail: %s", message)
	}
	if model.snapshot.Provider == nil || *model.snapshot.Provider != selectedProvider || model.snapshot.Model != "anthropic/claude" {
		t.Fatalf("provider result changed selected model/provider: %#v", model.snapshot)
	}
}

func TestInvalidSavedProviderKeyOpensReplacementPrompt(t *testing.T) {
	model := New(nil)
	keyEnv := "ANTHROPIC_API_KEY"
	handleCommandResult(t, &model, "setup.select_provider", map[string]any{
		"name": "anthropic", "label": "Anthropic", "configured": false,
		"key_env": &keyEnv, "state": "invalid", "detail": "ANTHROPIC_API_KEY was rejected",
	})

	if model.picker != pickerAPIKey || model.configProvider != "anthropic" {
		t.Fatalf("invalid key did not open replacement prompt: picker=%v provider=%q", model.picker, model.configProvider)
	}
	if message := ansi.Strip(model.providerOptionLabel("anthropic")); !strings.HasPrefix(message, "!") {
		t.Fatalf("invalid provider marker = %q", message)
	}
}

func TestInvalidEnvironmentKeyShowsGuidanceWithoutPrompt(t *testing.T) {
	model := New(nil)
	handleCommandResult(t, &model, "setup.select_provider", map[string]any{
		"name": "anthropic", "label": "Anthropic", "configured": false,
		"key_env": nil, "state": "invalid", "detail": "update it in the environment and restart Strix",
	})

	if model.picker != pickerNone {
		t.Fatalf("environment key opened an in-app prompt: %v", model.picker)
	}
	if message := ansi.Strip(model.setupContent()); !strings.Contains(message, "update it in the environment") {
		t.Fatalf("environment guidance missing: %q", message)
	}
}

func TestMouseSelectsProviderOption(t *testing.T) {
	model := New(nil)
	model.width, model.height = 100, 30
	model.options = []string{"openai", "anthropic"}
	model.openPicker(pickerProvider)

	_, top, _, _ := model.centeredViewBounds(model.pickerView())
	updated, cmd := model.updateMouse(tea.MouseMsg{
		X:      model.width / 2,
		Y:      top + 9,
		Button: tea.MouseButtonLeft,
		Action: tea.MouseActionPress,
	})
	result := updated.(Model)
	if result.configProvider != "anthropic" || result.picker != pickerNone || cmd == nil {
		t.Fatalf("mouse did not select provider to configure: provider=%q picker=%v cmd=%v", result.configProvider, result.picker, cmd)
	}
}

func TestRapidWheelEventsDoNotMutateProviderOrModelSearch(t *testing.T) {
	for _, picker := range []pickerMode{pickerProvider, pickerModel} {
		t.Run(pickerPlaceholderForTest(picker), func(t *testing.T) {
			model := New(nil)
			for index := range 40 {
				model.options = append(model.options, fmt.Sprintf("option-%02d", index))
			}
			model.openPicker(picker)

			for range 1_000 {
				updated, _ := model.updateMouse(tea.MouseMsg{Button: tea.MouseButtonWheelDown})
				model = updated.(Model)
			}
			if model.cursor != len(model.filtered)-1 || model.pickerInput.Value() != "" {
				t.Fatalf("wheel down changed search or failed to clamp: cursor=%d search=%q", model.cursor, model.pickerInput.Value())
			}

			for range 1_000 {
				updated, _ := model.updateMouse(tea.MouseMsg{Button: tea.MouseButtonWheelUp})
				model = updated.(Model)
			}
			if model.cursor != 0 || model.pickerInput.Value() != "" {
				t.Fatalf("wheel up changed search or failed to clamp: cursor=%d search=%q", model.cursor, model.pickerInput.Value())
			}
		})
	}
}

func pickerPlaceholderForTest(picker pickerMode) string {
	if picker == pickerProvider {
		return "provider"
	}
	return "model"
}

func TestProviderDisconnectButtonSendsDisconnectCommand(t *testing.T) {
	model, connection := newCommandTestModel(t)
	model.width, model.height = 100, 30
	model.options = []string{"anthropic"}
	model.providerLabels = map[string]string{"anthropic": "Anthropic"}
	model.providerConfigured = map[string]bool{"anthropic": true}
	model.providerStates = map[string]string{"anthropic": "configured"}
	model.providerDetails = map[string]string{"anthropic": "saved key"}
	model.providerDisconnectable["anthropic"] = true
	model.openPicker(pickerProvider)

	view := model.pickerView()
	left, top, _, _ := model.centeredViewBounds(view)
	x, y := -1, -1
	for row, line := range strings.Split(view, "\n") {
		plain := ansi.Strip(line)
		if index := strings.Index(plain, "[disconnect]"); index >= 0 {
			x, y = left+ansi.StringWidth(plain[:index])+1, top+row
			break
		}
	}
	if x < 0 {
		t.Fatal("disconnect button was not rendered")
	}

	updated, cmd := model.updateMouse(tea.MouseMsg{X: x, Y: y, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
	result := updated.(Model)
	if result.picker != pickerProvider {
		t.Fatal("disconnect button closed provider picker")
	}
	envelope := commandFromCmd(t, cmd, connection)
	if envelope.Type != "setup.disconnect_provider" || !strings.Contains(string(envelope.Payload), "anthropic") {
		t.Fatalf("unexpected disconnect command: %#v", envelope)
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
	updated, _ := model.updateModal(tea.KeyMsg{Type: tea.KeyLeft})
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
	if cmd == nil || model.modalChoice != 0 {
		t.Fatalf("mouse Copy was not activated: choice=%d cmd=%v", model.modalChoice, cmd)
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
	if view := ansi.Strip(model.agentsView(50, 10)); !strings.Contains(view, "⏷") {
		t.Fatalf("expanded agent does not show the large disclosure icon: %s", view)
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
	if view := ansi.Strip(result.agentsView(50, 10)); !strings.Contains(view, "⏵") {
		t.Fatalf("collapsed agent does not show the large disclosure icon: %s", view)
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
	top := strings.Split(ansi.Strip(verticalScrollbar(6, 24, 6, 0)), "\n")
	bottom := strings.Split(ansi.Strip(verticalScrollbar(6, 24, 6, 18)), "\n")

	if top[0] != "█" || top[5] != "│" {
		t.Fatalf("top scrollbar is incorrect: %#v", top)
	}
	if bottom[0] != "│" || bottom[5] != "█" {
		t.Fatalf("bottom scrollbar is incorrect: %#v", bottom)
	}
	if full := verticalScrollbar(4, 4, 4, 0); full != "" {
		t.Fatalf("non-overflowing scrollbar should be hidden: %q", full)
	}
	withoutBar := ansi.Strip(withVerticalScrollbar("content", 12, 2, 2, 2, 0))
	if strings.ContainsAny(withoutBar, "│█") {
		t.Fatalf("non-overflowing panel rendered a scrollbar: %q", withoutBar)
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
