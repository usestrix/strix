package app

import (
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
)

// lastIndex returns the index of the last command of the given type, or -1.
func lastIndex(types []string, want string) int {
	last := -1
	for i, value := range types {
		if value == want {
			last = i
		}
	}
	return last
}

// firstIndex returns the index of the first command of the given type, or -1.
func firstIndex(types []string, want string) int {
	for i, value := range types {
		if value == want {
			return i
		}
	}
	return -1
}

// drainCommands runs a (possibly batched) command and decodes every protocol
// frame the sends wrote to the connection, in order.
func drainCommands(t *testing.T, cmd tea.Cmd, connection *recordingConn) []protocol.Envelope {
	t.Helper()
	if cmd == nil {
		return nil
	}
	var run func(tea.Cmd)
	run = func(c tea.Cmd) {
		if c == nil {
			return
		}
		msg := c()
		switch typed := msg.(type) {
		case tea.BatchMsg:
			for _, sub := range typed {
				run(sub)
			}
		case sentMsg:
			if typed.err != nil {
				t.Fatalf("command failed: %#v", typed)
			}
		default:
			// tea.Sequence yields an unexported sequenceMsg ([]tea.Cmd); run its
			// commands in order, which is the ordering the sequence guarantees.
			if value := reflect.ValueOf(msg); value.Kind() == reflect.Slice {
				for i := 0; i < value.Len(); i++ {
					if sub, ok := value.Index(i).Interface().(tea.Cmd); ok {
						run(sub)
					}
				}
			}
		}
	}
	run(cmd)

	var envelopes []protocol.Envelope
	raw := connection.Bytes()
	for len(raw) >= 4 {
		size := int(binary.BigEndian.Uint32(raw[:4]))
		if len(raw) < size+4 {
			t.Fatalf("truncated command frame")
		}
		var envelope protocol.Envelope
		if err := json.Unmarshal(raw[4:size+4], &envelope); err != nil {
			t.Fatal(err)
		}
		envelopes = append(envelopes, envelope)
		raw = raw[size+4:]
	}
	return envelopes
}

func commandTypes(envelopes []protocol.Envelope) []string {
	types := make([]string, len(envelopes))
	for i, envelope := range envelopes {
		types[i] = envelope.Type
	}
	return types
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// startPayloadFlag reports a boolean field on the setup.start command.
func startPayloadFlag(t *testing.T, envelopes []protocol.Envelope, field string) (value, found bool) {
	t.Helper()
	for _, envelope := range envelopes {
		if envelope.Type != "setup.start" {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		flag, ok := payload[field].(bool)
		return flag, ok
	}
	return false, false
}

// A bare prompt launches straight away, asking to mount the working directory
// rather than adding it as a target. The prompt is held in case it is declined.
func TestSetupPromptWithoutTargetLaunchesAndRequestsMount(t *testing.T) {
	connection := &recordingConn{}
	model := New(&Client{conn: connection})
	model.snapshot = protocol.Snapshot{SetupMode: true, WorkingDir: "/Users/me/code/api"}

	updated, cmd := model.submit("find auth bugs in the login flow")
	model = updated.(Model)
	envelopes := drainCommands(t, cmd, connection)
	types := commandTypes(envelopes)

	if !contains(types, "setup.set_instruction") || !contains(types, "setup.start") {
		t.Fatalf("bare prompt did not launch: %v", types)
	}
	if contains(types, "setup.add_target") {
		t.Fatalf("the working directory must not be added as a target: %v", types)
	}
	if mount, found := startPayloadFlag(t, envelopes, "mount_working_dir"); !found || !mount {
		t.Fatalf("mount was not requested: mount_working_dir=%v found=%v", mount, found)
	}
	// setup.start leaves setup mode, so it must be the last command sent.
	if start, instr := firstIndex(types, "setup.start"), lastIndex(types, "setup.set_instruction"); start < instr {
		t.Fatalf("setup.start (%d) must come after setup.set_instruction (%d): %v", start, instr, types)
	}
	if model.pendingPrompt != "find auth bugs in the login flow" {
		t.Fatalf("prompt was not held in case the mount is declined: %q", model.pendingPrompt)
	}
	// The confirmation is not raised locally; the backend asks for it.
	if model.modal != modalNone {
		t.Fatalf("submit should not open a dialog itself: modal=%v", model.modal)
	}
}

// The backend asks from the live view, so the prompt follows the snapshot.
func TestPendingMountOpensAndClosesWithTheSnapshot(t *testing.T) {
	model := New(nil)
	model.width, model.height = 130, 40
	model.ready = true

	model.snapshot.PendingMount = "/Users/me/code/api"
	model.syncMountPrompt()
	if model.modal != modalConfirmMount {
		t.Fatalf("pending mount did not raise the prompt: modal=%v", model.modal)
	}
	if model.modalChoice != 1 {
		t.Fatalf("a consent prompt should default to declining, got %d", model.modalChoice)
	}
	// It names the directory the backend is waiting on, and stays compact.
	view := ansi.Strip(model.mountConfirmView())
	if !strings.Contains(view, "/Users/me/code/api") {
		t.Fatalf("prompt does not name the directory: %s", view)
	}
	if rows := strings.Count(view, "\n") + 1; rows > 6 {
		t.Fatalf("corner prompt should stay compact, got %d rows:\n%s", rows, view)
	}

	// Once the backend has the answer it clears, which closes the prompt.
	model.snapshot.PendingMount = ""
	model.syncMountPrompt()
	if model.modal != modalNone {
		t.Fatalf("prompt stayed open after the pending mount cleared: %v", model.modal)
	}
}

// Answering replies to the backend; declining puts the prompt back to edit.
func TestMountConfirmationAnswers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		key      tea.KeyMsg
		choice   int
		approved bool
	}{
		{"confirm", tea.KeyMsg{Type: tea.KeyEnter}, 0, true},
		{"cancel", tea.KeyMsg{Type: tea.KeyEnter}, 1, false},
		{"escape", tea.KeyMsg{Type: tea.KeyEsc}, 1, false},
	} {
		connection := &recordingConn{}
		model := New(&Client{conn: connection})
		model.width, model.height = 130, 40
		model.snapshot = protocol.Snapshot{SetupMode: true, WorkingDir: "/Users/me/code/api"}
		updated, _ := model.submit("find auth bugs in the login flow")
		model = updated.(Model)
		connection.Reset()
		model.snapshot.PendingMount = "/Users/me/code/api"
		model.syncMountPrompt()
		model.modalChoice = tc.choice

		updated, cmd := model.updateModal(tc.key)
		model = updated.(Model)
		envelopes := drainCommands(t, cmd, connection)

		if len(envelopes) != 1 || envelopes[0].Type != "setup.confirm_mount" {
			t.Fatalf("%s: expected one setup.confirm_mount, got %v", tc.name, commandTypes(envelopes))
		}
		var payload struct {
			Approved bool `json:"approved"`
		}
		if err := json.Unmarshal(envelopes[0].Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Approved != tc.approved {
			t.Fatalf("%s: approved=%v, want %v", tc.name, payload.Approved, tc.approved)
		}
		// Either answer launches, so the prompt stays with the run rather than
		// coming back to the composer.
		if got := model.input.Value(); got != "" {
			t.Fatalf("%s: composer = %q, want it cleared", tc.name, got)
		}
		if model.pendingPrompt != "" {
			t.Fatalf("%s: held prompt was not cleared: %q", tc.name, model.pendingPrompt)
		}
	}
}

// A prompt that names a target adds it and launches.
func TestSetupPromptWithTargetLaunches(t *testing.T) {
	connection := &recordingConn{}
	model := New(&Client{conn: connection})
	model.snapshot = protocol.Snapshot{SetupMode: true}

	_, cmd := model.submit("https://juice-shop.example.com hit the coupon endpoint")
	envelopes := drainCommands(t, cmd, connection)
	types := commandTypes(envelopes)

	for _, want := range []string{"setup.add_target", "setup.set_instruction", "setup.start"} {
		if !contains(types, want) {
			t.Fatalf("missing %s in %v", want, types)
		}
	}
	if _, found := startPayloadFlag(t, envelopes, "mount_working_dir"); found {
		t.Fatalf("a targeted prompt must not ask to mount the working directory: %v", types)
	}
	// The target and instruction must reach the backend before setup.start
	// closes the setup guard.
	start := firstIndex(types, "setup.start")
	if target := lastIndex(types, "setup.add_target"); start < target {
		t.Fatalf("setup.start (%d) must come after setup.add_target (%d): %v", start, target, types)
	}
	if instr := lastIndex(types, "setup.set_instruction"); start < instr {
		t.Fatalf("setup.start (%d) must come after setup.set_instruction (%d): %v", start, instr, types)
	}
}

// The prompt's buttons are buttons: clicking Cancel has to answer the backend,
// which it could not do while the mouse handler had no case for this modal.
func TestMountPromptButtonsAreClickable(t *testing.T) {
	for _, testCase := range []struct {
		label    string
		approved bool
	}{
		{mountConfirmLabel, true},
		{mountCancelLabel, false},
	} {
		connection := &recordingConn{}
		model := New(&Client{conn: connection})
		model.width, model.height = 130, 40
		model.snapshot = protocol.Snapshot{SetupMode: true, WorkingDir: "/Users/me/code/api"}
		updated, _ := model.submit("find auth bugs in the login flow")
		model = updated.(Model)
		connection.Reset()
		model.snapshot = protocol.Snapshot{
			ScanStarted: true, ScanState: "preparing", PendingMount: "/Users/me/code/api",
		}
		model.syncMountPrompt()

		left, top, panel := model.mountPromptBounds()
		clicked := false
		for row, line := range strings.Split(panel, "\n") {
			plain := ansi.Strip(line)
			index := strings.Index(plain, testCase.label)
			if index < 0 {
				continue
			}
			updated, cmd := model.updateModalMouse(tea.MouseMsg{
				X: left + ansi.StringWidth(plain[:index]) + 1, Y: top + row,
				Button: tea.MouseButtonLeft, Action: tea.MouseActionPress,
			})
			model = updated.(Model)
			envelopes := drainCommands(t, cmd, connection)
			if len(envelopes) != 1 || envelopes[0].Type != "setup.confirm_mount" {
				t.Fatalf("clicking %s sent %v", testCase.label, commandTypes(envelopes))
			}
			var payload struct {
				Approved bool `json:"approved"`
			}
			if err := json.Unmarshal(envelopes[0].Payload, &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Approved != testCase.approved {
				t.Fatalf("clicking %s answered approved=%v", testCase.label, payload.Approved)
			}
			clicked = true
			break
		}
		if !clicked {
			t.Fatalf("%s was not found in the prompt", testCase.label)
		}
	}
}

// Skipping the mount runs the scan without a directory. It must not throw the
// session back to the start screen, and it must not hand the prompt back: the
// run has it.
func TestSkippingTheMountKeepsTheScanRunning(t *testing.T) {
	connection := &recordingConn{}
	model := New(&Client{conn: connection})
	model.width, model.height = 130, 40
	model.snapshot = protocol.Snapshot{SetupMode: true, WorkingDir: "/Users/me/code/api"}
	updated, _ := model.submit("find auth bugs in the login flow")
	model = updated.(Model)
	model.snapshot = protocol.Snapshot{
		ScanStarted: true, ScanState: "preparing", PendingMount: "/Users/me/code/api",
	}
	model.syncMountPrompt()
	if model.modal != modalConfirmMount {
		t.Fatal("the prompt did not open")
	}

	model.modalChoice = 1
	updated, _ = model.updateModal(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)

	// The backend answers by starting the scan with no mount.
	model.handleEnvelope(stateEnvelope(t, 2, protocol.Snapshot{
		ScanStarted: true, ScanState: "running",
	}))

	if model.modal != modalNone {
		t.Fatalf("the prompt is still open: %v", model.modal)
	}
	if model.snapshot.SetupMode {
		t.Fatal("skipping the mount fell back to the start screen")
	}
	if got := model.input.Value(); got != "" {
		t.Fatalf("the prompt came back to the composer: %q", got)
	}
	if model.pendingPrompt != "" {
		t.Fatalf("the held prompt was not released: %q", model.pendingPrompt)
	}
}
