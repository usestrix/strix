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

// startVerify returns the verify flag on the setup.start command, and whether
// a setup.start command was present at all.
func startVerify(t *testing.T, envelopes []protocol.Envelope) (verify, found bool) {
	t.Helper()
	for _, envelope := range envelopes {
		if envelope.Type != "setup.start" {
			continue
		}
		var payload struct {
			Verify bool `json:"verify"`
		}
		if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		return payload.Verify, true
	}
	return false, false
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

// A bare prompt would mount the working directory, so it asks first instead of
// launching. Nothing is sent until the user confirms.
func TestSetupPromptWithoutTargetAsksBeforeMounting(t *testing.T) {
	connection := &recordingConn{}
	model := New(&Client{conn: connection})
	model.snapshot = protocol.Snapshot{SetupMode: true, WorkingDir: "/Users/me/code/api"}

	updated, cmd := model.submit("find auth bugs in the login flow")
	model = updated.(Model)

	if model.modal != modalConfirmMount {
		t.Fatalf("bare prompt did not open the mount confirmation: modal=%v", model.modal)
	}
	if model.modalChoice != 1 {
		t.Fatalf("consent prompt should default to declining, got choice %d", model.modalChoice)
	}
	if types := commandTypes(drainCommands(t, cmd, connection)); len(types) != 0 {
		t.Fatalf("nothing should be sent before consent, got %v", types)
	}
	if model.pendingPrompt != "find auth bugs in the login flow" {
		t.Fatalf("prompt was not held for the confirmation: %q", model.pendingPrompt)
	}
	// The dialog has to name the directory being mounted.
	if view := ansi.Strip(model.mountConfirmView()); !strings.Contains(view, "/Users/me/code/api") {
		t.Fatalf("confirmation does not name the directory: %s", view)
	}
}

// Confirming mounts the working directory: the prompt becomes the instruction
// and the scan launches optimistically with consent recorded.
func TestMountConfirmationLaunches(t *testing.T) {
	connection := &recordingConn{}
	model := New(&Client{conn: connection})
	model.snapshot = protocol.Snapshot{SetupMode: true, WorkingDir: "/Users/me/code/api"}

	updated, _ := model.submit("find auth bugs in the login flow")
	model = updated.(Model)
	model.modalChoice = 0 // Confirm
	updated, cmd := model.updateModal(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)

	envelopes := drainCommands(t, cmd, connection)
	types := commandTypes(envelopes)
	if !contains(types, "setup.set_instruction") || !contains(types, "setup.start") {
		t.Fatalf("confirmation did not launch: %v", types)
	}
	if mount, found := startPayloadFlag(t, envelopes, "mount_working_dir"); !found || !mount {
		t.Fatalf("consent was not sent: mount_working_dir=%v found=%v", mount, found)
	}
	// A bare prompt launches optimistically: no model preflight.
	if verify, found := startVerify(t, envelopes); !found || verify {
		t.Fatalf("bare prompt should launch with verify=false, got verify=%v found=%v", verify, found)
	}
	// setup.start leaves setup mode, so it must be the last command sent.
	if start, instr := firstIndex(types, "setup.start"), lastIndex(types, "setup.set_instruction"); start < instr {
		t.Fatalf("setup.start (%d) must come after setup.set_instruction (%d): %v", start, instr, types)
	}
	if model.modal != modalNone {
		t.Fatalf("modal stayed open after confirming: %v", model.modal)
	}
}

// Declining sends nothing and puts the prompt back so a target can be added.
func TestMountConfirmationDeclineRestoresPrompt(t *testing.T) {
	for _, decline := range []tea.KeyMsg{{Type: tea.KeyEsc}, {Type: tea.KeyEnter}} {
		connection := &recordingConn{}
		model := New(&Client{conn: connection})
		model.width, model.height = 130, 40
		model.snapshot = protocol.Snapshot{SetupMode: true, WorkingDir: "/Users/me/code/api"}

		updated, _ := model.submit("find auth bugs in the login flow")
		model = updated.(Model)
		// KeyEnter here lands on the default choice, which is Cancel.
		updated, cmd := model.updateModal(decline)
		model = updated.(Model)

		if types := commandTypes(drainCommands(t, cmd, connection)); len(types) != 0 {
			t.Fatalf("%v: declining should send nothing, got %v", decline.Type, types)
		}
		if model.modal != modalNone {
			t.Fatalf("%v: modal stayed open after declining", decline.Type)
		}
		if got := model.input.Value(); got != "find auth bugs in the login flow" {
			t.Fatalf("%v: prompt was not restored, got %q", decline.Type, got)
		}
		if model.pendingPrompt != "" {
			t.Fatalf("%v: pending prompt was not cleared: %q", decline.Type, model.pendingPrompt)
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
	// A named target keeps the upfront model check.
	if verify, found := startVerify(t, envelopes); !found || !verify {
		t.Fatalf("targeted prompt should launch with verify=true, got verify=%v found=%v", verify, found)
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
