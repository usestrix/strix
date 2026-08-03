package app

import (
	"encoding/binary"
	"encoding/json"
	"reflect"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
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

// A bare prompt with no target still launches: the whole prompt becomes the
// instruction and the scan starts. The backend defaults the target to the
// current directory, like any coding agent.
func TestSetupPromptWithoutTargetLaunches(t *testing.T) {
	connection := &recordingConn{}
	model := New(&Client{conn: connection})
	model.snapshot = protocol.Snapshot{SetupMode: true}

	_, cmd := model.submit("find auth bugs in the login flow")
	envelopes := drainCommands(t, cmd, connection)
	types := commandTypes(envelopes)

	if !contains(types, "setup.set_instruction") {
		t.Fatalf("prompt was not set as the instruction: %v", types)
	}
	if !contains(types, "setup.start") {
		t.Fatalf("prompt without a target did not launch: %v", types)
	}
	if contains(types, "setup.add_target") {
		t.Fatalf("a plain prompt should not add a target: %v", types)
	}
	// A bare prompt launches optimistically: no model preflight.
	if verify, found := startVerify(t, envelopes); !found || verify {
		t.Fatalf("bare prompt should launch with verify=false, got verify=%v found=%v", verify, found)
	}
	// setup.start leaves setup mode, so it must be the last command sent;
	// otherwise the instruction lands after the guard closes and errors.
	if start, instr := firstIndex(types, "setup.start"), lastIndex(types, "setup.set_instruction"); start < instr {
		t.Fatalf("setup.start (%d) must come after setup.set_instruction (%d): %v", start, instr, types)
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
