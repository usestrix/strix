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

type setupStartPayload struct {
	Instruction     string   `json:"instruction"`
	Targets         []string `json:"targets"`
	MountWorkingDir *bool    `json:"mount_working_dir"`
}

func decodeSetupStart(t *testing.T, envelopes []protocol.Envelope) setupStartPayload {
	t.Helper()
	if len(envelopes) != 1 || envelopes[0].Type != "setup.start" {
		t.Fatalf("expected one setup.start command, got %v", commandTypes(envelopes))
	}
	var payload setupStartPayload
	if err := json.Unmarshal(envelopes[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	return payload
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
	payload := decodeSetupStart(t, envelopes)

	if payload.Instruction != "find auth bugs in the login flow" {
		t.Fatalf("instruction was not preserved: %q", payload.Instruction)
	}
	if payload.Targets == nil || len(payload.Targets) != 0 {
		t.Fatalf("targetless prompt sent targets: %#v", payload.Targets)
	}
	if payload.MountWorkingDir == nil || !*payload.MountWorkingDir {
		t.Fatalf("mount was not requested: %#v", payload.MountWorkingDir)
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

func TestSetupPromptExtractsExactSchemeLessFiuuTarget(t *testing.T) {
	assertTargetedSetupStart(t, "fiuu.com", nil, []string{"fiuu.com"})
}

func TestSetupPromptExtractsOrderedSchemeLessFiuuTargets(t *testing.T) {
	prompt := "i need you to test fiuu.com/search-result/?s=, fiuu.com/blog/ (fiuu.com/blog/-9 will show you the sql query), fiuu.com/newsroom/, and fiuu.com/faq/ for sqli. all of the pages likely use mysql and the same database"
	want := []string{
		"fiuu.com/search-result/?s=",
		"fiuu.com/blog/",
		"fiuu.com/blog/-9",
		"fiuu.com/newsroom/",
		"fiuu.com/faq/",
	}
	assertTargetedSetupStart(t, prompt, nil, want)
}

func TestSetupPromptExtractsOrderedSchemeLessIPTargets(t *testing.T) {
	prompt := "i need you to test 192.0.2.10/search-result/?s=, 192.0.2.10/blog/ (192.0.2.10/blog/-9 will show you the sql query), 192.0.2.10/newsroom/, and 192.0.2.10/faq/ for sqli"
	want := []string{
		"192.0.2.10/search-result/?s=",
		"192.0.2.10/blog/",
		"192.0.2.10/blog/-9",
		"192.0.2.10/newsroom/",
		"192.0.2.10/faq/",
	}
	assertTargetedSetupStart(t, prompt, nil, want)
}

func TestSetupPromptKeepsSchemeAndNoSchemeCandidates(t *testing.T) {
	prompt := "test https://example.com, example.com, https://example.com and example.com."
	assertTargetedSetupStart(t, prompt, nil, []string{"https://example.com", "example.com"})
}

func TestSetupPromptExtractsHostSubdomainAndIPTargets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prompt string
		want   []string
	}{
		{
			name:   "mixed hosts and IP",
			prompt: "test example.com, api.example.com:8443/search?q=x#results, and 192.0.2.10:8080/admin.",
			want:   []string{"example.com", "api.example.com:8443/search?q=x#results", "192.0.2.10:8080/admin"},
		},
		{
			name:   "IP only",
			prompt: "test 192.0.2.10:8080/admin only.",
			want:   []string{"192.0.2.10:8080/admin"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertTargetedSetupStart(t, tc.prompt, nil, tc.want)
		})
	}
}

func TestSetupPromptTrimsTargetPunctuation(t *testing.T) {
	prompt := "test (\"https://example.com/path?q=x#frag\"), '[2001:db8::1]:8443/admin'; api.example.com, 2001:db8::2, localhost:3000, and https://münich.example/path."
	want := []string{
		"https://example.com/path?q=x#frag",
		"[2001:db8::1]:8443/admin",
		"api.example.com",
		"2001:db8::2",
		"localhost:3000",
		"https://münich.example/path",
	}
	assertTargetedSetupStart(t, prompt, nil, want)
}

func TestSetupPromptWithExistingTargetVerifiesWithoutMount(t *testing.T) {
	assertTargetedSetupStart(t, "focus on authentication", []string{"example.com"}, []string{})
}

func TestSetupPromptRejectsNonNetworkTokens(t *testing.T) {
	prompt := "Review README.md and main.py. Email dev@example.com about /etc/passwd, ./fixtures/site.test, and release v1.2.3-beta. This is ordinary prose."
	connection := &recordingConn{}
	model := New(&Client{conn: connection})
	model.snapshot = protocol.Snapshot{SetupMode: true}

	updated, cmd := model.submit(prompt)
	model = updated.(Model)
	payload := decodeSetupStart(t, drainCommands(t, cmd, connection))
	if payload.Instruction != prompt || payload.Targets == nil || len(payload.Targets) != 0 {
		t.Fatalf("targetless payload = %#v", payload)
	}
	if payload.MountWorkingDir == nil || !*payload.MountWorkingDir {
		t.Fatalf("targetless launch flags = %#v", payload)
	}
	if model.pendingPrompt != prompt {
		t.Fatalf("prompt was not held for mount confirmation: %q", model.pendingPrompt)
	}
}

func assertTargetedSetupStart(t *testing.T, prompt string, existing, want []string) {
	t.Helper()
	connection := &recordingConn{}
	model := New(&Client{conn: connection})
	model.snapshot = protocol.Snapshot{SetupMode: true, Targets: existing}

	updated, cmd := model.submit(prompt)
	model = updated.(Model)
	payload := decodeSetupStart(t, drainCommands(t, cmd, connection))
	if payload.Instruction != prompt {
		t.Fatalf("instruction = %q, want %q", payload.Instruction, prompt)
	}
	if !reflect.DeepEqual(payload.Targets, want) {
		t.Fatalf("targets = %#v, want %#v", payload.Targets, want)
	}
	if payload.MountWorkingDir != nil {
		t.Fatalf("targeted prompt included mount_working_dir=%v", *payload.MountWorkingDir)
	}
	if model.pendingPrompt != "" {
		t.Fatalf("targeted prompt was held for a mount: %q", model.pendingPrompt)
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
