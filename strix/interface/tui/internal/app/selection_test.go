package app

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/usestrix/strix/tui/internal/protocol"
)

func selectionModel(t *testing.T) Model {
	t.Helper()
	model := New(nil)
	model.showSplash = false
	model.ready = true
	model.width, model.height = 130, 40
	model.snapshot.Agents = append(
		model.snapshot.Agents,
		protocol.Agent{ID: "root", Name: "Strix", Status: "running"},
	)
	model.resizeViewport()
	model.viewportContent = strings.Join([]string{
		" first line of the trace",
		" second line of the trace",
		" third line of the trace",
	}, "\n")
	model.viewport.SetContent(model.viewportContent)
	return model
}

func TestDragSelectionCopiesPlainText(t *testing.T) {
	model := selectionModel(t)
	copied := ""
	original := writeClipboard
	writeClipboard = func(text string) error {
		copied = text
		return nil
	}
	defer func() { writeClipboard = original }()

	updated, _ := model.updateMouse(tea.MouseMsg{
		X: 2, Y: 1, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress,
	})
	model = updated.(Model)
	if !model.selection.dragging {
		t.Fatal("press in the trace did not start a selection")
	}
	updated, _ = model.updateMouse(tea.MouseMsg{X: 7, Y: 2, Action: tea.MouseActionMotion})
	model = updated.(Model)
	updated, cmd := model.updateMouse(tea.MouseMsg{Action: tea.MouseActionRelease})
	model = updated.(Model)
	if cmd == nil {
		t.Fatal("selection release produced no copy command")
	}
	msg := cmd()
	if copyMsg, ok := msg.(selectionCopiedMsg); !ok || copyMsg.err != nil {
		t.Fatalf("unexpected copy result: %#v", msg)
	}
	want := "first line of the trace\n second"
	if copied != want {
		t.Fatalf("copied %q, want %q", copied, want)
	}
	if model.selection.dragging || !model.selection.active {
		t.Fatalf("selection state after release: %+v", model.selection)
	}

	updated, tick := model.Update(msg)
	model = updated.(Model)
	if model.toast != "Copied to clipboard" {
		t.Fatalf("toast %q after copy", model.toast)
	}
	if !strings.Contains(model.View(), "Copied to clipboard") {
		t.Fatal("toast is not rendered")
	}
	if tick == nil {
		t.Fatal("toast was not scheduled to expire")
	}
	updated, _ = model.Update(toastExpiredMsg{id: model.toastID})
	model = updated.(Model)
	if model.toast != "" || model.selection.active {
		t.Fatalf("toast expiry left toast=%q selection=%+v", model.toast, model.selection)
	}
}

func TestPlainClickClearsSelectionWithoutCopying(t *testing.T) {
	model := selectionModel(t)
	original := writeClipboard
	writeClipboard = func(string) error {
		t.Fatal("plain click must not copy")
		return nil
	}
	defer func() { writeClipboard = original }()

	updated, _ := model.updateMouse(tea.MouseMsg{
		X: 2, Y: 1, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress,
	})
	model = updated.(Model)
	updated, cmd := model.updateMouse(tea.MouseMsg{Action: tea.MouseActionRelease})
	model = updated.(Model)
	if cmd != nil {
		t.Fatal("plain click produced a command")
	}
	if model.selection.active {
		t.Fatal("plain click left an active selection")
	}
}

func TestHighlightSelectionRestylesSelectedCells(t *testing.T) {
	model := selectionModel(t)
	model.selection = selectionState{
		active:     true,
		anchorLine: 0, anchorCol: 1,
		headLine: 0, headCol: 5,
	}

	visible := model.highlightSelection(model.viewportContent, 0)
	lines := strings.Split(visible, "\n")
	if !strings.Contains(lines[0], "\x1b[") {
		t.Fatalf("selected line was not restyled: %q", lines[0])
	}
	if strings.Contains(lines[1], "\x1b[") || strings.Contains(lines[2], "\x1b[") {
		t.Fatal("unselected lines were restyled")
	}
}

func TestSelectedTextSpansReversedDrag(t *testing.T) {
	model := selectionModel(t)
	model.selection = selectionState{
		active:     true,
		anchorLine: 2, anchorCol: 6,
		headLine: 1, headCol: 1,
	}

	want := "second line of the trace\n third"
	if got := model.selectedText(); got != want {
		t.Fatalf("selected text %q, want %q", got, want)
	}
}

func TestCleanCopiedTextStripsDecorations(t *testing.T) {
	in := "✓ Done\n  🐞 SQL injection found\n────────\n>_ curl -s http://x\nplain line"
	want := "  SQL injection found\ncurl -s http://x\nplain line"
	if got := cleanCopiedText(in); got != want {
		t.Fatalf("cleaned %q, want %q", got, want)
	}
}

func TestClickTogglesToolExpansion(t *testing.T) {
	model := New(nil)
	model.showSplash = false
	model.ready = true
	model.width, model.height = 130, 40
	model.snapshot.Agents = []protocol.Agent{{ID: "root", Name: "Strix", Status: "running"}}
	var output []string
	for i := 0; i < 20; i++ {
		output = append(output, "output line")
	}
	model.snapshot.Events = []protocol.Event{{
		ID: "ev-1", Type: "tool", AgentID: "root", Timestamp: "1",
		Data: map[string]any{
			"tool_name": "exec_command",
			"status":    "completed",
			"args":      map[string]any{"cmd": "seq 20"},
			"result":    strings.Join(output, "\n"),
		},
	}}
	model.resizeViewport()

	if !strings.Contains(model.viewportContent, "click to expand") {
		t.Fatalf("long tool output should start collapsed:\n%s", model.viewportContent)
	}
	if len(model.eventSpans) != 1 || model.eventSpans[0].eventID != "ev-1" {
		t.Fatalf("expected one expandable span, got %+v", model.eventSpans)
	}

	model.toggleEventAtLine(model.eventSpans[0].start)
	if !strings.Contains(model.viewportContent, "click to collapse") {
		t.Fatalf("click should expand the tool:\n%s", model.viewportContent)
	}
	model.toggleEventAtLine(model.eventSpans[0].start)
	if !strings.Contains(model.viewportContent, "click to expand") {
		t.Fatal("second click should collapse again")
	}
}
