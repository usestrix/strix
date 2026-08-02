package app

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func inputModel(t *testing.T) Model {
	t.Helper()
	model := New(nil)
	model.showSplash = false
	model.ready = true
	model.width, model.height = 130, 40
	model.resizeViewport()
	return model
}

func TestInputGrowsWithContentUpToCap(t *testing.T) {
	model := inputModel(t)
	if got := model.input.Height(); got != 1 {
		t.Fatalf("empty composer height = %d, want 1", got)
	}
	model.input.SetValue(strings.Repeat("line\n", 3) + "line")
	model.resizeViewport()
	if got := model.input.Height(); got != 4 {
		t.Fatalf("4-line composer height = %d, want 4", got)
	}
	model.input.SetValue(strings.Repeat("line\n", 19) + "line")
	model.resizeViewport()
	if got := model.input.Height(); got != maxInputLines {
		t.Fatalf("20-line composer height = %d, want %d", got, maxInputLines)
	}
}

func TestCtrlJInsertsNewline(t *testing.T) {
	model := inputModel(t)
	model.input.SetValue("hello")
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyCtrlJ})
	model = updated.(Model)
	if got := model.input.Value(); got != "hello\n" {
		t.Fatalf("value after ctrl+j = %q, want %q", got, "hello\n")
	}
}

func TestEnterSubmitsTrimmedMultilineMessage(t *testing.T) {
	model := inputModel(t)
	model.input.SetValue("first\nsecond ")
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if got := model.input.Value(); got != "" {
		t.Fatalf("composer not cleared after submit: %q", got)
	}
	if got := model.input.Height(); got != 1 {
		t.Fatalf("composer height after submit = %d, want 1", got)
	}
}

func TestDragSelectionInInputCopiesText(t *testing.T) {
	model := inputModel(t)
	copied := ""
	original := writeClipboard
	writeClipboard = func(text string) error {
		copied = text
		return nil
	}
	defer func() { writeClipboard = original }()

	model.input.SetValue("copy me please")
	model.resizeViewport()
	top := model.inputTop()

	updated, _ := model.updateMouse(tea.MouseMsg{
		X: 4, Y: top + 1, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress,
	})
	model = updated.(Model)
	if !model.selection.dragging || model.selection.region != regionInput {
		t.Fatalf("press in the composer did not start an input selection: %+v", model.selection)
	}
	updated, _ = model.updateMouse(tea.MouseMsg{X: 10, Y: top + 1, Action: tea.MouseActionMotion})
	model = updated.(Model)
	updated, cmd := model.updateMouse(tea.MouseMsg{Action: tea.MouseActionRelease})
	model = updated.(Model)
	if cmd == nil {
		t.Fatal("input selection release produced no copy command")
	}
	if msg, ok := cmd().(selectionCopiedMsg); !ok || msg.err != nil {
		t.Fatalf("unexpected copy result: %#v", cmd())
	}
	if copied != "copy me" {
		t.Fatalf("copied %q, want %q", copied, "copy me")
	}
}
