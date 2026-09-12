package app

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
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
	// The live composer opens at a single row, out of the trace's way.
	if got := model.input.Height(); got != 1 {
		t.Fatalf("empty composer height = %d, want 1", got)
	}
	model.input.SetValue(strings.Repeat("line\n", 4) + "line")
	model.resizeViewport()
	if got := model.input.Height(); got != 5 {
		t.Fatalf("5-line composer height = %d, want 5", got)
	}
	model.input.SetValue(strings.Repeat("line\n", 19) + "line")
	model.resizeViewport()
	if got := model.input.Height(); got != maxInputLines {
		t.Fatalf("20-line composer height = %d, want %d", got, maxInputLines)
	}
}

// The launch composer opens with room to breathe; the live one stays a single
// row until there is something to show, as it always has.
func TestComposerOpeningHeightPerMode(t *testing.T) {
	live := inputModel(t)
	if got := live.input.Height(); got != 1 {
		t.Fatalf("live composer opens at %d rows, want 1", got)
	}

	setup := inputModel(t)
	setup.snapshot.SetupMode = true
	setup.resizeViewport()
	if got := setup.input.Height(); got != minInputLines {
		t.Fatalf("launch composer opens at %d rows, want %d", got, minInputLines)
	}
}

// A prompt with no newline in it still has to grow the composer once it wraps.
func TestInputGrowsWithSoftWrappedLine(t *testing.T) {
	for _, setup := range []bool{false, true} {
		model := inputModel(t)
		model.snapshot.SetupMode = setup
		model.resizeViewport()
		floor, _ := model.composerBounds()
		if got := model.input.Height(); got != floor {
			t.Fatalf("setup=%v: empty composer height = %d, want floor %d", setup, got, floor)
		}
		width := model.input.Width()
		model.input.SetValue(strings.Repeat("x", width*5-1))
		model.resizeViewport()
		// Five rows of text; the textarea adds a trailing row when the last one
		// is full, so the cursor stays visible.
		if got := model.input.Height(); got < 5 || got > 6 {
			t.Fatalf("setup=%v: wrapped composer height = %d, want 5 or 6", setup, got)
		}
		model.input.SetValue(strings.Repeat("x", width*maxInputLines*2))
		model.resizeViewport()
		if got := model.input.Height(); got != maxInputLines {
			t.Fatalf("setup=%v: overlong composer height = %d, want %d", setup, got, maxInputLines)
		}
	}
}

// The composer never takes more than a third of a short terminal.
func TestInputHeightCappedOnShortTerminal(t *testing.T) {
	model := inputModel(t)
	model.width, model.height = 130, 15
	model.input.SetValue(strings.Repeat("line\n", 10) + "line")
	model.resizeViewport()
	if got := model.input.Height(); got != 5 {
		t.Fatalf("composer height on a 15-row terminal = %d, want 5", got)
	}
}

// The rendered frame must be exactly the terminal size at every step of
// typing. A composer that renders one cell too wide gets re-wrapped into an
// extra row, which pushes the frame past the bottom of the terminal and makes
// the screen jump at wrap points.
func TestFrameFitsTerminalWhileTyping(t *testing.T) {
	sizes := [][2]int{{130, 40}, {100, 30}, {80, 24}}
	for _, setup := range []bool{false, true} {
		for _, size := range sizes {
			model := New(nil)
			model.showSplash, model.ready, model.focus = false, true, focusInput
			model.width, model.height = size[0], size[1]
			model.snapshot = protocol.Snapshot{SetupMode: setup, Model: "anthropic/claude-sonnet-4-5"}
			if !setup {
				model.snapshot.Agents = []protocol.Agent{{ID: "a1", Name: "recon", Status: "running"}}
			}
			model.resizeViewport()
			for i, r := range strings.Repeat("alpha bravo charlie delta echo foxtrot ", 6) {
				updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
				model = updated.(Model)
				rows := strings.Split(model.View(), "\n")
				if len(rows) != size[1] {
					t.Fatalf("setup=%v %v: after %d chars the frame is %d rows, want %d",
						setup, size, i+1, len(rows), size[1])
				}
				for row, line := range rows {
					if width := lipgloss.Width(line); width != size[0] {
						t.Fatalf("setup=%v %v: after %d chars row %d is %d cells, want %d",
							setup, size, i+1, row, width, size[0])
					}
				}
			}
		}
	}
}

// The launch column is anchored: growing the composer must not walk the
// wordmark and the prompt up the screen.
func TestLaunchColumnHoldsStillWhileComposerGrows(t *testing.T) {
	model := New(nil)
	model.showSplash, model.ready, model.focus = false, true, focusInput
	model.width, model.height = 130, 40
	model.snapshot = protocol.Snapshot{SetupMode: true}
	model.resizeViewport()
	composerRow := func() int {
		for row, line := range strings.Split(ansi.Strip(model.View()), "\n") {
			if strings.Contains(line, "╭") {
				return row
			}
		}
		return -1
	}
	want := composerRow()
	for i, r := range strings.Repeat("alpha bravo charlie delta echo ", 12) {
		updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		model = updated.(Model)
		if got := composerRow(); got != want {
			t.Fatalf("after %d chars the composer moved to row %d, want %d (height %d)",
				i+1, got, want, model.input.Height())
		}
	}
	if model.input.Height() < 5 {
		t.Fatalf("composer only grew to %d rows; the test is not exercising growth", model.input.Height())
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
