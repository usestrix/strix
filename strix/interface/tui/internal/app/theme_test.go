package app

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/usestrix/strix/tui/internal/protocol"
)

// The default palette is unchanged, and the two opt-in modes hand the terminal
// back control of both the colors and the background (#1005).
func TestColorModes(t *testing.T) {
	restore := lipgloss.ColorProfile()
	defer lipgloss.SetColorProfile(restore)
	defer func() { paintBackground = true }()

	for _, mode := range []struct {
		name, colors, noColor string
		wantTruecolor         bool
		wantAnsi16            bool
		wantBackground        bool
	}{
		{name: "default", wantTruecolor: true, wantBackground: true},
		{name: "terminal", colors: "terminal", wantAnsi16: true},
		{name: "ansi alias", colors: "ANSI", wantAnsi16: true},
		{name: "no-color", noColor: "1"},
	} {
		lipgloss.SetColorProfile(termenv.TrueColor)
		paintBackground = true
		t.Setenv(terminalColorsEnv, mode.colors)
		t.Setenv(noColorEnv, mode.noColor)
		ApplyTheme()

		m := New(nil)
		m.width, m.height = 120, 20
		m.showSplash = false
		m.handleEnvelope(stateEnvelope(t, 1, protocol.Snapshot{ScanState: "running", Model: "anthropic/claude-sonnet-4.6"}))
		b := protocol.CollectionBootstrap{
			Collection: "agents", Revision: 1, Cursor: 0, NextCursor: 1, Done: true,
			Items: []json.RawMessage{rawJSON(t, protocol.Agent{ID: "a0", Name: "Strix", Status: "running"})},
		}
		m.handleEnvelope(protocol.Envelope{Version: protocol.Version, Type: "collection_bootstrap", Payload: rawJSON(t, b)})
		m.resizeViewport()
		view := m.View()

		truecolor := regexp.MustCompile(`\x1b\[[34]8;2;`).MatchString(view)
		ansi16 := regexp.MustCompile(`\x1b\[(?:3[0-7]|9[0-7])m`).MatchString(view)
		background := strings.Contains(view, "\x1b[48;2;0;0;0m")

		if truecolor != mode.wantTruecolor {
			t.Errorf("%s: truecolor = %v, want %v", mode.name, truecolor, mode.wantTruecolor)
		}
		if ansi16 != mode.wantAnsi16 {
			t.Errorf("%s: ansi-16 = %v, want %v", mode.name, ansi16, mode.wantAnsi16)
		}
		if background != mode.wantBackground {
			t.Errorf("%s: painted its own background = %v, want %v",
				mode.name, background, mode.wantBackground)
		}
		if mode.name == "no-color" && truecolor {
			t.Errorf("no-color still emitted color")
		}
	}
}
