package app

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
)

// A colored line wider than the wrap width must stay colored on every row, not
// only the first: ansi.Wrap emits the opening SGR once and the reset once, so
// wrapBlock re-opens the active style on each continuation line.
func TestWrapBlockCarriesColorAcrossContinuationLines(t *testing.T) {
	lipgloss.SetColorProfile(termenv.TrueColor)
	amber := "\x1b[38;2;245;158;11m"
	line := lipgloss.NewStyle().Foreground(lipgloss.Color("#f59e0b")).
		Render("Blocked: " + strings.Repeat("a reason long enough to wrap ", 4))

	rows := strings.Split(wrapBlock(line, 30), "\n")
	if len(rows) < 3 {
		t.Fatalf("expected the reason to wrap to several rows, got %d", len(rows))
	}
	for i, row := range rows {
		if strings.TrimSpace(ansi.Strip(row)) == "" {
			continue
		}
		if !strings.Contains(row, amber) {
			t.Errorf("row %d lost its color after wrapping: %q", i, row)
		}
	}
}

func TestWrapBlockLeavesShortColoredLineUnchanged(t *testing.T) {
	lipgloss.SetColorProfile(termenv.TrueColor)
	line := lipgloss.NewStyle().Foreground(lipgloss.Color("#f59e0b")).Render("Blocked: short")
	if got := wrapBlock(line, 80); got != line {
		t.Errorf("a line within width was rewritten:\n got %q\nwant %q", got, line)
	}
}
