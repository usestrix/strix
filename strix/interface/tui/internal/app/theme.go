package app

import (
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// The TUI draws with its own palette on a black background by default, which is
// what the Textual interface did before it. That ignores a terminal configured
// for anything else, so two other modes are available through the environment:
//
//	STRIX_TUI_COLORS=terminal   the terminal's own 16 colors, its own background
//	NO_COLOR=1                  no color at all, the terminal's own background
//
// The palette itself does not change. Setting the profile makes lipgloss map
// every color it is given onto what the profile can express, so the terminal
// resolves the actual shades from its theme, and dropping the painted background
// lets whatever the terminal uses show through.
const (
	terminalColorsEnv = "STRIX_TUI_COLORS"
	noColorEnv        = "NO_COLOR"
)

// paintBackground reports whether the frame paints its own background. When it
// does not, the terminal's shows through.
var paintBackground = true

// ApplyTheme resolves the color mode from the environment. It must run before
// anything renders, and before Bubble Tea starts.
func ApplyTheme() {
	// NO_COLOR is honored whenever it is present and not empty.
	// https://no-color.org
	if os.Getenv(noColorEnv) != "" {
		lipgloss.SetColorProfile(termenv.Ascii)
		paintBackground = false
		return
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv(terminalColorsEnv))) {
	case "terminal", "ansi", "16":
		lipgloss.SetColorProfile(termenv.ANSI)
		useTerminalPalette()
		paintBackground = false
	}
}

// useTerminalPalette rebinds the palette to ANSI indices, which the terminal
// resolves from its own theme.
//
// Letting lipgloss round the hex palette down instead is not enough: the greys
// the layout is built from (#333333 borders, #737373 hints) round to plain black
// and disappear, taking every panel outline with them. The structural colors are
// mapped by hand to bright black, which is a real color in every theme.
func useTerminalPalette() {
	const (
		ansiRed         = lipgloss.Color("1")
		ansiGreen       = lipgloss.Color("2")
		ansiYellow      = lipgloss.Color("3")
		ansiBlue        = lipgloss.Color("4")
		ansiWhite       = lipgloss.Color("7")
		ansiBrightBlack = lipgloss.Color("8")
		ansiBrightGreen = lipgloss.Color("10")
		ansiBrightBlue  = lipgloss.Color("12")
		ansiBrightWhite = lipgloss.Color("15")
	)
	green, brightGreen = ansiGreen, ansiBrightGreen
	blue, lightBlue = ansiBlue, ansiBrightBlue
	red = ansiRed
	orange, amber = ansiYellow, ansiYellow
	white, brightWhite = ansiBrightWhite, ansiBrightWhite
	textColor = ansiWhite
	dim, mid, dark = ansiBrightBlack, ansiWhite, ansiBrightBlack
	black = ansiBrightBlack

	treeLabel, treeGuide = ansiWhite, ansiBrightBlack
	treeCursorFg, treeCursorBg = ansiBrightWhite, ansiBlue

	thumbResting, thumbActive = ansiBrightBlack, ansiWhite
}

// panelBackground is the background modals and panels paint behind themselves,
// and nothing when the terminal's own background is in use.
func panelBackground() lipgloss.TerminalColor {
	if paintBackground {
		return black
	}
	return lipgloss.NoColor{}
}

// backgroundSGR reasserts the frame background after a style reset. It is empty
// when the terminal owns the background, so resets fall back to it.
func backgroundSGR() string {
	if paintBackground {
		return blackBG
	}
	return ""
}
