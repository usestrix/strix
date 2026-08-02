package app

// In-app text selection for the chat trace, in the tmux copy-mode style:
// drag with the left mouse button to highlight text, and the plain-text
// selection lands on the clipboard when the button is released. Coordinates
// are anchored to content lines, so an active selection survives scrolling.

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

type selectionCopiedMsg struct{ err error }

type selectionState struct {
	active   bool
	dragging bool
	// Content-line coordinates: anchor is where the drag started, head is
	// where the pointer currently is.
	anchorLine, anchorCol int
	headLine, headCol     int
}

// bounds returns the selection in reading order: (fromLine, fromCol) to
// (toLine, toCol), with toCol exclusive.
func (s selectionState) bounds() (fromLine, fromCol, toLine, toCol int) {
	if s.anchorLine < s.headLine || (s.anchorLine == s.headLine && s.anchorCol <= s.headCol) {
		return s.anchorLine, s.anchorCol, s.headLine, s.headCol + 1
	}
	return s.headLine, s.headCol, s.anchorLine, s.anchorCol + 1
}

// styleSelected uses reverse video directly so the highlight renders on any
// terminal profile.
func styleSelected(text string) string {
	return "\x1b[7m" + text + "\x1b[27m"
}

// chatContentCell maps main-view screen coordinates to a content cell inside
// the chat trace, honoring the pane border and the scroll offset.
func (m Model) chatContentCell(x, y int) (line, col int, ok bool) {
	_, _, chatWidth, chatHeight := m.layout()
	traceHeight := chatHeight - 2
	if x < 1 || x > chatWidth-2 || y < 1 || y > traceHeight {
		return 0, 0, false
	}
	return m.viewport.YOffset + y - 1, x - 1, true
}

func (m *Model) beginSelection(line, col int) {
	m.selection = selectionState{
		active: true, dragging: true,
		anchorLine: line, anchorCol: col,
		headLine: line, headCol: col,
	}
	m.selectionNotice = ""
}

func (m *Model) extendSelection(line, col int) {
	m.selection.headLine = max(0, line)
	m.selection.headCol = max(0, col)
}

// finishSelection ends the drag and copies the highlighted text; a plain
// click (no movement) just clears any previous highlight.
func (m *Model) finishSelection() tea.Cmd {
	m.selection.dragging = false
	if m.selection.anchorLine == m.selection.headLine && m.selection.anchorCol == m.selection.headCol {
		m.selection.active = false
		return nil
	}
	text := m.selectedText()
	if text == "" {
		m.selection.active = false
		return nil
	}
	return func() tea.Msg {
		return selectionCopiedMsg{err: writeClipboard(text)}
	}
}

func (m Model) selectedText() string {
	fromLine, fromCol, toLine, toCol := m.selection.bounds()
	lines := strings.Split(m.viewportContent, "\n")
	var out []string
	for i := max(0, fromLine); i <= min(toLine, len(lines)-1); i++ {
		left, right := 0, ansi.StringWidth(lines[i])
		if i == fromLine {
			left = fromCol
		}
		if i == toLine {
			right = min(right, toCol)
		}
		out = append(out, strings.TrimRight(ansi.Strip(ansi.Cut(lines[i], left, right)), " "))
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n")
}

// highlightSelection re-styles the selected cells of the visible trace chunk.
// visible holds the rows starting at content line offset.
func (m Model) highlightSelection(visible string, offset int) string {
	if !m.selection.active {
		return visible
	}
	fromLine, fromCol, toLine, toCol := m.selection.bounds()
	rows := strings.Split(visible, "\n")
	for i, row := range rows {
		line := offset + i
		if line < fromLine || line > toLine {
			continue
		}
		width := ansi.StringWidth(row)
		left, right := 0, width
		if line == fromLine {
			left = min(fromCol, width)
		}
		if line == toLine {
			right = min(toCol, width)
		}
		if right <= left {
			continue
		}
		rows[i] = ansi.Cut(row, 0, left) +
			styleSelected(ansi.Strip(ansi.Cut(row, left, right))) +
			ansi.Cut(row, right, width)
	}
	return strings.Join(rows, "\n")
}
