package app

// In-app text selection for the chat trace, in the tmux copy-mode style:
// drag with the left mouse button to highlight text, and the plain-text
// selection lands on the clipboard when the button is released. Coordinates
// are anchored to content lines, so an active selection survives scrolling.

import (
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

type selectionCopiedMsg struct{ err error }

type toastExpiredMsg struct{ id int }

// toastDuration matches the old Textual notify("Copied to clipboard", timeout=2).
const toastDuration = 2 * time.Second

// showToast displays a transient notification and schedules its dismissal;
// the copy highlight is cleared together with the toast.
func (m *Model) showToast(text string) tea.Cmd {
	return m.showToastFor(text, toastDuration)
}

func (m *Model) showToastFor(text string, duration time.Duration) tea.Cmd {
	m.toastID++
	m.toast = text
	id := m.toastID
	return tea.Tick(duration, func(time.Time) tea.Msg { return toastExpiredMsg{id: id} })
}

type selectionRegion int

const (
	regionChat selectionRegion = iota
	regionInput
)

type selectionState struct {
	active   bool
	dragging bool
	region   selectionRegion
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

// inputPromptWidth is the composer prompt ("> " / "  ") column width; input
// selection coordinates are relative to the text after it.
const inputPromptWidth = 2

// inputTop returns the screen row of the composer's top border in the main view.
func (m Model) inputTop() int {
	_, _, _, chatHeight := m.layout()
	statusH := 0
	if m.statusVisible() {
		statusH = 1
	}
	return chatHeight + statusH
}

// inputContentCell maps main-view screen coordinates to a text cell inside
// the composer, honoring the border, padding, and prompt columns.
func (m Model) inputContentCell(x, y int) (line, col int, ok bool) {
	_, _, chatWidth, _ := m.layout()
	top := m.inputTop()
	textLeft := 2 + inputPromptWidth // border + padding, then the prompt
	if x < textLeft || x > chatWidth-2 || y <= top || y > top+m.input.Height() {
		return 0, 0, false
	}
	return y - top - 1, x - textLeft, true
}

func (m *Model) beginSelection(region selectionRegion, line, col int) {
	m.selection = selectionState{
		active: true, dragging: true, region: region,
		anchorLine: line, anchorCol: col,
		headLine: line, headCol: col,
	}
	m.toast = ""
}

func (m *Model) extendSelection(line, col int) {
	m.selection.headLine = max(0, line)
	m.selection.headCol = max(0, col)
}

// finishSelection ends the drag and copies the highlighted text; a plain
// click (no movement) clears any previous highlight and, in the chat trace,
// toggles the clicked tool's collapsed state.
func (m *Model) finishSelection() tea.Cmd {
	m.selection.dragging = false
	if m.selection.anchorLine == m.selection.headLine && m.selection.anchorCol == m.selection.headCol {
		region := m.selection.region
		line := m.selection.anchorLine
		m.selection.active = false
		if region == regionChat {
			m.toggleEventAtLine(line)
		}
		return nil
	}
	text := m.selectedText()
	if text == "" {
		m.selection.active = false
		return nil
	}
	if m.selection.region == regionChat {
		if cleaned := cleanCopiedText(text); strings.TrimSpace(cleaned) != "" {
			text = cleaned
		}
	}
	return func() tea.Msg {
		return selectionCopiedMsg{err: writeClipboard(text)}
	}
}

// iconPrefixes and decorativeLines port StrixTUIApp._ICON_PREFIXES and
// _DECORATIVE_LINES: UI ornaments dropped from copied chat text.
// kittyPlaceholderRune marks kitty graphics placeholder cells, which carry no
// copyable text.
const kittyPlaceholderRune = 0x10eeee

var iconPrefixes = []string{
	"🐞 ", "🌐 ", "📋 ", "🧠 ", "◆ ", "◇ ", "◈ ", "→ ", "○ ", "● ", "✓ ", "✗ ",
	"⚠ ", "▍ ", "▍", "┃ ", "• ", ">_ ", "</> ", "<~> ", "[ ] ", "[~] ", "[•] ",
}

var decorativeLines = map[string]bool{
	"● In progress...": true,
	"✓ Done":           true,
	"✗ Failed":         true,
	"✗ Error":          true,
	"○ Unknown":        true,
}

// cleanCopiedText ports _clean_copied_text: drop decorative status lines and
// horizontal rules, and strip leading UI icons while keeping indentation.
func cleanCopiedText(text string) string {
	var cleaned []string
	for _, line := range strings.Split(text, "\n") {
		stripped := strings.TrimLeft(line, " \t")
		if decorativeLines[stripped] {
			continue
		}
		if stripped != "" && strings.Trim(stripped, "─") == "" {
			continue
		}
		if strings.ContainsRune(stripped, kittyPlaceholderRune) {
			continue
		}
		out := line
		for _, prefix := range iconPrefixes {
			if strings.HasPrefix(stripped, prefix) {
				leading := line[:len(line)-len(stripped)]
				out = leading + stripped[len(prefix):]
				break
			}
		}
		cleaned = append(cleaned, out)
	}
	return strings.Join(cleaned, "\n")
}

// toggleEventAtLine expands or collapses the tool event rendered at the given
// chat content line.
func (m *Model) toggleEventAtLine(line int) {
	for _, span := range m.eventSpans {
		if line >= span.start && line <= span.end {
			m.expandedEvents[span.eventID] = !m.expandedEvents[span.eventID]
			m.refreshViewport()
			return
		}
	}
}

func (m Model) selectedText() string {
	fromLine, fromCol, toLine, toCol := m.selection.bounds()
	source := m.viewportContent
	if m.selection.region == regionInput {
		source = m.inputText()
	}
	lines := strings.Split(source, "\n")
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

// inputText returns the composer's visible rows without the prompt columns,
// as the source for input-region selection.
func (m Model) inputText() string {
	rows := strings.Split(m.input.View(), "\n")
	for i, row := range rows {
		rows[i] = ansi.Cut(row, inputPromptWidth, ansi.StringWidth(row))
	}
	return strings.Join(rows, "\n")
}

// highlightInputSelection re-styles the selected cells of the rendered
// composer, shifting columns past the prompt.
func (m Model) highlightInputSelection(view string) string {
	if !m.selection.active || m.selection.region != regionInput {
		return view
	}
	return highlightRows(view, 0, m.selection, inputPromptWidth)
}

// highlightSelection re-styles the selected cells of the visible trace chunk.
// visible holds the rows starting at content line offset.
func (m Model) highlightSelection(visible string, offset int) string {
	if !m.selection.active || m.selection.region != regionChat {
		return visible
	}
	return highlightRows(visible, offset, m.selection, 0)
}

// highlightRows applies reverse video to the selected cells; shift moves the
// selection columns right (for rows with a fixed prefix like the prompt).
func highlightRows(visible string, offset int, selection selectionState, shift int) string {
	fromLine, fromCol, toLine, toCol := selection.bounds()
	fromCol += shift
	toCol += shift
	rows := strings.Split(visible, "\n")
	for i, row := range rows {
		line := offset + i
		if line < fromLine || line > toLine {
			continue
		}
		width := ansi.StringWidth(row)
		left, right := shift, width
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
