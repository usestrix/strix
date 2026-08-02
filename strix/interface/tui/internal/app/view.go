package app

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
	"github.com/usestrix/strix/tui/internal/render"
)

// eventSpan records which content lines of the chat trace belong to an
// expandable tool event, so clicks can toggle its collapsed state.
type eventSpan struct {
	start, end int
	eventID    string
}

func (m *Model) chatContent() string {
	if len(m.snapshot.Agents) == 0 {
		switch m.snapshot.ScanState {
		case "failed":
			message := "Scan failed"
			if m.snapshot.Error != nil && strings.TrimSpace(*m.snapshot.Error) != "" {
				detail := strings.ReplaceAll(strings.TrimSpace(*m.snapshot.Error), "\n", " ")
				message += "\n\n" + ansi.Truncate(detail, max(1, m.viewport.Width-4), "...")
			}
			return centeredPlaceholder(message, m.viewport.Width, m.viewport.Height)
		case "stopped":
			return centeredPlaceholder("Scan stopped", m.viewport.Width, m.viewport.Height)
		case "completed":
			return centeredPlaceholder("Scan completed", m.viewport.Width, m.viewport.Height)
		case "preparing":
			return centeredPlaceholder("Preparing scan...", m.viewport.Width, m.viewport.Height)
		default:
			return centeredPlaceholder("Loading...", m.viewport.Width, m.viewport.Height)
		}
	}
	if m.selectedAgent >= len(m.snapshot.Agents) {
		return ""
	}
	agentID := m.snapshot.Agents[m.selectedAgent].ID
	events := append([]protocol.Event(nil), m.snapshot.Events...)
	// Match _gather_agent_events: sort by (timestamp, id).
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].Timestamp != events[j].Timestamp {
			return events[i].Timestamp < events[j].Timestamp
		}
		return events[i].ID < events[j].ID
	})
	// .chat-content has padding: 0 1 — one column of horizontal padding, so wrap
	// to width-2 and indent every line by one cell.
	contentWidth := max(1, m.viewport.Width-2)
	var blocks []string
	var spans []eventSpan
	line := 0
	for _, event := range events {
		if event.AgentID != agentID {
			continue
		}
		var block string
		expandable := false
		if event.Type == "chat" {
			block = render.Chat(event.Data)
		} else if event.Type == "tool" {
			name := render.StringValue(event.Data["tool_name"])
			block, expandable = render.CollapseTool(render.Tool(event.Data), name, m.expandedEvents[event.ID])
		}
		if block == "" {
			continue
		}
		wrapped := wrapBlock(block, contentWidth)
		if len(blocks) > 0 {
			line++ // blank separator line between blocks
		}
		height := strings.Count(wrapped, "\n") + 1
		if expandable {
			spans = append(spans, eventSpan{start: line, end: line + height - 1, eventID: event.ID})
		}
		line += height
		blocks = append(blocks, wrapped)
	}
	m.eventSpans = spans
	if len(blocks) == 0 {
		return centeredPlaceholder("Starting agent...", m.viewport.Width, m.viewport.Height)
	}
	return indentLines(strings.Join(blocks, "\n\n"), " ")
}

// indentLines prefixes every line with the given pad (chat-content padding-left).
func indentLines(s, pad string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = pad + line
	}
	return strings.Join(lines, "\n")
}

func centeredPlaceholder(text string, width, height int) string {
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, lipgloss.NewStyle().Foreground(dim).Italic(true).Render(text))
}

// truncate clips to a display-cell width, honoring wide runes and ANSI styling.
func truncate(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if ansi.StringWidth(value) <= limit {
		return value
	}
	return ansi.Truncate(value, limit, "…")
}

// wrapBlock hard-wraps each line of a rendered block to the given cell width so
// content never spills past the chat border, matching Textual's word wrapping.
func wrapBlock(value string, width int) string {
	if width <= 0 {
		return value
	}
	var out []string
	for _, line := range strings.Split(value, "\n") {
		if ansi.StringWidth(line) <= width {
			out = append(out, line)
			continue
		}
		out = append(out, strings.Split(ansi.Wrap(line, width, " -"), "\n")...)
	}
	return strings.Join(out, "\n")
}

func verticalScrollbar(height, total, visible, offset int) string {
	if height <= 0 || total <= visible {
		return ""
	}
	visible = min(max(1, visible), max(1, total))
	total = max(visible, total)
	thumbHeight := height
	thumbStart := 0
	if total > visible {
		thumbHeight = max(1, height*visible/total)
		maxOffset := total - visible
		thumbStart = (height - thumbHeight) * min(max(0, offset), maxOffset) / maxOffset
	}
	trackStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#262626"))
	thumbStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#737373"))
	bar := make([]string, height)
	for row := range bar {
		bar[row] = trackStyle.Render("│")
		if row >= thumbStart && row < thumbStart+thumbHeight {
			bar[row] = thumbStyle.Render("█")
		}
	}
	return strings.Join(bar, "\n")
}

func withVerticalScrollbar(
	content string,
	width, height, total, visible, offset int,
) string {
	if total <= visible {
		return fixedPanelBody(content, width, height)
	}
	bodyWidth := max(1, width-2)
	body := fixedPanelBody(content, bodyWidth, height)
	bar := verticalScrollbar(height, total, visible, offset)
	return lipgloss.JoinHorizontal(lipgloss.Top, body, " ", bar)
}

func visibleContent(content string, offset, height int) string {
	if height <= 0 || content == "" {
		return ""
	}
	lines := strings.Split(content, "\n")
	start := min(max(0, offset), len(lines))
	end := min(len(lines), start+height)
	return strings.Join(lines[start:end], "\n")
}

func fixedPanelBody(content string, width, height int) string {
	lines := strings.Split(content, "\n")
	body := make([]string, max(0, height))
	for row := range body {
		line := ""
		if row < len(lines) {
			line = ansi.Truncate(lines[row], max(1, width), "")
		}
		padding := strings.Repeat(" ", max(0, width-ansi.StringWidth(line)))
		// End every source style before padding; otherwise inline-code and tool
		// backgrounds can paint the empty space through to the panel border.
		body[row] = line + "\x1b[0m" + blackBG + padding
	}
	return strings.Join(body, "\n")
}

func (m Model) View() string {
	return fillBackground(m.viewInner())
}

func (m Model) viewInner() string {
	if m.showSplash {
		return m.splashView()
	}
	if !m.ready {
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, lipgloss.NewStyle().Foreground(dim).Render("Connecting to Strix…"), lipgloss.WithWhitespaceBackground(black))
	}
	main := m.mainView()
	if m.snapshot.SetupMode {
		main = m.setupView()
	}
	if m.picker != pickerNone {
		// Picker screens use a transparent backdrop (background: $background 0%).
		main = m.overlay(main, m.pickerView(), false)
	} else if m.modal != modalNone {
		// Only the vulnerability detail dims its backdrop (#000000 80%); Help,
		// Quit and Stop are transparent.
		main = m.overlay(main, m.modalView(), m.modal == modalVulnerability)
	}
	return m.toastOverlay(main)
}

// toastOverlay splices a transient notification into the bottom-right corner,
// where Textual's notify() toasts appeared.
func (m Model) toastOverlay(view string) string {
	if m.toast == "" {
		return view
	}
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(green).
		Background(black).
		Foreground(textColor).
		Padding(0, 1).
		Render(m.toast)
	fg := strings.Split(box, "\n")
	bg := strings.Split(view, "\n")
	boxWidth := lipgloss.Width(box)
	left := max(0, m.width-boxWidth-2)
	top := max(0, m.height-len(fg)-1)
	for row := top; row < min(len(bg), top+len(fg)); row++ {
		fgLine := fg[row-top]
		rightStart := left + boxWidth
		leftPart := padToWidth(ansi.Truncate(bg[row], left, ""), left)
		rightPart := ""
		if lipgloss.Width(bg[row]) > rightStart {
			rightPart = ansi.TruncateLeft(bg[row], rightStart, "")
		}
		bg[row] = leftPart + fgLine + rightPart
	}
	return strings.Join(bg, "\n")
}

// blackBG is the SGR that selects a solid black background.
const blackBG = "\x1b[48;2;0;0;0m"

// fillBackground paints the whole frame black like Textual's Screen background.
// Bubble Tea has no screen compositor, so any cell the view does not explicitly
// color shows the terminal's default background. lipgloss emits a full reset
// (\x1b[0m) at the end of every styled span, which also clears the background, so
// we reassert black after each reset (and at the start). Spans that set their own
// background — inline code, selected rows, buttons — keep it, because their color
// is emitted before the reset.
func fillBackground(view string) string {
	if view == "" {
		return view
	}
	return blackBG + strings.ReplaceAll(view, "\x1b[0m", "\x1b[0m"+blackBG)
}

func (m Model) splashView() string {
	shine := "Starting Strix Agent"
	chars := []rune(shine)
	pos := m.splashFrame % (len(chars) + 8)
	var start strings.Builder
	for i, char := range chars {
		distance := i - pos
		if distance < 0 {
			distance = -distance
		}
		// Tiers match SplashScreen._build_start_line_text:
		// bright_white / white / #a3a3a3 / #525252.
		color := lipgloss.Color("#525252")
		bold := false
		switch {
		case distance <= 1:
			color, bold = brightWhite, true
		case distance <= 3:
			color, bold = white, true
		case distance <= 5:
			color = lipgloss.Color("#a3a3a3")
		}
		start.WriteString(lipgloss.NewStyle().Foreground(color).Bold(bold).Render(string(char)))
	}
	welcome := lipgloss.NewStyle().Bold(true).Foreground(white).Render("Welcome to ") +
		lipgloss.NewStyle().Bold(true).Foreground(green).Render("Strix") +
		lipgloss.NewStyle().Bold(true).Foreground(white).Render("!")
	version := lipgloss.NewStyle().Foreground(white).Faint(true).Render("v" + appVersion)
	tagline := lipgloss.NewStyle().Foreground(white).Faint(true).Render("Open-source AI hackers for your apps")
	url := lipgloss.NewStyle().Bold(true).Foreground(green).Render("strix.ai")
	content := lipgloss.NewStyle().Foreground(green).Render(banner) + "\n\n" +
		welcome + "\n" + version + "\n" + tagline + "\n\n" +
		start.String() + "\n\n" + url
	if warn := m.snapshot.ModelWarning; warn != "" {
		content += "\n\n" + splashModelWarning(warn)
	}
	panel := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(green).Padding(1, 6).Align(lipgloss.Center).Render(content)
	// #splash_screen background is solid black.
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, panel,
		lipgloss.WithWhitespaceBackground(black))
}

// splashModelWarning ports SplashScreen._build_model_warning_text.
func splashModelWarning(model string) string {
	yellow := lipgloss.Color("#eab308")
	return lipgloss.NewStyle().Bold(true).Foreground(yellow).Render("⚠ ") +
		lipgloss.NewStyle().Bold(true).Foreground(render.Cyan).Render(model) +
		lipgloss.NewStyle().Foreground(yellow).Render(" is not a recommended frontier model - pentest quality could be degraded")
}

func (m Model) mainView() string {
	showSidebar, sidebarWidth, chatWidth, chatHeight := m.layout()
	// Matches tui_styles.tcss: #chat_history border is near-black when idle and
	// green on focus.
	chatBorder := lipgloss.Color("#0a0a0a")
	if m.focus == focusChat {
		chatBorder = green
	}
	traceHeight := chatHeight - 2
	trace := withVerticalScrollbar(
		m.highlightSelection(
			visibleContent(m.viewportContent, m.viewport.YOffset, traceHeight),
			m.viewport.YOffset,
		),
		chatWidth-2,
		traceHeight,
		m.viewport.TotalLineCount(),
		m.viewport.VisibleLineCount(),
		m.viewport.YOffset,
	)
	chat := lipgloss.NewStyle().Width(chatWidth - 2).Height(traceHeight).Border(lipgloss.RoundedBorder()).BorderForeground(chatBorder).Render(trace)

	inputBorder := dark
	if m.focus == focusInput {
		inputBorder = green
	}
	input := lipgloss.NewStyle().Width(chatWidth - 2).Height(m.input.Height()).Border(lipgloss.RoundedBorder()).BorderForeground(inputBorder).PaddingLeft(1).Render(m.highlightInputSelection(m.input.View()))

	// Chat column: chat history, optional status row, live slash-command menu,
	// then input — all chat-width.
	leftParts := []string{chat}
	if m.statusVisible() {
		leftParts = append(leftParts, m.statusView(chatWidth))
	}
	if menu := m.commandMenuView(chatWidth); menu != "" {
		leftParts = append(leftParts, menu)
	}
	leftParts = append(leftParts, input)
	leftColumn := strings.Join(leftParts, "\n")

	body := leftColumn
	if showSidebar {
		body = lipgloss.JoinHorizontal(lipgloss.Top, leftColumn, " ", m.sidebarView(sidebarWidth, m.height))
	}
	return lipgloss.NewStyle().Background(black).Foreground(textColor).Render(body)
}

func (m Model) sidebarView(width, height int) string {
	// Stats box height fits its content (auto, max 15); vulns panel max-height 12.
	statsBody := m.statsView()
	statsHeight, vulnHeight, agentHeight := m.sidebarHeights()
	// #agents_tree padding: 1 (all sides); interior lines = box - border - v.padding.
	agentRows := max(1, agentHeight-4)
	agentEntries := agentTreeEntries(m.snapshot.Agents, m.collapsedAgents)
	agents := withVerticalScrollbar(
		m.agentsView(max(1, width-6), agentRows),
		width-4,
		agentRows,
		len(agentEntries),
		agentRows,
		m.agentOffset,
	)
	agentBorder := dark
	if m.focus == focusAgents {
		agentBorder = lipgloss.Color("#1a1a1a")
	}
	parts := []string{
		lipgloss.NewStyle().Width(width-2).Height(m.viewerHeight()-2).Border(lipgloss.RoundedBorder()).BorderForeground(dark).Padding(0, 1).Render(m.viewerView(width - 4)),
		lipgloss.NewStyle().Width(width-2).Height(agentHeight-2).Border(lipgloss.RoundedBorder()).BorderForeground(agentBorder).Padding(1, 1).Render(agents),
	}
	if vulnHeight > 0 {
		vulnBorder := dark
		if m.focus == focusVulnerabilities {
			vulnBorder = lipgloss.Color("#1a1a1a")
		}
		vulnRows := max(1, vulnHeight-2)
		totalRows, offsetRows := m.vulnerabilityScrollRows()
		findings := withVerticalScrollbar(
			m.vulnerabilitiesView(max(1, width-6), vulnRows),
			width-4,
			vulnRows,
			totalRows,
			vulnRows,
			offsetRows,
		)
		parts = append(parts, lipgloss.NewStyle().Width(width-2).Height(vulnRows).Border(lipgloss.RoundedBorder()).BorderForeground(vulnBorder).Padding(0, 1).Render(findings))
	}
	parts = append(parts, lipgloss.NewStyle().Width(width-2).Height(statsHeight-2).Border(lipgloss.RoundedBorder()).BorderForeground(dark).Padding(0, 1).Render(statsBody))
	return strings.Join(parts, "\n")
}

func (m Model) sidebarHeights() (statsHeight, vulnHeight, agentHeight int) {
	statsHeight = min(15, strings.Count(m.statsView(), "\n")+3)
	if len(m.snapshot.Vulnerabilities) > 0 {
		rows := 0
		width := m.vulnerabilityListWidth()
		for i := range m.snapshot.Vulnerabilities {
			rows += len(m.vulnerabilityTitleLines(i, width))
		}
		vulnHeight = min(12, rows+2)
	}
	agentHeight = max(3, m.height-m.viewerHeight()-statsHeight-vulnHeight)
	return
}

func (m Model) viewerHeight() int {
	return strings.Count(m.viewerView(m.viewerContentWidth()), "\n") + 3
}

func (m Model) viewerContentWidth() int {
	_, sidebarWidth, _, _ := m.layout()
	if sidebarWidth == 0 {
		sidebarWidth = 24
	}
	return max(1, sidebarWidth-4)
}

func (m Model) viewerView(width int) string {
	switch m.snapshot.ViewerStatus {
	case "running":
		status := lipgloss.NewStyle().Foreground(green).Render("● Viewer running")
		if m.snapshot.ViewerURL != nil && strings.TrimSpace(*m.snapshot.ViewerURL) != "" {
			url := wrapBlock(strings.TrimSpace(*m.snapshot.ViewerURL), width)
			return status + "\n" + lipgloss.NewStyle().Foreground(dim).Render(url)
		}
		return status
	case "unavailable":
		return truncate(lipgloss.NewStyle().Foreground(amber).Render("Viewer UI not built"), width)
	case "failed":
		return truncate(lipgloss.NewStyle().Foreground(red).Render("Viewer failed to start"), width)
	default:
		return truncate(lipgloss.NewStyle().Foreground(textColor).Render("▶ Watch live in browser"), width)
	}
}

func (m Model) statsView() string {
	w := lipgloss.NewStyle().Foreground(white)
	var b strings.Builder
	if model := m.snapshot.Model; model != "" {
		b.WriteString(w.Render(model))
	}
	if m.snapshot.Subscription {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(lipgloss.NewStyle().Foreground(green).Render("ChatGPT subscription"))
	}
	total := numberValue(m.snapshot.Usage["total_tokens"])
	if total > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(w.Render(fmt.Sprintf("%s tokens", formatCount(total))))
		if cost := floatValue(m.snapshot.Usage["cost"]); !m.snapshot.Subscription && cost > 0 {
			b.WriteString(w.Render(fmt.Sprintf(" · $%.2f", cost)))
		}
	}
	if caido := m.snapshot.CaidoURL; caido != "" {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(white).Render("Caido: ") + w.Render(caido))
	}
	if b.Len() > 0 {
		b.WriteString("\n")
	}
	b.WriteString(w.Render("v" + appVersion))
	return b.String()
}

func numberValue(value any) int64 {
	switch v := value.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	}
	return 0
}
func floatValue(value any) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case string:
		n, _ := strconv.ParseFloat(v, 64)
		return n
	}
	return 0
}
func formatCount(value int64) string {
	if value >= 1_000_000 {
		return fmt.Sprintf("%.1fM", float64(value)/1_000_000)
	}
	if value >= 1_000 {
		return fmt.Sprintf("%.1fK", float64(value)/1_000)
	}
	return strconv.FormatInt(value, 10)
}

func (m Model) statusView(width int) string {
	// Status text color mirrors #status_text (#a3a3a3); keymap hints use white
	// keys and dim actions (keymap_styled). See _get_status_display_content.
	left, right := "", ""
	if len(m.snapshot.Agents) > 0 && !m.snapshot.SetupMode {
		agent := m.snapshot.Agents[m.selectedAgent]
		quitHint := lipgloss.NewStyle().Foreground(white).Render("ctrl-q") + lipgloss.NewStyle().Foreground(dim).Render(" ") + lipgloss.NewStyle().Foreground(dim).Render("quit")
		switch agent.Status {
		case "running":
			if m.agentHasEvents(agent.ID) {
				left = m.sweepView() + lipgloss.NewStyle().Foreground(white).Render("esc") + lipgloss.NewStyle().Foreground(dim).Render(" ") + lipgloss.NewStyle().Foreground(dim).Render("stop")
			} else {
				left = m.sweepView() + lipgloss.NewStyle().Foreground(white).Render("Initializing")
			}
			right = quitHint
		case "waiting":
			left = lipgloss.NewStyle().Foreground(dim).Render("Send message to resume")
			if msg := agent.ErrorMessage; msg != "" {
				left = lipgloss.NewStyle().Foreground(red).Render(msg) +
					lipgloss.NewStyle().Foreground(dim).Render(" · Send message to resume")
			}
		case "budget_paused":
			left = lipgloss.NewStyle().Foreground(amber).Render("Budget limit reached") +
				lipgloss.NewStyle().Foreground(dim).Render(" · Send a message to continue")
			right = quitHint
		case "completed":
			left = lipgloss.NewStyle().Foreground(mid).Render("Agent completed")
		case "stopped":
			left = lipgloss.NewStyle().Foreground(mid).Render("Agent stopped")
		case "failed", "crashed":
			msg := agent.ErrorMessage
			if msg == "" {
				msg = "Agent failed"
			}
			left = lipgloss.NewStyle().Foreground(red).Render(msg) +
				lipgloss.NewStyle().Foreground(dim).Render(" · Send message to resume")
		}
	}
	if m.errorText != "" {
		left = lipgloss.NewStyle().Foreground(red).Render(m.errorText)
	}
	gap := max(1, width-lipgloss.Width(left)-lipgloss.Width(right))
	return " " + left + strings.Repeat(" ", max(1, gap-1)) + right
}

func (m Model) sweepView() string {
	palette := []lipgloss.Color{
		black, lipgloss.Color("#031a09"), lipgloss.Color("#052e16"), lipgloss.Color("#0d4a2a"),
		lipgloss.Color("#15803d"), green, brightGreen, lipgloss.Color("#86efac"),
	}
	const numSquares = 6
	numColors := len(palette)
	offset := numColors - 1
	maxPos := (numSquares - 1) + offset
	totalRange := maxPos + offset
	cycleLength := totalRange * 2
	frameInCycle := m.sweepFrame % cycleLength
	wavePos := totalRange - abs(totalRange-frameInCycle)
	sweepPos := wavePos - offset

	dotColor := lipgloss.Color("#0a3d1f")
	var b strings.Builder
	for i := 0; i < numSquares; i++ {
		dist := abs(i - sweepPos)
		colorIdx := numColors - 1 - dist
		if colorIdx <= 0 {
			b.WriteString(lipgloss.NewStyle().Foreground(dotColor).Render("·"))
		} else {
			b.WriteString(lipgloss.NewStyle().Foreground(palette[colorIdx]).Render("▪"))
		}
	}
	b.WriteString(" ")
	return b.String()
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func titleCase(s string) string {
	return strings.Title(strings.ToLower(s))
}

// overlay composites a centered dialog on top of the live main view. When
// dimmed is true (vulnerability detail, background: #000000 80%) the backdrop is
// recolored to a dark grey; otherwise it is left untouched to match Textual's
// transparent modal backdrop (background: $background 0%).
func (m Model) overlay(background, foreground string, dimmed bool) string {
	bg := strings.Split(background, "\n")
	fg := strings.Split(foreground, "\n")
	dialogHeight := len(fg)
	dialogWidth := lipgloss.Width(foreground)
	top := max(0, (m.height-dialogHeight)/2)
	left := max(0, (m.width-dialogWidth)/2)
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#3f3f46"))
	for row := 0; row < len(bg); row++ {
		if row < top || row >= top+dialogHeight {
			if dimmed {
				bg[row] = dimStyle.Render(ansi.Strip(bg[row]))
			}
			continue
		}
		fgLine := fg[row-top]
		rightStart := left + dialogWidth
		var leftPart, rightPart string
		if dimmed {
			bgLine := ansi.Strip(bg[row])
			leftPart = dimStyle.Render(truncateToWidth(bgLine, left))
			if lipgloss.Width(bgLine) > rightStart {
				rightPart = dimStyle.Render(ansi.TruncateLeft(bgLine, rightStart, ""))
			}
		} else {
			// Preserve the original styling of the visible backdrop segments.
			leftPart = padToWidth(ansi.Truncate(bg[row], left, ""), left)
			if lipgloss.Width(bg[row]) > rightStart {
				rightPart = ansi.TruncateLeft(bg[row], rightStart, "")
			}
		}
		bg[row] = leftPart + fgLine + rightPart
	}
	return strings.Join(bg, "\n")
}

// padToWidth right-pads an ANSI string to an exact display width.
func padToWidth(value string, width int) string {
	w := lipgloss.Width(value)
	if w >= width {
		return value
	}
	return value + strings.Repeat(" ", width-w)
}

func truncateToWidth(value string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(value) <= width {
		return value + strings.Repeat(" ", width-lipgloss.Width(value))
	}
	return ansi.Truncate(value, width, "")
}
