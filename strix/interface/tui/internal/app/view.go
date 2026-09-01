package app

import (
	"encoding/json"
	"fmt"
	"os"
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

// renderedBlock is a chat block kept across frames: rendering (syntax
// highlighting, image placements, wrapping) is expensive and only changes
// when the event, the chat width, or its expanded state changes.
type renderedBlock struct {
	version    int
	width      int
	expanded   bool
	wrapped    string
	expandable bool
	height     int
}

func (m *Model) renderEvent(event protocol.Event, width int) renderedBlock {
	expanded := m.expandedEvents[event.ID]
	if cached, ok := m.blockCache[event.ID]; ok &&
		cached.version == event.Version && cached.width == width && cached.expanded == expanded {
		return cached
	}
	var block string
	expandable := false
	switch event.Type {
	case "chat":
		block = render.Chat(event.Data)
	case "tool":
		name := render.StringValue(event.Data["tool_name"])
		block, expandable = render.CollapseTool(render.Tool(event.Data), name, expanded)
	}
	entry := renderedBlock{version: event.Version, width: width, expanded: expanded, expandable: expandable}
	if block != "" {
		entry.wrapped = wrapBlock(block, width)
		entry.height = strings.Count(entry.wrapped, "\n") + 1
	}
	if m.blockCache == nil {
		m.blockCache = map[string]renderedBlock{}
	}
	m.blockCache[event.ID] = entry
	return entry
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
	render.SetImageWidth(contentWidth - 2)
	var blocks []string
	var spans []eventSpan
	line := 0
	for _, event := range events {
		if event.AgentID != agentID {
			continue
		}
		entry := m.renderEvent(event, contentWidth)
		if entry.wrapped == "" {
			continue
		}
		if len(blocks) > 0 {
			line++ // blank separator line between blocks
		}
		if entry.expandable {
			spans = append(spans, eventSpan{start: line, end: line + entry.height - 1, eventID: event.ID})
		}
		line += entry.height
		blocks = append(blocks, entry.wrapped)
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

// scrollbarThumb brightens the bar being dragged so the grab reads as taking
// hold of it.
func (m Model) scrollbarThumb(target scrollbarTarget) lipgloss.Color {
	if m.draggingScrollbar == target {
		return thumbActive
	}
	return thumbResting
}

func verticalScrollbar(height, total, visible, offset int, thumb lipgloss.Color) string {
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
	thumbStyle := lipgloss.NewStyle().Foreground(thumb)
	bar := make([]string, height)
	for row := range bar {
		bar[row] = " "
		if row >= thumbStart && row < thumbStart+thumbHeight {
			bar[row] = thumbStyle.Render("█")
		}
	}
	return strings.Join(bar, "\n")
}

// withVerticalScrollbar reserves a single column for the bar, and only while the
// panel actually overflows.
func withVerticalScrollbar(
	content string,
	width, height, total, visible, offset int,
	thumb lipgloss.Color,
) string {
	if total <= visible {
		return fixedPanelBody(content, width, height)
	}
	body := fixedPanelBody(content, max(1, width-1), height)
	bar := verticalScrollbar(height, total, visible, offset, thumb)
	return lipgloss.JoinHorizontal(lipgloss.Top, body, bar)
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
	view := fillBackground(m.viewInner())
	// Kitty graphics transmissions ride out of band: they carry no visible
	// cells, so writing them directly keeps the Bubble Tea frame diff clean.
	for _, seq := range render.DrainImageTransmissions() {
		_, _ = os.Stdout.WriteString(seq)
	}
	return view
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
	if m.modal == modalConfirmMount {
		// A corner prompt, not a dialog: it sits out of the way in the live view
		// while the scan waits on the answer.
		main = m.cornerOverlay(main, m.modalView())
	} else if m.modal != modalNone {
		// Only the vulnerability detail dims its backdrop (#000000 80%); Help,
		// Quit and Stop are transparent.
		main = m.overlay(main, m.modalView(), m.modal == modalVulnerability)
	}
	return m.toastOverlay(main)
}

// mountPromptBounds is where the working-directory prompt is drawn. It is placed
// by cornerOverlay rather than centered, so a click has to be tested against
// these bounds and not the ones the other modals use.
func (m Model) mountPromptBounds() (left, top int, panel string) {
	panel = m.modalView()
	if panel == "" {
		return 0, 0, ""
	}
	_, _, chatWidth, _ := m.layout()
	left = max(0, min(chatWidth, m.width)-lipgloss.Width(panel))
	statusH := 0
	if m.statusVisible() {
		statusH = 1
	}
	return left, max(0, m.inputTop()-statusH-lipgloss.Height(panel)), panel
}

// cornerOverlay splices a panel in directly above the composer, right-aligned
// with it, leaving the rest of the view visible behind it.
func (m Model) cornerOverlay(view, panel string) string {
	if panel == "" {
		return view
	}
	fg := strings.Split(panel, "\n")
	bg := strings.Split(view, "\n")
	panelWidth := lipgloss.Width(panel)
	// Right edge of the chat column, so it lines up with the composer rather
	// than covering the sidebar.
	_, _, chatWidth, _ := m.layout()
	left := max(0, min(chatWidth, m.width)-panelWidth)
	// Bottom row sits just above the composer, clearing the status line so the
	// scan state and quit hint stay readable.
	statusH := 0
	if m.statusVisible() {
		statusH = 1
	}
	top := max(0, m.inputTop()-statusH-len(fg))
	for row := top; row < min(len(bg), top+len(fg)); row++ {
		fgLine := ansi.Truncate(fg[row-top], max(0, m.width-left), "")
		rightStart := left + lipgloss.Width(fgLine)
		leftPart := padToWidth(ansi.Truncate(bg[row], left, ""), left)
		rightPart := ""
		if lipgloss.Width(bg[row]) > rightStart {
			rightPart = ansi.TruncateLeft(bg[row], rightStart, "")
		}
		bg[row] = leftPart + fgLine + rightPart
	}
	return strings.Join(bg, "\n")
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

// Base frame colors are reapplied after full SGR resets so the TUI does not
// inherit an unreadable foreground from the user's terminal profile.
const (
	blackBG         = "\x1b[48;2;0;0;0m"
	textFG          = "\x1b[38;2;212;212;212m"
	baseFrameColors = blackBG + textFG
)

// fillBackground paints the whole frame black like Textual's Screen background.
// Bubble Tea has no screen compositor, so any cell the view does not explicitly
// color shows the terminal's default background. lipgloss emits a full reset
// (\x1b[0m) at the end of every styled span, which clears both foreground and
// background. Reasserting only black made uncolored and faint text inherit the
// terminal profile's foreground; light profiles therefore rendered that text
// black-on-black. Reapply both base colors after each reset (and at the start).
// Spans that set their own colors — inline code, selected rows, buttons — keep
// them, because their color is emitted after the base style.
func fillBackground(view string) string {
	if view == "" {
		return view
	}
	return baseFrameColors + strings.ReplaceAll(view, "\x1b[0m", "\x1b[0m"+baseFrameColors)
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
	// The wordmark is shared with the launch screen so the two read as one moment.
	content := wordmark() + "\n\n" +
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

// chatPaneKey identifies everything the bordered trace depends on.
type chatPaneKey struct {
	offset        int
	width, height int
	border        lipgloss.Color
	selection     selectionState
}

// chatPane memoizes the bordered trace: slicing, scrollbar padding and border
// styling all re-measure every visible cell, which is costly when inline image
// placeholders (a base rune plus two combining marks per cell) fill the pane,
// and the trace is unchanged across most frames.
var chatPane struct {
	key     chatPaneKey
	content string
	out     string
}

func (m Model) renderChatPane(width, height int, border lipgloss.Color) string {
	key := chatPaneKey{offset: m.viewport.YOffset, width: width, height: height, border: border, selection: m.selection}
	if chatPane.out != "" && chatPane.key == key && chatPane.content == m.viewportContent {
		return chatPane.out
	}
	trace := withVerticalScrollbar(
		m.highlightSelection(visibleContent(m.viewportContent, m.viewport.YOffset, height), m.viewport.YOffset),
		width,
		height,
		m.viewport.TotalLineCount(),
		m.viewport.VisibleLineCount(),
		m.viewport.YOffset,
		m.scrollbarThumb(scrollbarTrace),
	)
	out := lipgloss.NewStyle().Width(width).Height(height).
		Border(lipgloss.RoundedBorder()).BorderForeground(border).Render(trace)
	chatPane.key, chatPane.content, chatPane.out = key, m.viewportContent, out
	return out
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
	chat := m.renderChatPane(chatWidth-2, traceHeight, chatBorder)

	inputBorder := dark
	if m.focus == focusInput {
		inputBorder = green
	}
	input := lipgloss.NewStyle().Width(chatWidth - 2).Height(m.input.Height()).
		Border(lipgloss.RoundedBorder()).BorderForeground(inputBorder).PaddingLeft(1).
		Render(m.highlightInputSelection(m.input.View()))

	// Chat column: chat history, optional status row, then input — all chat-width.
	leftParts := []string{chat}
	if m.statusVisible() {
		leftParts = append(leftParts, m.statusView(chatWidth))
	}
	leftParts = append(leftParts, input)
	leftColumn := strings.Join(leftParts, "\n")

	body := leftColumn
	if showSidebar {
		body = lipgloss.JoinHorizontal(lipgloss.Top, leftColumn, " ", m.sidebarView(sidebarWidth, m.height))
	}
	return lipgloss.NewStyle().Background(black).Foreground(textColor).Render(body)
}

// Every panel that Tab can reach shows focus the way the chat and the composer
// do, with a green border. The stylesheet asked for near-black on the tree
// instead, through a Tree:focus rule that lost to the #agents_tree id selector
// and so never applied - honoring it made the outline vanish on the one panel
// that had just become active.
func (m Model) sidebarView(width, height int) string {
	// Stats box height fits its content (auto, max 15); vulns panel max-height 12.
	statsBody := m.statsView()
	statsHeight, vulnHeight, mcpHeight, agentHeight := m.sidebarHeights()
	agentBorder := dark
	if m.focus == focusAgents {
		agentBorder = green
	}
	// #agents_tree padding: 1 (all sides); interior lines = box - border - v.padding.
	agentRows := max(1, agentHeight-4)
	agentEntries := agentTreeEntries(m.snapshot.Agents, m.collapsedAgents)
	agents := withVerticalScrollbar(
		m.agentsView(max(1, width-5), agentRows),
		width-4,
		agentRows,
		len(agentEntries),
		agentRows,
		m.agentOffset,
		m.scrollbarThumb(scrollbarAgents),
	)
	parts := []string{
		lipgloss.NewStyle().Width(width-2).Height(m.viewerHeight()-2).Border(lipgloss.RoundedBorder()).BorderForeground(dark).Padding(0, 1).Render(m.viewerView(width - 4)),
		lipgloss.NewStyle().Width(width-2).Height(agentHeight-2).Border(lipgloss.RoundedBorder()).BorderForeground(agentBorder).Padding(1, 1).Render(agents),
	}
	if vulnHeight > 0 {
		vulnBorder := dark
		if m.focus == focusVulnerabilities {
			vulnBorder = green
		}
		vulnRows := max(1, vulnHeight-2)
		totalRows, offsetRows := m.vulnerabilityScrollRows()
		findings := withVerticalScrollbar(
			m.vulnerabilitiesView(m.vulnerabilityListWidth(), vulnRows),
			width-4,
			vulnRows,
			totalRows,
			vulnRows,
			offsetRows,
			m.scrollbarThumb(scrollbarFindings),
		)
		parts = append(parts, lipgloss.NewStyle().Width(width-2).Height(vulnRows).Border(lipgloss.RoundedBorder()).BorderForeground(vulnBorder).Padding(0, 1).Render(findings))
	}
	if mcpHeight > 0 {
		mcpBorder := dark
		if m.focus == focusMcp {
			mcpBorder = green
		}
		mcpRows := max(1, mcpHeight-2)
		parts = append(parts, lipgloss.NewStyle().Width(width-2).Height(mcpRows).Border(lipgloss.RoundedBorder()).BorderForeground(mcpBorder).Padding(0, 1).Render(m.mcpConnectionsView(width-4, mcpRows)))
	}
	parts = append(parts, lipgloss.NewStyle().Width(width-2).Height(statsHeight-2).Border(lipgloss.RoundedBorder()).BorderForeground(dark).Padding(0, 1).Render(statsBody))
	return strings.Join(parts, "\n")
}

func (m Model) sidebarHeights() (statsHeight, vulnHeight, mcpHeight, agentHeight int) {
	// Measure the stats panel the way its box will render it: a long model name
	// wraps inside the sidebar, and counting only its newlines would size the
	// box short and push the whole frame past the bottom of the terminal.
	statsRows := lipgloss.Height(lipgloss.NewStyle().Width(m.viewerContentWidth()).Render(m.statsView()))
	statsHeight = min(15, statsRows+2)
	if len(m.snapshot.Vulnerabilities) > 0 {
		vulnHeight = min(12, len(m.vulnerabilityRows(m.vulnerabilityListWidth()))+2)
	}
	// One header line + one line per connection + the box border (2). Capped so a
	// long roster cannot crowd out the agent tree; a roster past the cap scrolls
	// inside the panel. Absent entirely when the run has no MCP connections.
	if len(m.snapshot.Connections) > 0 {
		mcpHeight = min(9, len(m.snapshot.Connections)+3)
	}
	agentHeight = max(3, m.height-m.viewerHeight()-statsHeight-vulnHeight-mcpHeight)
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
		label := m.snapshot.SubscriptionLabel
		if label == "" {
			label = "ChatGPT subscription"
		}
		b.WriteString(lipgloss.NewStyle().Foreground(green).Render(label))
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

// mcpConnectionsView renders the sidebar MCP panel: a header carrying the total
// connection count, then one row per connection with a status glyph and its tool
// count (or "offline").
//   - a solid green dot marks an attached, idle connection;
//   - a green cycling quarter-circle (◐ ◓ ◑ ◒) marks a call running against it;
//   - a red dot plus "offline" marks a connection whose live session has died.
//
// The header stays fixed while the roster below it scrolls: when there are more
// connections than the panel can show, the visible window is chosen by
// m.mcpOffset and withVerticalScrollbar draws a thumb in the reserved last
// column, exactly as the agent tree and findings list scroll.
//
// "In use" is derived from the connection-tagged tool-call events in the stream,
// not carried on the connection roster, so a call in flight shows motion without
// any extra backend signal. The quarter-circle rides the shared sweepFrame tick.
func (m Model) mcpConnectionsView(width, rows int) string {
	conns := m.snapshot.Connections
	header := truncate(lipgloss.NewStyle().Foreground(dim).Render(
		fmt.Sprintf("MCP Connections (%d)", len(conns))), width)
	bodyRows := max(0, rows-1)
	if bodyRows == 0 {
		return header
	}
	inUse := m.mcpInUse()
	frames := []rune{'◐', '◓', '◑', '◒'}
	// Reserve the scrollbar column whether or not the bar is showing, so the
	// roster does not shift sideways as it grows past the panel.
	rosterWidth := max(1, width-1)
	start := windowStart(m.mcpOffset, len(conns), bodyRows)
	end := min(len(conns), start+bodyRows)
	lines := make([]string, 0, max(0, end-start))
	for i := start; i < end; i++ {
		conn := conns[i]
		var glyph, right string
		switch {
		case conn.Dead:
			glyph = lipgloss.NewStyle().Foreground(red).Render("●")
			right = lipgloss.NewStyle().Foreground(red).Render("offline")
		case inUse[conn.Name]:
			glyph = lipgloss.NewStyle().Foreground(green).Render(string(frames[m.sweepFrame%len(frames)]))
			right = lipgloss.NewStyle().Foreground(dim).Render(toolsLabel(conn.ToolCount))
		default:
			glyph = lipgloss.NewStyle().Foreground(green).Render("●")
			right = lipgloss.NewStyle().Foreground(dim).Render(toolsLabel(conn.ToolCount))
		}
		rightWidth := lipgloss.Width(right)
		name := truncate(lipgloss.NewStyle().Foreground(textColor).Render(conn.Name), max(1, rosterWidth-2-rightWidth-1))
		gap := max(1, rosterWidth-2-lipgloss.Width(name)-rightWidth)
		lines = append(lines, glyph+" "+name+strings.Repeat(" ", gap)+right)
	}
	roster := withVerticalScrollbar(
		strings.Join(lines, "\n"),
		width,
		bodyRows,
		len(conns),
		bodyRows,
		m.mcpOffset,
		m.scrollbarThumb(scrollbarMcp),
	)
	return header + "\n" + roster
}

// mcpPageSize is how many connection rows the roster shows at once, below its
// fixed header line.
func (m Model) mcpPageSize() int {
	_, _, mcpHeight, _ := m.sidebarHeights()
	// mcpHeight = 2 (border) + header (1) + roster rows.
	return max(1, mcpHeight-3)
}

// clampMcpOffset keeps the roster offset within the range that still shows a
// full page of connections at the bottom.
func (m Model) clampMcpOffset(offset int) int {
	return min(max(0, offset), max(0, len(m.snapshot.Connections)-m.mcpPageSize()))
}

// mcpInUse is the set of MCP connections with a tool call currently running,
// read off the connection-tagged tool events the model already holds. Each MCP
// dispatch event carries the connection name (mcp_connection) and a status that
// moves running -> completed as its own event is upserted, so a connection is
// "in use" exactly while one of its events is still running.
func (m Model) mcpInUse() map[string]bool {
	inUse := map[string]bool{}
	for _, event := range m.snapshot.Events {
		if event.Type != "tool" {
			continue
		}
		connection := render.StringValue(event.Data["mcp_connection"])
		if connection == "" {
			continue
		}
		if render.StringValue(event.Data["status"]) == "running" {
			inUse[connection] = true
		}
	}
	return inUse
}

func toolsLabel(count int) string {
	if count == 1 {
		return "1 tool"
	}
	return fmt.Sprintf("%d tools", count)
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
				left = statusMessage(msg, red, " · Send message to resume", width)
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
			left = statusMessage(msg, red, " · Send message to resume", width)
		}
	}
	if m.errorText != "" {
		left = statusMessage(m.errorText, red, "", width-lipgloss.Width(right))
	}
	return composeStatusRow(left, right, width)
}

// composeStatusRow lays the status text and the corner hint on one row exactly
// width columns wide. A wider row would widen the whole chat column, because
// JoinHorizontal pads every row of a block to its widest, which pushes the
// sidebar off screen and wraps the frame.
func composeStatusRow(left, right string, width int) string {
	if width <= 0 {
		return ""
	}
	const leading = 1 // the row is indented one column, like the panels above it
	// A terminal can be narrower than the hint itself. Drop the hint rather than
	// keep it at the cost of the status, which is the part carrying information;
	// ctrl-q works whether or not the row has room to say so.
	if lipgloss.Width(right) > 0 && width < lipgloss.Width(right)+leading+2 {
		right = ""
	}
	separator := 0
	if lipgloss.Width(right) > 0 {
		separator = 1
	}
	left = truncate(left, max(0, width-leading-lipgloss.Width(right)-separator))
	padding := max(0, width-leading-lipgloss.Width(left)-lipgloss.Width(right))
	return " " + left + strings.Repeat(" ", padding) + right
}

// statusMessage fits a message and its trailing hint on the one status row. A
// model or backend error can be a wrapped exception several lines long, so it is
// flattened to a single line and clipped, leaving the hint readable.
func statusMessage(message string, color lipgloss.Color, hint string, width int) string {
	styledHint := lipgloss.NewStyle().Foreground(dim).Render(hint)
	room := max(1, width-2-lipgloss.Width(styledHint))
	flat := truncate(flattenStatus(message), room)
	return lipgloss.NewStyle().Foreground(color).Render(flat) + styledHint
}

// flattenStatus turns a multi-line message into one line, collapsing the runs of
// whitespace that joining its lines leaves behind.
func flattenStatus(message string) string {
	message = strings.NewReplacer("\r\n", " ", "\r", " ", "\n", " ", "\t", " ").Replace(message)
	return strings.Join(strings.Fields(message), " ")
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
