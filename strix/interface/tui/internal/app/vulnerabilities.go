package app

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/render"
)

var panelSeverityColors = map[string]lipgloss.Color{
	"critical": render.SevCrit, "high": render.SevHigh, "medium": render.SevMed, "low": green, "info": blue,
}

// vulnerabilityRow is one rendered line of the findings list. The list scrolls by
// row rather than by finding, so a long title does not make the panel jump a
// whole entry at a time.
type vulnerabilityRow struct {
	index int    // the finding this line belongs to
	text  string // one wrapped line of its title
	first bool   // the line that carries the number and the severity dot
}

// vulnerabilityRows lays every finding out as the lines it will occupy.
func (m Model) vulnerabilityRows(width int) []vulnerabilityRow {
	// Wrapped lines sit under the title rather than under the severity dot.
	body := max(1, width-2)
	rows := make([]vulnerabilityRow, 0, len(m.snapshot.Vulnerabilities))
	for i := range m.snapshot.Vulnerabilities {
		for line, text := range strings.Split(wrapBlock(m.vulnerabilityTitle(i), body), "\n") {
			rows = append(rows, vulnerabilityRow{index: i, text: text, first: line == 0})
		}
	}
	return rows
}

func (m Model) vulnerabilitiesView(width, height int) string {
	rows := m.vulnerabilityRows(width)
	start := min(max(0, m.vulnOffset), max(0, len(rows)-1))
	end := min(len(rows), start+height)
	lines := make([]string, 0, max(0, end-start))
	for _, row := range rows[start:end] {
		style := lipgloss.NewStyle().Foreground(textColor)
		if row.index == m.selectedVuln {
			style = style.Bold(true).Foreground(white)
		}
		prefix := "  "
		if row.first {
			severity := strings.ToLower(render.StringValue(m.snapshot.Vulnerabilities[row.index]["severity"]))
			color, ok := panelSeverityColors[severity]
			if !ok {
				color = blue // matches SEVERITY_COLORS.get(severity, "#3b82f6")
			}
			prefix = lipgloss.NewStyle().Foreground(color).Render("● ")
		}
		lines = append(lines, prefix+style.Render(row.text))
	}
	return strings.Join(lines, "\n")
}

// vulnerabilityListWidth is the one width the findings list is laid out at, for
// rendering and for every interaction alike. Wrapping a title at two widths a
// column apart gives two different row counts, and then a click resolves to the
// wrong finding and the scrollbar reports the wrong length.
//
// The panel is sidebarWidth-2 wide with a column of padding either side, and the
// scrollbar takes one more. That last column is reserved whether or not the bar
// is showing, so the layout does not shift as the list grows past the panel.
func (m Model) vulnerabilityListWidth() int {
	_, sidebarWidth, _, _ := m.layout()
	return max(1, sidebarWidth-5)
}

func (m Model) vulnerabilityTitle(index int) string {
	title := render.StringValue(m.snapshot.Vulnerabilities[index]["title"])
	if title == "" {
		title = "Unknown Vulnerability"
	}
	return title
}

// vulnerabilityScrollRows reports the list length and position in rows, which is
// what the scrollbar needs to move continuously.
func (m Model) vulnerabilityScrollRows() (total, offset int) {
	return len(m.vulnerabilityRows(m.vulnerabilityListWidth())), m.vulnOffset
}

// vulnerabilityIndexAtRow maps a click on a visible row back to its finding.
func (m Model) vulnerabilityIndexAtRow(row int) int {
	rows := m.vulnerabilityRows(m.vulnerabilityListWidth())
	target := m.vulnOffset + row
	if target < 0 || target >= len(rows) {
		return -1
	}
	return rows[target].index
}

// ensureVulnerabilityVisible scrolls the least it can to bring the selected
// finding into view, keeping the whole entry visible where it fits.
func (m *Model) ensureVulnerabilityVisible() {
	rows := m.vulnerabilityRows(m.vulnerabilityListWidth())
	if len(rows) == 0 {
		m.vulnOffset = 0
		return
	}
	height := m.vulnerabilityPageSize()
	firstRow, lastRow := -1, -1
	for row, entry := range rows {
		if entry.index != m.selectedVuln {
			continue
		}
		if firstRow < 0 {
			firstRow = row
		}
		lastRow = row
	}
	if firstRow < 0 {
		m.vulnOffset = clampVulnerabilityOffset(m.vulnOffset, len(rows), height)
		return
	}
	if firstRow < m.vulnOffset {
		m.vulnOffset = firstRow
	} else if lastRow >= m.vulnOffset+height {
		// Prefer showing the whole entry, but never scroll its start out of view.
		m.vulnOffset = min(firstRow, lastRow-height+1)
	}
	m.vulnOffset = clampVulnerabilityOffset(m.vulnOffset, len(rows), height)
}

func clampVulnerabilityOffset(offset, total, height int) int {
	return min(max(0, offset), max(0, total-height))
}

func (m Model) vulnerabilityPageSize() int {
	_, vulnHeight, _ := m.sidebarHeights()
	return max(1, vulnHeight-2)
}

// vulnerabilityPageItems is how many findings a page step should move by: the
// number of distinct entries currently on screen.
func (m Model) vulnerabilityPageItems() int {
	rows := m.vulnerabilityRows(m.vulnerabilityListWidth())
	height := m.vulnerabilityPageSize()
	start := min(max(0, m.vulnOffset), max(0, len(rows)))
	end := min(len(rows), start+height)
	seen := 0
	previous := -1
	for _, row := range rows[start:end] {
		if row.index != previous {
			seen++
			previous = row.index
		}
	}
	return max(1, seen)
}

func (m *Model) moveVulnerabilitySelection(delta int) {
	m.selectedVuln = max(0, min(len(m.snapshot.Vulnerabilities)-1, m.selectedVuln+delta))
}

// keepVulnerabilitySelectionInWindow pulls the selection to the nearest finding
// still on screen after the list has been scrolled directly.
func (m *Model) keepVulnerabilitySelectionInWindow() {
	rows := m.vulnerabilityRows(m.vulnerabilityListWidth())
	if len(rows) == 0 {
		return
	}
	height := m.vulnerabilityPageSize()
	start := min(max(0, m.vulnOffset), max(0, len(rows)-1))
	end := min(len(rows), start+height)
	visible := rows[start:end]
	if len(visible) == 0 {
		return
	}
	for _, row := range visible {
		if row.index == m.selectedVuln {
			return
		}
	}
	if m.selectedVuln < visible[0].index {
		m.selectedVuln = visible[0].index
		return
	}
	m.selectedVuln = visible[len(visible)-1].index
}

// statsView ports build_tui_stats_text + the version line appended in
// _update_stats_display: model, token/cost line, optional Caido URL, version.
func (m Model) modalView() string {
	switch m.modal {
	case modalHelp:
		title := lipgloss.NewStyle().Bold(true).Foreground(green).Width(34).Align(lipgloss.Center).Render("Strix Help")
		body := lipgloss.NewStyle().Foreground(textColor).Render("F1        Help\nCtrl+O    Open viewer\nCtrl+Q/C  Quit\nESC       Stop Agent\nEnter     Send / expand node\nCtrl+J    Newline in message\nTab       Switch panels\n↑/↓       Navigate tree\nDrag      Select & copy text\nClick     Expand/collapse tool")
		content := title + "\n\n" + body
		return lipgloss.NewStyle().Width(38).Border(lipgloss.RoundedBorder()).BorderForeground(green).Background(black).Padding(1, 2).Render(content)
	case modalQuit:
		// #quit_dialog: width 24, border round #333333, title #d4d4d4.
		return m.confirmView("Quit Strix?", 24, dark, textColor)
	case modalStop:
		name := "agent"
		if len(m.snapshot.Agents) > 0 {
			name = m.snapshot.Agents[m.selectedAgent].Name
		}
		// #stop_agent_dialog: width 30, border round #a3a3a3, title #a3a3a3.
		return m.confirmView("🛑 Stop '"+name+"'?", 30, mid, mid)
	case modalConfirmMount:
		return m.mountConfirmView()
	case modalVulnerability:
		if len(m.snapshot.Vulnerabilities) == 0 {
			return ""
		}
		return m.vulnerabilityDetail()
	}
	return ""
}

func (m Model) confirmView(title string, width int, border, titleColor lipgloss.Color) string {
	return m.confirmDialog(title, "", width, border, titleColor, red, "Yes", "No")
}

// The mount prompt's buttons, named so the renderer and the click test cannot
// drift apart.
const (
	mountConfirmLabel = "Mount"
	mountCancelLabel  = "Skip"
)

// mountConfirmView asks before a target-less scan mounts the working directory.
// It is a compact prompt docked in the corner of the live view: nothing is
// prepared until it is answered, and the directory is a workspace rather than a
// target, so the prompt is what the scan follows.
func (m Model) mountConfirmView() string {
	width := min(52, max(20, m.width-4))
	dir := strings.TrimSpace(m.snapshot.PendingMount)
	if dir == "" {
		dir = "the current directory"
	}
	title := render.Bold(amber).Render("△ Mount working directory?")
	body := render.Col(white).Render(truncatePath(dir, width-4)) + "\n" +
		render.Dim().Render("writable in the sandbox · skip to run without it")
	return m.cornerPrompt(title, body, width, mountConfirmLabel, mountCancelLabel)
}

// truncatePath keeps the tail of a path visible, which is the part that
// identifies the directory.
func truncatePath(path string, width int) string {
	if width <= 1 || lipgloss.Width(path) <= width {
		return path
	}
	return "…" + ansi.TruncateLeft(path, lipgloss.Width(path)-width+1, "")
}

// cornerPrompt renders a compact two-button prompt for the corner of the live
// view, sized to its content rather than centered like the modal dialogs.
func (m Model) cornerPrompt(title, body string, width int, confirmLabel, cancelLabel string) string {
	// Each label keeps its padding whether or not it is focused, so moving the
	// choice repaints a background instead of shifting the pair sideways.
	button := func(label string, focused bool, fill lipgloss.Color) string {
		style := lipgloss.NewStyle().Bold(true)
		if focused {
			return style.Background(fill).Foreground(brightWhite).Render(" " + label + " ")
		}
		return style.Foreground(fill).Render(" " + label + " ")
	}
	yes := button(confirmLabel, m.modalChoice == 0, amber)
	no := button(cancelLabel, m.modalChoice != 0, dim)
	if m.modalChoice != 0 {
		no = button(cancelLabel, true, lipgloss.Color("#3e3e3e"))
	}
	inner := lipgloss.NewStyle().Width(width - 4)
	content := inner.Render(title) + "\n" + inner.Render(body) + "\n" +
		inner.Align(lipgloss.Right).Render(yes+" "+no)
	return lipgloss.NewStyle().Width(width-2).Border(lipgloss.RoundedBorder()).
		BorderForeground(amber).Background(black).Padding(0, 1).Render(content)
}

// confirmDialog renders a two-button prompt. The focused button fills its
// background; body is optional detail shown between the title and the buttons.
func (m Model) confirmDialog(
	title, body string,
	width int,
	border, titleColor, confirmColor lipgloss.Color,
	confirmLabel, cancelLabel string,
) string {
	// Two equal columns with a one-cell gutter. The buttons keep their columns
	// whichever one is focused, so moving the choice repaints a background
	// instead of shifting the row.
	contentWidth := width - 4
	inner := lipgloss.NewStyle().Width(contentWidth)
	// Two columns share the content width with a one-cell gutter; the label
	// carries a space on each side before it is centered in its column.
	leftColumn := (contentWidth - 1) / 2
	rightColumn := contentWidth - 1 - leftColumn
	button := func(label string, column int, focused bool, fill lipgloss.Color) string {
		style := lipgloss.NewStyle().Width(column).Align(lipgloss.Center).Bold(true)
		if focused {
			return style.Background(fill).Foreground(brightWhite).Render(" " + label + " ")
		}
		return style.Foreground(fill).Render(" " + label + " ")
	}
	yes := button(confirmLabel, leftColumn, m.modalChoice == 0, confirmColor)
	no := button(cancelLabel, rightColumn, false, dim)
	if m.modalChoice != 0 {
		no = button(cancelLabel, rightColumn, true, lipgloss.Color("#3e3e3e"))
	}
	content := inner.Bold(true).Foreground(titleColor).Align(lipgloss.Center).Render(title)
	if body != "" {
		content += "\n\n" + inner.Render(body)
	}
	content += "\n\n" + inner.Align(lipgloss.Center).Render(yes+" "+no)
	// Width() sets the content box, so the border's two columns come off it to
	// keep the dialog the width the design calls for.
	return lipgloss.NewStyle().Width(width - 2).Border(lipgloss.RoundedBorder()).BorderForeground(border).Background(black).Padding(1).Render(content)
}

// vulnerabilityBody ports VulnerabilityDetailScreen._render_vulnerability:
// the exact field order, labels, colors, and dict keys.
func vulnerabilityBody(v map[string]any) string {
	fieldStyle := render.Bold(render.Field)
	var b strings.Builder
	b.WriteString("🐞 " + render.Bold(render.ReportHdr).Render("Vulnerability Report"))

	field := func(label, value string) {
		if value != "" {
			b.WriteString("\n\n" + fieldStyle.Render(label+": ") + value)
		}
	}
	field("Agent", render.StringValue(v["agent_name"]))
	field("Title", render.StringValue(v["title"]))
	if sev := render.StringValue(v["severity"]); sev != "" {
		b.WriteString("\n\n" + fieldStyle.Render("Severity: ") +
			lipgloss.NewStyle().Bold(true).Foreground(render.SeverityColor(sev)).Render(strings.ToUpper(sev)))
	}
	if score, ok := render.NumericValue(v["cvss"]); ok {
		b.WriteString("\n\n" + fieldStyle.Render("CVSS Score: ") +
			lipgloss.NewStyle().Bold(true).Foreground(render.CVSSColor(score)).Render(render.StringValue(v["cvss"])))
	}
	field("Target", render.StringValue(v["target"]))
	if dep, ok := v["dependency_metadata"].(map[string]any); ok {
		field("Package", render.StringValue(dep["package_name"]))
		field("Ecosystem", render.StringValue(dep["package_ecosystem"]))
		field("Installed Version", render.StringValue(dep["installed_version"]))
		field("Fixed Version", render.StringValue(dep["fixed_version"]))
		field("Introduced By", render.StringValue(dep["introduced_by"]))
		field("Dependency Chain", render.StringValue(dep["dependency_path"]))
	}
	field("Endpoint", render.StringValue(v["endpoint"]))
	field("Method", render.StringValue(v["method"]))
	field("CVE", render.StringValue(v["cve"]))
	field("CWE", render.StringValue(v["cwe"]))
	if fe := render.StringValue(v["fix_effort"]); fe != "" {
		field("Fix Effort", titleCase(fe))
	}
	if bd, ok := v["cvss_breakdown"].(map[string]any); ok && len(bd) > 0 {
		if parts := render.CVSSVectorParts(bd); len(parts) > 0 {
			b.WriteString("\n\n" + fieldStyle.Render("CVSS Vector: ") + render.Dim().Render(strings.Join(parts, "/")))
		}
	}

	section := func(label, value string) {
		if value != "" {
			b.WriteString("\n\n" + fieldStyle.Render(label) + "\n" + value)
		}
	}
	section("Description", render.StringValue(v["description"]))
	section("Impact", render.StringValue(v["impact"]))
	section("Technical Analysis", render.StringValue(v["technical_analysis"]))
	section("Evidence", render.StringValue(v["evidence"]))
	section("PoC Description", render.StringValue(v["poc_description"]))
	if poc := render.StringValue(v["poc_script_code"]); poc != "" {
		pocLang, pocCode := render.ParseFencedCode(poc)
		b.WriteString("\n\n" + fieldStyle.Render("PoC Code") + "\n" + render.HighlightCode(pocCode, pocLang))
	}
	section("Remediation", render.StringValue(v["remediation_steps"]))
	section("Assumptions", render.StringValue(v["assumptions"]))
	return b.String()
}

func (m Model) vulnerabilityDialogSize() (width, height int) {
	return min(m.width, min(110, max(40, m.width*85/100))), min(m.height, min(45, max(10, m.height*85/100)))
}

func (m *Model) resizeVulnerabilityViewport() {
	if m.modal != modalVulnerability || len(m.snapshot.Vulnerabilities) == 0 {
		return
	}
	width, height := m.vulnerabilityDialogSize()
	innerWidth := max(1, width-8)               // border plus three cells of horizontal padding
	m.vulnViewport.Width = max(1, innerWidth-2) // right padding and one-cell scrollbar
	m.vulnViewport.Height = max(1, height-9)    // padding, one-row grid gutter, and two-row footer
	m.vulnViewport.SetContent(wrapBlock(vulnerabilityBody(m.snapshot.Vulnerabilities[m.selectedVuln]), m.vulnViewport.Width))
	m.vulnViewport.SetYOffset(m.vulnViewport.YOffset)
}

func (m Model) vulnerabilityScrollView() string {
	view := m.vulnViewport.View()
	if m.vulnViewport.TotalLineCount() <= m.vulnViewport.VisibleLineCount() {
		return view + "  "
	}
	height := m.vulnViewport.Height
	thumbHeight := max(1, height*m.vulnViewport.VisibleLineCount()/m.vulnViewport.TotalLineCount())
	thumbStart := int(m.vulnViewport.ScrollPercent() * float64(height-thumbHeight))
	bar := make([]string, height)
	for row := range bar {
		cell := " "
		if row >= thumbStart && row < thumbStart+thumbHeight {
			cell = lipgloss.NewStyle().Foreground(lipgloss.Color("#404040")).Render("█")
		}
		bar[row] = cell
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, view, " ", strings.Join(bar, "\n"))
}

func (m Model) vulnerabilityDetail() string {
	width, height := m.vulnerabilityDialogSize()
	inner := max(1, width-8)
	// Button row: right-aligned Copy / Done above a top rule (#vuln_detail_buttons).
	rule := lipgloss.NewStyle().Foreground(lipgloss.Color("#1a1a1a")).Render(strings.Repeat("─", max(1, inner)))
	focused := m.focusedReportButton()
	var stepping, acting []string
	for _, button := range m.reportButtons() {
		rendered := m.reportButton(button, button == focused)
		if button == reportPrev || button == reportNext {
			stepping = append(stepping, rendered)
			continue
		}
		acting = append(acting, rendered)
	}
	// Stepping sits on the left behind the position, acting on the right.
	right := strings.Join(acting, "  ")
	left := strings.Join(stepping, "  ")
	if total := len(m.snapshot.Vulnerabilities); total > 1 {
		left = render.Dim().Render(fmt.Sprintf("%d/%d", m.selectedVuln+1, total)) + "  " + left
	}
	room := max(0, inner-lipgloss.Width(right))
	buttonRow := rule + "\n" +
		lipgloss.NewStyle().Width(room).Render(truncate(left, room)) + right
	content := m.vulnerabilityScrollView() + "\n" + buttonRow
	return lipgloss.NewStyle().Width(width-2).Height(height-2).Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("#262626")).Background(lipgloss.Color("#0a0a0a")).Padding(2, 3).Render(content)
}

// showVulnerability moves the open report to another finding, keeping the list
// behind it in step and starting the new report at its top.
func (m *Model) showVulnerability(index int) {
	if index < 0 || index >= len(m.snapshot.Vulnerabilities) || index == m.selectedVuln {
		return
	}
	m.selectedVuln = index
	m.ensureVulnerabilityVisible()
	// The copy state belongs to the report that was on screen, not this one.
	m.vulnerabilityCopied = false
	m.vulnerabilityCopyError = ""
	m.resizeVulnerabilityViewport()
	m.vulnViewport.GotoTop()
}

// The report's buttons. Prev and Next carry their arrows so a click test cannot
// be fooled by the same word appearing in the body of a finding.
const (
	reportPrev = "‹ Prev"
	reportNext = "Next ›"
	reportCopy = "Copy"
	reportDone = "Done"
)

// reportButtons is the row as it stands, left to right. Stepping is offered only
// in the directions that have a report.
func (m Model) reportButtons() []string {
	previous, next := m.vulnerabilityNeighbors()
	buttons := make([]string, 0, 4)
	if previous {
		buttons = append(buttons, reportPrev)
	}
	if next {
		buttons = append(buttons, reportNext)
	}
	return append(buttons, reportCopy, reportDone)
}

// focusedReportButton is the button Enter would press. It falls back to Done when
// the focused one has gone, which happens when stepping to either end drops a
// direction from the row.
func (m Model) focusedReportButton() string {
	for _, button := range m.reportButtons() {
		if button == m.reportFocus {
			return button
		}
	}
	return reportDone
}

// stepReportFocus moves along the row, wrapping at its ends.
func (m *Model) stepReportFocus(delta int) {
	buttons := m.reportButtons()
	current := 0
	for i, button := range buttons {
		if button == m.focusedReportButton() {
			current = i
		}
	}
	m.reportFocus = buttons[clampCycle(current+delta, len(buttons))]
}

// vulnerabilityNeighbors reports which way the open report can be stepped. The
// ends are not wrapped: a report is one of an ordered list, and rolling from the
// last to the first hides that you reached the end.
func (m Model) vulnerabilityNeighbors() (previous, next bool) {
	return m.selectedVuln > 0, m.selectedVuln < len(m.snapshot.Vulnerabilities)-1
}

// reportButton renders one button of the report row. Copy reports the outcome of
// the last attempt in its own label.
func (m Model) reportButton(label string, focused bool) string {
	if label == reportCopy {
		switch {
		case m.vulnerabilityCopied:
			label = "Copied!"
		case m.vulnerabilityCopyError != "":
			label = "Copy failed"
		}
	}
	if focused {
		return lipgloss.NewStyle().Background(lipgloss.Color("#363636")).
			Foreground(brightWhite).Bold(true).Padding(0, 1).Render(label)
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("#525252")).Render(label)
}

func (m *Model) startVulnerabilityCopy() tea.Cmd {
	m.vulnerabilityCopied = false
	m.vulnerabilityCopyError = ""
	if m.selectedVuln < 0 || m.selectedVuln >= len(m.snapshot.Vulnerabilities) {
		return nil
	}
	report := vulnerabilityMarkdownReport(m.snapshot.Vulnerabilities[m.selectedVuln])
	return func() tea.Msg {
		return vulnerabilityCopiedMsg{err: writeClipboard(report)}
	}
}

// titleCase upper-cases the first letter of each word (Python str.title()).
