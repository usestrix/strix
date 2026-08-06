package app

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/render"
)

var panelSeverityColors = map[string]lipgloss.Color{
	"critical": render.SevCrit, "high": render.SevHigh, "medium": render.SevMed, "low": green, "info": blue,
}

func (m Model) vulnerabilitiesView(width, height int) string {
	var lines []string
	start := min(max(0, m.vulnOffset), max(0, len(m.snapshot.Vulnerabilities)-1))
	for i := start; i < len(m.snapshot.Vulnerabilities) && len(lines) < height; i++ {
		vuln := m.snapshot.Vulnerabilities[i]
		severity := strings.ToLower(render.StringValue(vuln["severity"]))
		color, ok := panelSeverityColors[severity]
		if !ok {
			color = blue // matches SEVERITY_COLORS.get(severity, "#3b82f6")
		}
		marker := lipgloss.NewStyle().Foreground(color).Render("● ")
		style := lipgloss.NewStyle().Foreground(textColor)
		if i == m.selectedVuln {
			style = style.Bold(true).Foreground(white)
		}
		for row, titleLine := range m.vulnerabilityTitleLines(i, width) {
			if len(lines) >= height {
				break
			}
			prefix := "  "
			if row == 0 {
				prefix = marker
			}
			lines = append(lines, prefix+style.Render(titleLine))
		}
	}
	return strings.Join(lines, "\n")
}

func (m Model) vulnerabilityListWidth() int {
	_, sidebarWidth, _, _ := m.layout()
	return max(1, sidebarWidth-6)
}

func (m Model) vulnerabilityTitleLines(index, width int) []string {
	title := render.StringValue(m.snapshot.Vulnerabilities[index]["title"])
	if title == "" {
		title = "Unknown Vulnerability"
	}
	return strings.Split(wrapBlock(title, max(1, width-2)), "\n")
}

func (m Model) vulnerabilityScrollRows() (total, offset int) {
	width := m.vulnerabilityListWidth()
	for i := range m.snapshot.Vulnerabilities {
		rows := len(m.vulnerabilityTitleLines(i, width))
		total += rows
		if i < m.vulnOffset {
			offset += rows
		}
	}
	return total, offset
}

func (m Model) vulnerabilityOffsetAtRow(targetRow int) int {
	width := m.vulnerabilityListWidth()
	row := 0
	for i := range m.snapshot.Vulnerabilities {
		row += len(m.vulnerabilityTitleLines(i, width))
		if targetRow < row {
			return i
		}
	}
	return max(0, len(m.snapshot.Vulnerabilities)-1)
}

func (m Model) vulnerabilityVisibleEnd(start int) int {
	height := m.vulnerabilityPageSize()
	width := m.vulnerabilityListWidth()
	rows := 0
	end := min(max(0, start), len(m.snapshot.Vulnerabilities))
	for end < len(m.snapshot.Vulnerabilities) {
		itemRows := len(m.vulnerabilityTitleLines(end, width))
		if rows > 0 && rows+itemRows > height {
			break
		}
		rows += itemRows
		end++
		if rows >= height {
			break
		}
	}
	return end
}

func (m Model) vulnerabilityIndexAtRow(row int) int {
	width := m.vulnerabilityListWidth()
	currentRow := 0
	for i := m.vulnOffset; i < m.vulnerabilityVisibleEnd(m.vulnOffset); i++ {
		currentRow += len(m.vulnerabilityTitleLines(i, width))
		if row < currentRow {
			return i
		}
	}
	return -1
}

func (m *Model) ensureVulnerabilityVisible() {
	if len(m.snapshot.Vulnerabilities) == 0 {
		m.vulnOffset = 0
		return
	}
	if m.selectedVuln < m.vulnOffset {
		m.vulnOffset = m.selectedVuln
	}
	for m.selectedVuln >= m.vulnerabilityVisibleEnd(m.vulnOffset) && m.vulnOffset < m.selectedVuln {
		m.vulnOffset++
	}
	m.vulnOffset = min(m.vulnOffset, len(m.snapshot.Vulnerabilities)-1)
}

func (m Model) vulnerabilityPageSize() int {
	_, vulnHeight, _ := m.sidebarHeights()
	return max(1, vulnHeight-2)
}

func (m Model) vulnerabilityPageItems() int {
	return max(1, m.vulnerabilityVisibleEnd(m.vulnOffset)-m.vulnOffset)
}

func (m *Model) moveVulnerabilitySelection(delta int) {
	m.selectedVuln = max(0, min(len(m.snapshot.Vulnerabilities)-1, m.selectedVuln+delta))
}

func (m *Model) keepVulnerabilitySelectionInWindow() {
	if len(m.snapshot.Vulnerabilities) == 0 {
		return
	}
	if m.selectedVuln < m.vulnOffset {
		m.selectedVuln = m.vulnOffset
	} else if end := m.vulnerabilityVisibleEnd(m.vulnOffset); m.selectedVuln >= end {
		m.selectedVuln = max(m.vulnOffset, end-1)
	}
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
		render.Dim().Render("writable in the sandbox")
	return m.cornerPrompt(title, body, width, "Confirm", "Cancel")
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
	copyLabel := "Copy"
	if m.vulnerabilityCopied {
		copyLabel = "Copied!"
	} else if m.vulnerabilityCopyError != "" {
		copyLabel = "Copy failed"
	}
	copyButton := lipgloss.NewStyle().Foreground(lipgloss.Color("#525252"))
	doneButton := lipgloss.NewStyle().Foreground(mid)
	if m.modalChoice == 0 {
		copyButton = copyButton.Background(lipgloss.Color("#363636")).Foreground(brightWhite).Bold(true).Padding(0, 1)
	} else {
		doneButton = doneButton.Background(lipgloss.Color("#363636")).Foreground(brightWhite).Bold(true).Padding(0, 1)
	}
	buttons := copyButton.Render(copyLabel) + "  " + doneButton.Render("Done")
	buttonRow := rule + "\n" + lipgloss.NewStyle().Width(inner).Align(lipgloss.Right).Render(buttons)
	content := m.vulnerabilityScrollView() + "\n" + buttonRow
	return lipgloss.NewStyle().Width(width-2).Height(height-2).Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("#262626")).Background(lipgloss.Color("#0a0a0a")).Padding(2, 3).Render(content)
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
