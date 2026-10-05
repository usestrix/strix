package app

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type sidebarPanel int

const (
	panelNone sidebarPanel = iota - 1
	panelAgents
	panelFindings
	panelMcp
	panelStats
)

const (
	panelOpenGlyph      = "▾"
	panelCollapsedGlyph = "▸"
	panelZoomGlyph      = "⤢"
	panelUnzoomGlyph    = "⤡"
	sidebarHideGlyph    = "»"
	sidebarShowGlyph    = "«"
	panelGlyphZone      = 3
)

type panelRect struct {
	panel  sidebarPanel
	top    int
	height int
}

func (m Model) panelControls() bool {
	return len(m.snapshot.Vulnerabilities) > 0 || len(m.snapshot.Connections) > 0
}

func (m Model) panelShrunk(panel sidebarPanel) bool {
	if panel == panelStats || !m.panelControls() {
		return false
	}
	return m.collapsedPanels[panel] || (m.zoomedPanel != panelNone && m.zoomedPanel != panel)
}

func (m Model) panelHeight(panel sidebarPanel, open int) int {
	if m.panelShrunk(panel) {
		return 1
	}
	return open
}

func panelFocus(panel sidebarPanel) (focusMode, bool) {
	switch panel {
	case panelAgents:
		return focusAgents, true
	case panelFindings:
		return focusVulnerabilities, true
	case panelMcp:
		return focusMcp, true
	default:
		return focusInput, false
	}
}

func (m Model) sidebarPanels() []panelRect {
	statsHeight, vulnHeight, mcpHeight, agentHeight := m.sidebarHeights()
	top := m.viewerHeight()
	rects := []panelRect{{panelAgents, top, agentHeight}}
	top += agentHeight
	if vulnHeight > 0 {
		rects = append(rects, panelRect{panelFindings, top, vulnHeight})
		top += vulnHeight
	}
	if mcpHeight > 0 {
		rects = append(rects, panelRect{panelMcp, top, mcpHeight})
		top += mcpHeight
	}
	top += m.sidebarGap()
	return append(rects, panelRect{panelStats, top, statsHeight})
}

func (m Model) sidebarGap() int {
	statsHeight, vulnHeight, mcpHeight, agentHeight := m.sidebarHeights()
	return max(0, m.height-m.viewerHeight()-agentHeight-vulnHeight-mcpHeight-statsHeight)
}

func (m Model) panelAt(y int) (panelRect, bool) {
	for _, rect := range m.sidebarPanels() {
		if y >= rect.top && y < rect.top+rect.height {
			return rect, true
		}
	}
	return panelRect{}, false
}

func (m Model) panelTop(panel sidebarPanel) int {
	for _, rect := range m.sidebarPanels() {
		if rect.panel == panel {
			return rect.top
		}
	}
	return 0
}

func (m Model) panelTitle(panel sidebarPanel) string {
	switch panel {
	case panelAgents:
		return fmt.Sprintf("Agents (%d)", len(m.snapshot.Agents))
	case panelFindings:
		return fmt.Sprintf("Findings (%d)", len(m.snapshot.Vulnerabilities))
	case panelMcp:
		return fmt.Sprintf("MCP (%d)", len(m.snapshot.Connections))
	default:
		return m.snapshot.Model
	}
}

func (m Model) panelHeader(panel sidebarPanel, width int) string {
	style := lipgloss.NewStyle().Foreground(dim)
	if !m.panelControls() {
		return truncate(style.Render(m.panelTitle(panel)), max(1, width))
	}
	glyph := panelZoomGlyph
	if m.zoomedPanel == panel {
		glyph = panelUnzoomGlyph
	}
	label := truncate(style.Render(panelOpenGlyph+" "+m.panelTitle(panel)), max(1, width-2))
	gap := max(1, width-lipgloss.Width(label)-1)
	return label + strings.Repeat(" ", gap) + style.Render(glyph)
}

func (m Model) collapsedPanelRow(panel sidebarPanel, width int) string {
	title := m.panelTitle(panel)
	if panel != panelStats {
		title = panelCollapsedGlyph + " " + title
	}
	label := lipgloss.NewStyle().Foreground(dim).Render(title)
	return " " + truncate(label, max(1, width-1))
}

func (m Model) panelBox(panel sidebarPanel, body string, width, height int, focused bool) string {
	if height <= 1 {
		return m.collapsedPanelRow(panel, width)
	}
	border := dark
	if focused {
		border = green
	}
	content := body
	if panel != panelStats {
		content = m.panelHeader(panel, width-4)
		if body != "" {
			content += "\n\n" + body
		}
	}
	return lipgloss.NewStyle().Width(width-2).Height(height-2).Border(lipgloss.RoundedBorder()).
		BorderForeground(border).Padding(0, 1).Render(content)
}

const (
	toggleButtonWidth = 3
	railButtonWidth   = 5
	railButtonHeight  = 3
	sidebarRailWidth  = railButtonWidth + 1
)

var toggleButtonFill = lipgloss.Color("#262626")

func sidebarToggleButton(glyph string) string {
	return lipgloss.NewStyle().
		Background(toggleButtonFill).
		Foreground(brightWhite).
		Bold(true).
		Width(toggleButtonWidth).
		Align(lipgloss.Center).
		Render(glyph)
}

func (m Model) railVisible() bool {
	return m.sidebarHidden && m.width >= 120
}

func (m Model) sidebarRail(height int) string {
	button := lipgloss.NewStyle().
		Background(toggleButtonFill).
		Foreground(brightWhite).
		Bold(true).
		Width(railButtonWidth).
		Height(railButtonHeight).
		Align(lipgloss.Center, lipgloss.Center).
		Render(sidebarShowGlyph)
	return lipgloss.NewStyle().
		Width(sidebarRailWidth).
		Height(height).
		Align(lipgloss.Right).
		Render(button)
}

func (m Model) toggleButtonHit(x, y int) bool {
	if m.railVisible() {
		return y < railButtonHeight && x >= m.width-railButtonWidth
	}
	return y == 1 && x >= m.width-2-toggleButtonWidth && x < m.width-2
}

func (m Model) viewerBox(width int) string {
	textWidth := max(1, width-toggleButtonWidth-1)
	text := m.viewerView(textWidth)
	rows := strings.Count(text, "\n") + 1
	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		fixedPanelBody(text, textWidth, rows),
		" ",
		sidebarToggleButton(sidebarHideGlyph),
	)
}

func (m *Model) toggleSidebar() {
	m.sidebarHidden = !m.sidebarHidden
	m.resizeViewport()
	m.panelsChanged()
}

func (m *Model) togglePanelCollapsed(panel sidebarPanel) {
	if m.collapsedPanels[panel] {
		delete(m.collapsedPanels, panel)
	} else {
		m.collapsedPanels[panel] = true
		if m.zoomedPanel == panel {
			m.zoomedPanel = panelNone
		}
	}
	m.panelsChanged()
}

func (m *Model) togglePanelZoom(panel sidebarPanel) {
	if m.zoomedPanel == panel {
		m.zoomedPanel = panelNone
	} else {
		m.zoomedPanel = panel
		delete(m.collapsedPanels, panel)
	}
	m.panelsChanged()
}

func (m *Model) revealPanel(panel sidebarPanel) {
	delete(m.collapsedPanels, panel)
	m.zoomedPanel = panelNone
	m.panelsChanged()
}

func (m *Model) clickPanel(rect panelRect, x, y int) bool {
	switch {
	case rect.panel == panelStats || !m.panelControls():
		return false
	case rect.height <= 1 && !m.panelShrunk(rect.panel):
		m.togglePanelZoom(rect.panel)
	case rect.height <= 1:
		m.revealPanel(rect.panel)
	case y-rect.top != 1:
		return false
	case x >= m.width-2-panelGlyphZone:
		m.togglePanelZoom(rect.panel)
	default:
		m.togglePanelCollapsed(rect.panel)
	}
	if focus, ok := panelFocus(rect.panel); ok && !m.panelShrunk(rect.panel) {
		m.focus = focus
		m.input.Blur()
	}
	return true
}

func (m *Model) panelsChanged() {
	showSidebar, _, _, _ := m.layout()
	for _, rect := range m.sidebarPanels() {
		if focus, ok := panelFocus(rect.panel); ok && m.focus == focus && (!showSidebar || rect.height <= 1) {
			m.focus = focusInput
			m.input.Focus()
		}
	}
	m.ensureAgentVisible()
	totalRows, _ := m.vulnerabilityScrollRows()
	m.vulnOffset = clampVulnerabilityOffset(m.vulnOffset, totalRows, m.vulnerabilityPageSize())
	m.mcpOffset = m.clampMcpOffset(m.mcpOffset)
}

func (m *Model) scrollPanel(panel sidebarPanel, delta int) {
	switch panel {
	case panelAgents:
		m.focus = focusAgents
		m.input.Blur()
		rows := m.agentPageSize()
		total := len(agentTreeEntries(m.snapshot.Agents, m.collapsedAgents))
		m.agentOffset = min(max(0, total-rows), max(0, m.agentOffset+delta))
		m.keepAgentSelectionInWindow()
		m.refreshViewport()
	case panelFindings:
		m.focus = focusVulnerabilities
		m.input.Blur()
		totalRows, _ := m.vulnerabilityScrollRows()
		m.vulnOffset = min(max(0, totalRows-m.vulnerabilityPageSize()), max(0, m.vulnOffset+delta))
		m.keepVulnerabilitySelectionInWindow()
	case panelMcp:
		m.focus = focusMcp
		m.input.Blur()
		m.mcpOffset = m.clampMcpOffset(m.mcpOffset + delta)
	}
}
