package app

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

func (m Model) updateMain(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "f1":
		m.openModal(modalHelp)
		return m, nil
	case "ctrl+c", "ctrl+q":
		// Nothing to lose on the start screen; quit without confirmation.
		if m.snapshot.SetupMode {
			m.quitting = true
			return m, tea.Batch(send(m.client, "app.quit", map[string]any{}), tea.Quit)
		}
		m.modalChoice = 1
		m.openModal(modalQuit)
		return m, nil
	case "ctrl+o":
		return m, send(m.client, "viewer.open", map[string]any{})
	case "tab":
		m.cycleFocus(1)
		return m, nil
	case "shift+tab":
		m.cycleFocus(-1)
		return m, nil
	case "esc":
		if !m.snapshot.SetupMode && m.selectedAgentCanStop() {
			m.modalChoice = 1
			m.openModal(modalStop)
		}
		return m, nil
	case "up", "down":
		if m.focus == focusAgents && len(m.snapshot.Agents) > 0 {
			delta := 1
			if key.String() == "up" {
				delta = -1
			}
			entries := agentTreeEntries(m.snapshot.Agents, m.collapsedAgents)
			row := selectedAgentRow(entries, m.selectedAgent)
			row = max(0, min(len(entries)-1, row+delta))
			m.selectedAgent = entries[row].index
			m.ensureAgentVisible()
			m.refreshViewport()
			return m, nil
		}
		if m.focus == focusVulnerabilities && len(m.snapshot.Vulnerabilities) > 0 {
			delta := 1
			if key.String() == "up" {
				delta = -1
			}
			m.moveVulnerabilitySelection(delta)
			m.ensureVulnerabilityVisible()
			return m, nil
		}
		if m.focus == focusMcp && len(m.snapshot.Connections) > 0 {
			delta := 1
			if key.String() == "up" {
				delta = -1
			}
			m.mcpOffset = m.clampMcpOffset(m.mcpOffset + delta)
			return m, nil
		}
	case "enter", " ":
		if m.focus == focusVulnerabilities && len(m.snapshot.Vulnerabilities) > 0 {
			if key.String() == "enter" {
				m.openModal(modalVulnerability)
				return m, nil
			}
		}
		if m.focus == focusAgents {
			if m.selectedAgent < len(m.snapshot.Agents) {
				agentID := m.snapshot.Agents[m.selectedAgent].ID
				if hasAgentChildren(agentID, m.snapshot.Agents) {
					if m.collapsedAgents == nil {
						m.collapsedAgents = map[string]bool{}
					}
					m.collapsedAgents[agentID] = !m.collapsedAgents[agentID]
					m.ensureAgentVisible()
				}
			}
			return m, nil
		}
		if key.String() == "enter" && m.focus == focusInput {
			value := strings.TrimSpace(m.input.Value())
			m.input.SetValue("")
			m.resizeViewport()
			if value != "" {
				return m.submit(value)
			}
			return m, nil
		}
	case "pgup":
		if m.focus == focusVulnerabilities && len(m.snapshot.Vulnerabilities) > 0 {
			m.moveVulnerabilitySelection(-m.vulnerabilityPageItems())
			m.ensureVulnerabilityVisible()
			return m, nil
		}
		if m.focus == focusMcp && len(m.snapshot.Connections) > 0 {
			m.mcpOffset = m.clampMcpOffset(m.mcpOffset - m.mcpPageSize())
			return m, nil
		}
		m.focus = focusChat
		m.input.Blur()
		m.followOutput = false
		m.viewport.HalfViewUp()
		return m, nil
	case "pgdown":
		if m.focus == focusVulnerabilities && len(m.snapshot.Vulnerabilities) > 0 {
			m.moveVulnerabilitySelection(m.vulnerabilityPageItems())
			m.ensureVulnerabilityVisible()
			return m, nil
		}
		if m.focus == focusMcp && len(m.snapshot.Connections) > 0 {
			m.mcpOffset = m.clampMcpOffset(m.mcpOffset + m.mcpPageSize())
			return m, nil
		}
		m.focus = focusChat
		m.input.Blur()
		m.viewport.HalfViewDown()
		return m, nil
	case "home":
		if m.focus == focusVulnerabilities && len(m.snapshot.Vulnerabilities) > 0 {
			m.selectedVuln = 0
			m.ensureVulnerabilityVisible()
			return m, nil
		}
	case "end":
		if m.focus == focusVulnerabilities && len(m.snapshot.Vulnerabilities) > 0 {
			m.selectedVuln = len(m.snapshot.Vulnerabilities) - 1
			m.ensureVulnerabilityVisible()
			return m, nil
		}
		m.viewport.GotoBottom()
		m.followOutput = true
		return m, nil
	}
	if m.focus == focusChat {
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(key)
		return m, cmd
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(key)
	// Typing changes how far the composer wraps, so refit it.
	m.resizeViewport()
	return m, cmd
}

// updateMouse routes wheel and click events to the pane under the pointer.
func (m Model) updateMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	if m.modal != modalNone {
		return m.updateModalMouse(msg)
	}
	if m.snapshot.SetupMode {
		return m.updateSetupMouse(msg)
	}
	showSidebar, _, chatWidth, chatHeight := m.layout()
	viewerHeight := m.viewerHeight()
	_, vulnHeight, mcpHeight, agentHeight := m.sidebarHeights()
	x, y := msg.X, msg.Y
	if m.updateMainScrollbarMouse(
		msg, showSidebar, chatWidth, chatHeight, viewerHeight, agentHeight, vulnHeight, mcpHeight,
	) {
		return m, nil
	}
	if m.selection.dragging {
		switch msg.Action {
		case tea.MouseActionMotion:
			// Clamp to the owning pane so dragging past an edge keeps
			// extending the selection.
			if m.selection.region == regionInput {
				top := m.inputTop()
				cx := min(max(x, 2+inputPromptWidth), max(2+inputPromptWidth, chatWidth-2))
				cy := min(max(y, top+1), top+m.input.Height())
				if line, col, ok := m.inputContentCell(cx, cy); ok {
					m.extendSelection(line, col)
				}
				return m, nil
			}
			traceHeight := chatHeight - 2
			cx := min(max(x, 1), max(1, chatWidth-2))
			cy := min(max(y, 1), max(1, traceHeight))
			if line, col, ok := m.chatContentCell(cx, cy); ok {
				m.extendSelection(line, col)
			}
			return m, nil
		case tea.MouseActionRelease:
			return m, m.finishSelection()
		}
	}
	switch msg.Button {
	case tea.MouseButtonWheelUp:
		if showSidebar && x >= chatWidth+1 {
			switch {
			case y < viewerHeight:
				return m, nil
			case y < viewerHeight+agentHeight:
				m.focus = focusAgents
				m.input.Blur()
				m.agentOffset = max(0, m.agentOffset-3)
				m.keepAgentSelectionInWindow()
				m.refreshViewport()
			case vulnHeight > 0 && y < viewerHeight+agentHeight+vulnHeight:
				m.focus = focusVulnerabilities
				m.input.Blur()
				m.vulnOffset = max(0, m.vulnOffset-3)
				m.keepVulnerabilitySelectionInWindow()
			case mcpHeight > 0 && y < viewerHeight+agentHeight+vulnHeight+mcpHeight:
				m.focus = focusMcp
				m.input.Blur()
				m.mcpOffset = m.clampMcpOffset(m.mcpOffset - 3)
			}
			return m, nil
		}
		m.focus = focusChat
		m.input.Blur()
		m.followOutput = false
		m.viewport.LineUp(3)
		return m, nil
	case tea.MouseButtonWheelDown:
		if showSidebar && x >= chatWidth+1 {
			switch {
			case y < viewerHeight:
				return m, nil
			case y < viewerHeight+agentHeight:
				m.focus = focusAgents
				m.input.Blur()
				rows := m.agentPageSize()
				m.agentOffset = min(max(0, len(agentTreeEntries(m.snapshot.Agents, m.collapsedAgents))-rows), m.agentOffset+3)
				m.keepAgentSelectionInWindow()
				m.refreshViewport()
			case vulnHeight > 0 && y < viewerHeight+agentHeight+vulnHeight:
				m.focus = focusVulnerabilities
				m.input.Blur()
				totalRows, _ := m.vulnerabilityScrollRows()
				m.vulnOffset = min(max(0, totalRows-m.vulnerabilityPageSize()), m.vulnOffset+3)
				m.keepVulnerabilitySelectionInWindow()
			case mcpHeight > 0 && y < viewerHeight+agentHeight+vulnHeight+mcpHeight:
				m.focus = focusMcp
				m.input.Blur()
				m.mcpOffset = m.clampMcpOffset(m.mcpOffset + 3)
			}
			return m, nil
		}
		m.viewport.LineDown(3)
		if m.viewport.AtBottom() {
			m.followOutput = true
		}
		return m, nil
	}
	if msg.Action != tea.MouseActionPress || msg.Button != tea.MouseButtonLeft {
		return m, nil
	}
	statusH := 0
	if m.statusVisible() {
		statusH = 1
	}
	inputTop := chatHeight + statusH
	// Chat column: chat box on top, input box below the (optional) status row.
	if x < chatWidth {
		switch {
		case y >= inputTop:
			m.focus = focusInput
			m.input.Focus()
			if line, col, ok := m.inputContentCell(x, y); ok {
				m.beginSelection(regionInput, line, col)
			} else {
				m.selection.active = false
			}
		case y < chatHeight:
			m.focus = focusChat
			m.input.Blur()
			if line, col, ok := m.chatContentCell(x, y); ok {
				m.beginSelection(regionChat, line, col)
			} else {
				m.selection.active = false
			}
		default:
			m.selection.active = false
		}
		return m, nil
	}

	if !showSidebar || x < chatWidth+1 {
		return m, nil
	}
	// Sidebar: viewer, agents, vulnerabilities, then stats.
	switch {
	case y < viewerHeight:
		return m, send(m.client, "viewer.open", map[string]any{})
	case y < viewerHeight+agentHeight:
		m.focus = focusAgents
		m.input.Blur()
		// Content starts after the top border (1) and vertical padding (1).
		entries := agentTreeEntries(m.snapshot.Agents, m.collapsedAgents)
		start := windowStart(m.agentOffset, len(entries), max(1, agentHeight-4))
		localY := y - viewerHeight
		if row := start + localY - 2; localY >= 2 && localY < agentHeight-2 && row < len(entries) {
			m.selectedAgent = entries[row].index
			agentID := m.snapshot.Agents[m.selectedAgent].ID
			if hasAgentChildren(agentID, m.snapshot.Agents) {
				m.collapsedAgents[agentID] = !m.collapsedAgents[agentID]
				m.ensureAgentVisible()
			}
			m.refreshViewport()
		}
	case vulnHeight > 0 && y < viewerHeight+agentHeight+vulnHeight:
		m.focus = focusVulnerabilities
		m.input.Blur()
		// Content starts after the top border (1); clicking a row opens its detail.
		row := y - viewerHeight - agentHeight - 1
		if idx := m.vulnerabilityIndexAtRow(row); row >= 0 && row < vulnHeight-2 && idx >= 0 {
			m.selectedVuln = idx
			m.openModal(modalVulnerability)
		}
	}
	return m, nil
}

func (m *Model) updateMainScrollbarMouse(
	msg tea.MouseMsg,
	showSidebar bool,
	chatWidth, chatHeight, viewerHeight, agentHeight, vulnHeight, mcpHeight int,
) bool {
	if msg.Action == tea.MouseActionRelease {
		if m.draggingScrollbar == scrollbarNone {
			return false
		}
		m.draggingScrollbar = scrollbarNone
		return true
	}
	if msg.Action == tea.MouseActionMotion && m.draggingScrollbar != scrollbarNone {
		m.scrollFromMouse(m.draggingScrollbar, msg.Y, chatHeight, viewerHeight, agentHeight, vulnHeight)
		return true
	}
	if msg.Action != tea.MouseActionPress || msg.Button != tea.MouseButtonLeft {
		return false
	}
	target := m.scrollbarAt(msg, showSidebar, chatWidth, chatHeight, viewerHeight, agentHeight, vulnHeight, mcpHeight)
	if target == scrollbarNone {
		return false
	}
	m.draggingScrollbar = target
	m.scrollFromMouse(target, msg.Y, chatHeight, viewerHeight, agentHeight, vulnHeight)
	return true
}

// scrollbarGrab is how far either side of the bar still counts as grabbing it. A
// one column target is unreasonable to hit with a mouse, and nothing else lives
// in the column beside it.
const scrollbarGrab = 1

func nearColumn(x, column int) bool {
	return x >= column-scrollbarGrab && x <= column+scrollbarGrab
}

// scrollbarAt reports which scrollbar, if any, the pointer is over.
func (m Model) scrollbarAt(
	msg tea.MouseMsg,
	showSidebar bool,
	chatWidth, chatHeight, viewerHeight, agentHeight, vulnHeight, mcpHeight int,
) scrollbarTarget {
	mcpTop := viewerHeight + agentHeight + vulnHeight
	switch {
	case nearColumn(msg.X, chatWidth-2) && msg.Y >= 1 && msg.Y < chatHeight-1 &&
		m.viewport.TotalLineCount() > m.viewport.VisibleLineCount():
		return scrollbarTrace
	case showSidebar && nearColumn(msg.X, m.width-3) && msg.Y >= viewerHeight+2 &&
		msg.Y < viewerHeight+agentHeight-2 &&
		len(agentTreeEntries(m.snapshot.Agents, m.collapsedAgents)) > m.agentPageSize():
		return scrollbarAgents
	case showSidebar && vulnHeight > 0 && nearColumn(msg.X, m.width-3) &&
		msg.Y >= viewerHeight+agentHeight+1 &&
		msg.Y < viewerHeight+agentHeight+vulnHeight-1:
		totalRows, _ := m.vulnerabilityScrollRows()
		if totalRows > m.vulnerabilityPageSize() {
			return scrollbarFindings
		}
	// The roster scrolls below a fixed header, so its bar starts two rows into
	// the panel (border then header) rather than one.
	case showSidebar && mcpHeight > 0 && nearColumn(msg.X, m.width-3) &&
		msg.Y >= mcpTop+2 && msg.Y < mcpTop+mcpHeight-1:
		if len(m.snapshot.Connections) > m.mcpPageSize() {
			return scrollbarMcp
		}
	}
	return scrollbarNone
}

func (m *Model) scrollFromMouse(
	target scrollbarTarget,
	y, chatHeight, viewerHeight, agentHeight, vulnHeight int,
) {
	switch target {
	case scrollbarTrace:
		height := max(1, chatHeight-2)
		offset := scrollbarOffset(y-1, height, m.viewport.TotalLineCount(), m.viewport.VisibleLineCount())
		m.focus = focusChat
		m.input.Blur()
		m.viewport.SetYOffset(offset)
		m.followOutput = m.viewport.AtBottom()
	case scrollbarAgents:
		height := m.agentPageSize()
		total := len(agentTreeEntries(m.snapshot.Agents, m.collapsedAgents))
		m.focus = focusAgents
		m.input.Blur()
		m.agentOffset = scrollbarOffset(y-viewerHeight-2, height, total, height)
		m.keepAgentSelectionInWindow()
		m.refreshViewport()
	case scrollbarFindings:
		height := m.vulnerabilityPageSize()
		totalRows, _ := m.vulnerabilityScrollRows()
		m.focus = focusVulnerabilities
		m.input.Blur()
		// The offset is a row, so dragging moves the list continuously.
		m.vulnOffset = scrollbarOffset(y-viewerHeight-agentHeight-1, height, totalRows, height)
		m.keepVulnerabilitySelectionInWindow()
	case scrollbarMcp:
		height := m.mcpPageSize()
		total := len(m.snapshot.Connections)
		m.focus = focusMcp
		m.input.Blur()
		// The bar starts two rows into the panel (border then the fixed header).
		m.mcpOffset = scrollbarOffset(y-viewerHeight-agentHeight-vulnHeight-2, height, total, height)
	}
}

func scrollbarOffset(row, height, total, visible int) int {
	maxOffset := max(0, total-visible)
	if height <= 1 || maxOffset == 0 {
		return 0
	}
	return maxOffset * min(max(0, row), height-1) / (height - 1)
}

func (m Model) updateSetupMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	switch msg.Button {
	case tea.MouseButtonWheelUp:
		m.focus = focusChat
		m.input.Blur()
		m.followOutput = false
		m.viewport.LineUp(3)
		return m, nil
	case tea.MouseButtonWheelDown:
		m.viewport.LineDown(3)
		if m.viewport.AtBottom() {
			m.followOutput = true
		}
		return m, nil
	}
	if msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonLeft {
		m.focus = focusInput
		m.input.Focus()
	}
	return m, nil
}

// pressReportButton performs a button of the report row, however it was reached.
func (m Model) pressReportButton(button string) (tea.Model, tea.Cmd) {
	switch button {
	case reportPrev:
		m.showVulnerability(m.selectedVuln - 1)
	case reportNext:
		m.showVulnerability(m.selectedVuln + 1)
	case reportCopy:
		m.reportFocus = reportCopy
		return m, m.startVulnerabilityCopy()
	default:
		m.closeModal()
	}
	return m, nil
}

func (m Model) updateModalMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	if m.modal == modalVulnerability {
		view := m.modalView()
		left, top, _, _ := m.centeredViewBounds(view)
		viewportLeft := left + 4 // border and three-cell dialog padding
		viewportTop := top + 3   // border and two-cell dialog padding
		insideViewport := msg.X >= viewportLeft && msg.X < viewportLeft+m.vulnViewport.Width+2 &&
			msg.Y >= viewportTop && msg.Y < viewportTop+m.vulnViewport.Height
		switch msg.Button {
		case tea.MouseButtonWheelUp:
			if insideViewport {
				m.vulnViewport.LineUp(3)
			}
			return m, nil
		case tea.MouseButtonWheelDown:
			if insideViewport {
				m.vulnViewport.LineDown(3)
			}
			return m, nil
		}
	}
	if msg.Action != tea.MouseActionPress || msg.Button != tea.MouseButtonLeft {
		return m, nil
	}
	view := m.modalView()
	switch m.modal {
	case modalQuit, modalStop:
		if m.centeredLabelHit(view, "Yes", msg.X, msg.Y) {
			m.modalChoice = 0
			return m.updateModal(tea.KeyMsg{Type: tea.KeyEnter})
		}
		if m.centeredLabelHit(view, "No", msg.X, msg.Y) {
			m.modalChoice = 1
			return m.updateModal(tea.KeyMsg{Type: tea.KeyEnter})
		}
	case modalConfirmMount:
		left, top, panel := m.mountPromptBounds()
		if labelHitAt(panel, mountConfirmLabel, left, top, msg.X, msg.Y) {
			m.modalChoice = 0
			cmd := m.answerMountConfirmation(true)
			return m, cmd
		}
		if labelHitAt(panel, mountCancelLabel, left, top, msg.X, msg.Y) {
			m.modalChoice = 1
			cmd := m.answerMountConfirmation(false)
			return m, cmd
		}
	case modalVulnerability:
		for _, button := range m.reportButtons() {
			if button == reportCopy || button == reportDone {
				continue
			}
			if m.centeredLabelHit(view, button, msg.X, msg.Y) {
				m.reportFocus = button
				return m.pressReportButton(button)
			}
		}
		if m.centeredLabelHit(view, "Copy", msg.X, msg.Y) {
			m.reportFocus = reportCopy
			cmd := m.startVulnerabilityCopy()
			return m, cmd
		}
		if m.centeredLabelHit(view, "Done", msg.X, msg.Y) {
			m.reportFocus = reportDone
			m.closeModal()
		}
	}
	return m, nil
}

func (m Model) centeredViewBounds(view string) (left, top, width, height int) {
	width = lipgloss.Width(view)
	height = strings.Count(view, "\n") + 1
	left = max(0, (m.width-width)/2)
	top = max(0, (m.height-height)/2)
	return
}

func (m Model) centeredLabelHit(view, label string, x, y int) bool {
	left, top, _, _ := m.centeredViewBounds(view)
	return labelHitAt(view, label, left, top, x, y)
}

// labelHitAt reports whether a click landed on a label drawn in a panel whose
// top-left corner is at (left, top). The mount prompt is docked in a corner
// rather than centered, so it cannot use the centered bounds.
func labelHitAt(panel, label string, left, top, x, y int) bool {
	for row, line := range strings.Split(panel, "\n") {
		plain := ansi.Strip(line)
		index := strings.Index(plain, label)
		if index < 0 || y != top+row {
			continue
		}
		start := left + ansi.StringWidth(plain[:index])
		return x >= start-1 && x < start+ansi.StringWidth(label)+1
	}
	return false
}

func (m *Model) cycleFocus(delta int) {
	available := []focusMode{focusInput, focusChat}
	if m.width >= 120 {
		available = append(available, focusAgents)
		if len(m.snapshot.Vulnerabilities) > 0 {
			available = append(available, focusVulnerabilities)
		}
		if len(m.snapshot.Connections) > 0 {
			available = append(available, focusMcp)
		}
	}
	idx := 0
	for i, focus := range available {
		if focus == m.focus {
			idx = i
		}
	}
	m.focus = available[clampCycle(idx+delta, len(available))]
	if m.focus == focusInput {
		m.input.Focus()
	} else {
		m.input.Blur()
	}
}

func clampCycle(value, length int) int {
	if length <= 0 {
		return 0
	}
	return (value%length + length) % length
}

func (m Model) updateModal(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.modal == modalHelp {
		if key.String() != "" {
			m.closeModal()
		}
		return m, nil
	}
	if m.modal == modalVulnerability {
		switch key.String() {
		case "esc":
			m.closeModal()
		// The arrows step between reports directly; tab walks the button row.
		case "left":
			m.showVulnerability(m.selectedVuln - 1)
		case "right":
			m.showVulnerability(m.selectedVuln + 1)
		case "tab":
			m.stepReportFocus(1)
		case "shift+tab":
			m.stepReportFocus(-1)
		case "enter":
			return m.pressReportButton(m.focusedReportButton())
		case "c":
			m.reportFocus = reportCopy
			cmd := m.startVulnerabilityCopy()
			return m, cmd
		case "up":
			m.vulnViewport.LineUp(1)
		case "down":
			m.vulnViewport.LineDown(1)
		case "pgup":
			m.vulnViewport.HalfViewUp()
		case "pgdown":
			m.vulnViewport.HalfViewDown()
		case "home":
			m.vulnViewport.GotoTop()
		case "end":
			m.vulnViewport.GotoBottom()
		}
		return m, nil
	}
	switch key.String() {
	case "esc":
		if m.modal == modalConfirmMount {
			// The backend is waiting on an answer; escape declines it.
			cmd := m.answerMountConfirmation(false)
			return m, cmd
		}
		m.closeModal()
		return m, nil
	case "left", "right", "up", "down", "tab":
		m.modalChoice = 1 - m.modalChoice
		return m, nil
	case "enter":
		modal, choice := m.modal, m.modalChoice
		if modal == modalConfirmMount {
			// The snapshot closes this prompt once the backend has the answer.
			// Bound to a variable first: the call restores the held prompt into
			// the composer, and that has to be in the model being returned.
			cmd := m.answerMountConfirmation(choice == 0)
			return m, cmd
		}
		m.closeModal()
		if choice == 1 {
			return m, nil
		}
		if modal == modalQuit {
			m.quitting = true
			return m, tea.Batch(send(m.client, "app.quit", map[string]any{}), tea.Quit)
		}
		if modal == modalStop && m.selectedAgentCanStop() {
			agent := m.snapshot.Agents[m.selectedAgent]
			return m, send(m.client, "agent.stop", map[string]any{"agent_id": agent.ID})
		}
	}
	return m, nil
}

func (m *Model) openModal(mode modalMode) {
	m.modal = mode
	m.input.Blur()
	if mode == modalConfirmMount {
		// A consent prompt defaults to declining.
		m.modalChoice = 1
	}
	if mode == modalVulnerability {
		m.reportFocus = reportDone
		m.modalChoice = 1
		m.vulnerabilityCopied = false
		m.vulnerabilityCopyError = ""
		m.resizeVulnerabilityViewport()
		m.vulnViewport.GotoTop()
	}
}

func (m *Model) closeModal() {
	m.modal = modalNone
	if m.focus == focusInput {
		m.input.Focus()
	}
}
