package app

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
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
	if msg.Action == tea.MouseActionMotion && !m.selection.dragging && m.draggingScrollbar == scrollbarNone {
		return m, nil
	}
	if m.height > 0 && msg.Action != tea.MouseActionRelease {
		// Bubble Tea drops leading rows when an alt-screen frame is too tall.
		msg.Y += max(0, lipgloss.Height(m.viewInner())-m.height)
	}
	if m.modal != modalNone {
		return m.updateModalMouse(msg)
	}
	if m.snapshot.SetupMode {
		return m.updateSetupMouse(msg)
	}
	showSidebar, _, chatWidth, chatHeight := m.layout()
	x, y := msg.X, msg.Y
	if m.updateMainScrollbarMouse(msg, showSidebar, chatWidth, chatHeight) {
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
			if rect, ok := m.panelAt(y); ok && rect.height > 1 {
				m.scrollPanel(rect.panel, -3)
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
			if rect, ok := m.panelAt(y); ok && rect.height > 1 {
				m.scrollPanel(rect.panel, 3)
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

	if x < chatWidth+1 {
		return m, nil
	}
	if m.toggleButtonHit(x, y) {
		m.selection.active = false
		m.toggleSidebar()
		return m, nil
	}
	if !showSidebar {
		return m, nil
	}
	if y < m.viewerHeight() {
		return m, send(m.client, "viewer.open", map[string]any{})
	}
	rect, ok := m.panelAt(y)
	if !ok || m.clickPanel(rect, x, y) {
		return m, nil
	}
	bodyRow, inBody := rect.bodyRow(y)
	switch rect.panel {
	case panelAgents:
		m.focus = focusAgents
		m.input.Blur()
		entries := m.agentDisplayRows(m.agentListWidth())
		start := windowStart(m.agentOffset, len(entries), m.agentPageSize())
		if row := start + bodyRow; inBody && row < len(entries) {
			m.selectedAgent = entries[row].index
			agentID := m.snapshot.Agents[m.selectedAgent].ID
			if !entries[row].approvalStatus && hasAgentChildren(agentID, m.snapshot.Agents) {
				m.collapsedAgents[agentID] = !m.collapsedAgents[agentID]
				m.ensureAgentVisible()
			}
			m.refreshViewport()
		}
	case panelFindings:
		m.focus = focusVulnerabilities
		m.input.Blur()
		if inBody {
			if idx := m.vulnerabilityIndexAtRow(bodyRow); idx >= 0 {
				m.selectedVuln = idx
				m.openModal(modalVulnerability)
			}
		}
	case panelMcp:
		m.focus = focusMcp
		m.input.Blur()
	}
	return m, nil
}

func (m *Model) updateMainScrollbarMouse(msg tea.MouseMsg, showSidebar bool, chatWidth, chatHeight int) bool {
	if msg.Action == tea.MouseActionRelease {
		if m.draggingScrollbar == scrollbarNone {
			return false
		}
		m.draggingScrollbar = scrollbarNone
		return true
	}
	if msg.Action == tea.MouseActionMotion && m.draggingScrollbar != scrollbarNone {
		m.scrollFromMouse(m.draggingScrollbar, msg.Y, chatHeight)
		return true
	}
	if msg.Action != tea.MouseActionPress || msg.Button != tea.MouseButtonLeft {
		return false
	}
	target := m.scrollbarAt(msg, showSidebar, chatWidth, chatHeight)
	if target == scrollbarNone {
		return false
	}
	m.draggingScrollbar = target
	m.scrollFromMouse(target, msg.Y, chatHeight)
	return true
}

// scrollbarGrab is how far either side of the bar still counts as grabbing it. A
// one column target is unreasonable to hit with a mouse, and nothing else lives
// in the column beside it.
const scrollbarGrab = 1

func nearColumn(x, column int) bool {
	return x >= column-scrollbarGrab && x <= column+scrollbarGrab
}

func (m Model) scrollbarAt(msg tea.MouseMsg, showSidebar bool, chatWidth, chatHeight int) scrollbarTarget {
	if nearColumn(msg.X, chatWidth-2) && msg.Y >= 1 && msg.Y < chatHeight-1 &&
		m.viewport.TotalLineCount() > m.viewport.VisibleLineCount() {
		return scrollbarTrace
	}
	if !showSidebar || msg.X < m.width-3 || msg.X > m.width-2 {
		return scrollbarNone
	}
	rect, ok := m.panelAt(msg.Y)
	if _, inBody := rect.bodyRow(msg.Y); !ok || !inBody {
		return scrollbarNone
	}
	switch rect.panel {
	case panelAgents:
		if len(m.agentDisplayRows(m.agentListWidth())) > m.agentPageSize() {
			return scrollbarAgents
		}
	case panelFindings:
		if totalRows, _ := m.vulnerabilityScrollRows(); totalRows > m.vulnerabilityPageSize() {
			return scrollbarFindings
		}
	case panelMcp:
		if len(m.snapshot.Connections) > m.mcpPageSize() {
			return scrollbarMcp
		}
	}
	return scrollbarNone
}

func (m *Model) scrollFromMouse(target scrollbarTarget, y, chatHeight int) {
	switch target {
	case scrollbarTrace:
		height := max(1, chatHeight-2)
		offset := scrollbarOffset(y-1, height, m.viewport.TotalLineCount(), m.viewport.VisibleLineCount(), m.viewport.YOffset)
		m.focus = focusChat
		m.input.Blur()
		m.viewport.SetYOffset(offset)
		m.followOutput = m.viewport.AtBottom()
	case scrollbarAgents:
		height := m.agentPageSize()
		total := len(m.agentDisplayRows(m.agentListWidth()))
		m.focus = focusAgents
		m.input.Blur()
		m.agentOffset = scrollbarOffset(y-m.panelTop(panelAgents)-sidebarBodyInset, height, total, height, m.agentOffset)
		m.keepAgentSelectionInWindow()
		m.refreshViewport()
	case scrollbarFindings:
		height := m.vulnerabilityPageSize()
		totalRows, _ := m.vulnerabilityScrollRows()
		m.focus = focusVulnerabilities
		m.input.Blur()
		// The offset is a row, so dragging moves the list continuously.
		m.vulnOffset = scrollbarOffset(y-m.panelTop(panelFindings)-sidebarBodyInset, height, totalRows, height, m.vulnOffset)
		m.keepVulnerabilitySelectionInWindow()
	case scrollbarMcp:
		height := m.mcpPageSize()
		total := len(m.snapshot.Connections)
		m.focus = focusMcp
		m.input.Blur()
		m.mcpOffset = scrollbarOffset(y-m.panelTop(panelMcp)-sidebarBodyInset, height, total, height, m.mcpOffset)
	}
}

func scrollbarOffset(row, height, total, visible, current int) int {
	maxOffset := max(0, total-visible)
	if height < 1 || maxOffset == 0 {
		return 0
	}
	if height == 1 {
		switch {
		case row < 0:
			return 0
		case row > 0:
			return maxOffset
		default:
			return min(max(0, current), maxOffset)
		}
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
	left, top, _, height := m.centeredViewBounds(view)
	if m.modal == modalApproval || m.modal == modalConfirmMount {
		left, top, _ = m.mountPromptBounds()
	}
	switch m.modal {
	case modalApproval:
		if buttonHitAt(view, " Allow ", left, top, height-2, msg) {
			cmd := m.answerApproval(true)
			return m, cmd
		}
		if buttonHitAt(view, " Block ", left, top, height-2, msg) {
			cmd := m.answerApproval(false)
			return m, cmd
		}
	case modalQuit, modalStop:
		row := height - 3
		if msg.Y == top+row {
			width := m.confirmDialogWidth() - 4
			column := (width - 1) / 2
			x := msg.X - left - 2
			colored := lipgloss.ColorProfile() != termenv.Ascii
			yesFill := colored && m.modalChoice == 0 && x >= 0 && x < column
			noFill := colored && m.modalChoice != 0 && x > column && x < width
			switch {
			case yesFill || buttonHitAt(view, confirmYes, left, top, row, msg):
				m.modalChoice = 0
			case noFill || buttonHitAt(view, confirmNo, left, top, row, msg):
				m.modalChoice = 1
			default:
				return m, nil
			}
			return m.updateModal(tea.KeyMsg{Type: tea.KeyEnter})
		}
	case modalConfirmMount:
		if buttonHitAt(view, " "+mountConfirmLabel+" ", left, top, height-2, msg) {
			m.modalChoice = 0
			cmd := m.answerMountConfirmation(true)
			return m, cmd
		}
		if buttonHitAt(view, " "+mountCancelLabel+" ", left, top, height-2, msg) {
			m.modalChoice = 1
			cmd := m.answerMountConfirmation(false)
			return m, cmd
		}
	case modalVulnerability:
		focused := m.focusedReportButton()
		for _, button := range m.reportButtons() {
			label := ansi.Strip(m.reportButton(button, button == focused))
			if buttonHitAt(view, label, left, top, 4+lipgloss.Height(m.vulnerabilityScrollView()), msg) {
				m.reportFocus = button
				return m.pressReportButton(button)
			}
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

func buttonHitAt(panel, label string, left, top, row int, msg tea.MouseMsg) bool {
	if row < 0 || msg.Y != top+row {
		return false
	}
	lines := strings.Split(panel, "\n")
	if row >= len(lines) {
		return false
	}
	plain := ansi.Strip(lines[row])
	if label == "" {
		return false
	}
	if index := strings.Index(plain, label); index >= 0 {
		start := left + ansi.StringWidth(plain[:index])
		return msg.X >= start && msg.X < start+ansi.StringWidth(label)
	}
	return false
}

func (m *Model) cycleFocus(delta int) {
	available := []focusMode{focusInput, focusChat}
	if showSidebar, _, _, _ := m.layout(); showSidebar {
		for _, rect := range m.sidebarPanels() {
			if focus, ok := panelFocus(rect.panel); ok && rect.height > 1 {
				available = append(available, focus)
			}
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
		if m.modal == modalApproval {
			cmd := m.answerApproval(false)
			return m, cmd
		}
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
		if modal == modalApproval {
			cmd := m.answerApproval(choice == 0)
			return m, cmd
		}
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
