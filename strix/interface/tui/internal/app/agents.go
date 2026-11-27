package app

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/usestrix/strix/tui/internal/protocol"
	"github.com/usestrix/strix/tui/internal/render"
)

type agentTreeEntry struct {
	index          int
	depth          int
	prefix         string
	approvalStatus bool
}

type agentDisplayRow struct {
	agentTreeEntry
	text string
}

// agentTreeEntries mirrors Textual Tree's depth-first ordering while retaining
// each agent's snapshot index for event lookup and commands.
func agentTreeEntries(agents []protocol.Agent, collapsed map[string]bool) []agentTreeEntry {
	indexByID := make(map[string]int, len(agents))
	for i, agent := range agents {
		indexByID[agent.ID] = i
	}
	children := make(map[int][]int, len(agents))
	var roots []int
	for i, agent := range agents {
		parentIndex := -1
		if agent.ParentID != nil {
			if candidate, ok := indexByID[*agent.ParentID]; ok && candidate != i {
				parentIndex = candidate
			}
		}
		if parentIndex < 0 {
			roots = append(roots, i)
		} else {
			children[parentIndex] = append(children[parentIndex], i)
		}
	}

	entries := make([]agentTreeEntry, 0, len(agents))
	visited := make(map[int]bool, len(agents))
	var hideDescendants func(int)
	hideDescendants = func(index int) {
		for _, child := range children[index] {
			if visited[child] {
				continue
			}
			visited[child] = true
			hideDescendants(child)
		}
	}
	var walk func(int, int, []bool, bool)
	walk = func(index, depth int, continuations []bool, isLast bool) {
		if visited[index] {
			return
		}
		visited[index] = true
		var prefix strings.Builder
		if depth > 0 {
			for _, continues := range continuations {
				if continues {
					prefix.WriteString("│  ")
				} else {
					prefix.WriteString("   ")
				}
			}
			if isLast {
				prefix.WriteString("└─ ")
			} else {
				prefix.WriteString("├─ ")
			}
		}
		entries = append(entries, agentTreeEntry{index: index, depth: depth, prefix: prefix.String()})
		if collapsed[agents[index].ID] {
			hideDescendants(index)
			return
		}
		nextContinuations := continuations
		if depth > 0 {
			nextContinuations = append(append([]bool(nil), continuations...), !isLast)
		}
		for i, child := range children[index] {
			walk(child, depth+1, nextContinuations, i == len(children[index])-1)
		}
	}
	for i, root := range roots {
		walk(root, 0, nil, i == len(roots)-1)
	}
	// Malformed cycles have no root. Keep their nodes visible rather than losing
	// them, treating the first unvisited node as another root.
	for i := range agents {
		if !visited[i] {
			walk(i, 0, nil, true)
		}
	}
	return entries
}

func hasAgentChildren(agentID string, agents []protocol.Agent) bool {
	for _, agent := range agents {
		if agent.ParentID != nil && *agent.ParentID == agentID {
			return true
		}
	}
	return false
}

func windowStart(offset, length, size int) int {
	return min(max(0, offset), max(0, length-size))
}

func selectedAgentRow(entries []agentTreeEntry, selectedIndex int) int {
	for row, entry := range entries {
		if entry.index == selectedIndex {
			return row
		}
	}
	return 0
}

func selectedAgentIndex(agents []protocol.Agent, selectedID string) int {
	if selectedID != "" {
		for i, agent := range agents {
			if agent.ID == selectedID {
				return i
			}
		}
	}
	return 0
}

func (m Model) selectedAgentID() string {
	if m.selectedAgent >= 0 && m.selectedAgent < len(m.snapshot.Agents) {
		return m.snapshot.Agents[m.selectedAgent].ID
	}
	return ""
}

func (m Model) selectedAgentCanStop() bool {
	if m.selectedAgent < 0 || m.selectedAgent >= len(m.snapshot.Agents) {
		return false
	}
	switch m.snapshot.Agents[m.selectedAgent].Status {
	case "running", "waiting", "budget_paused":
		return true
	default:
		return false
	}
}

func (m Model) agentsView(width, height int) string {
	return renderAgentRows(m.agentDisplayRows(width), m.agentOffset, height)
}

func renderAgentRows(rows []agentDisplayRow, offset, height int) string {
	start := windowStart(offset, len(rows), height)
	end := min(len(rows), start+height)
	var lines []string
	for _, row := range rows[start:end] {
		lines = append(lines, row.text)
	}
	return strings.Join(lines, "\n")
}

func (m Model) agentListWidth() int {
	return max(1, m.sidebarInnerWidth()-1)
}

func (m Model) agentDisplayRows(width int) []agentDisplayRow {
	var rows []agentDisplayRow
	statusIcons := map[string]string{"running": "⚪", "waiting": "⏸", "budget_paused": "⏸", "completed": "🟢", "failed": "🔴", "crashed": "🔴", "stopped": "■"}
	for _, entry := range agentTreeEntries(m.snapshot.Agents, m.collapsedAgents) {
		agent := m.snapshot.Agents[entry.index]
		icon := statusIcons[agent.Status]
		if icon == "" {
			icon = "○"
		}
		vulnSuffix := ""
		if count := m.agentVulnCount(agent.ID); count > 0 {
			vulnSuffix = fmt.Sprintf(" (%d)", count)
		}
		// Only a node with children carries a toggle; a leaf renders none at all,
		// so its icon sits where its parent's toggle would be.
		disclosure := ""
		if hasAgentChildren(agent.ID, m.snapshot.Agents) {
			disclosure = "▼ "
			if m.collapsedAgents[agent.ID] {
				disclosure = "▶ "
			}
		}
		label := disclosure + icon + " " + agent.Name + vulnSuffix
		// The guides are dim and stay outside the cursor; the cursor is a filled
		// block behind the label alone.
		labelStyle := lipgloss.NewStyle().Foreground(treeLabel)
		if entry.index == m.selectedAgent {
			labelStyle = labelStyle.Foreground(treeCursorFg).Background(treeCursorBg).Bold(true)
		}
		for i, line := range strings.Split(label, "\n") {
			prefix := entry.prefix
			if i > 0 {
				prefix = strings.Repeat(" ", lipgloss.Width(prefix))
			}
			room := max(1, width-lipgloss.Width(prefix))
			text := lipgloss.NewStyle().Foreground(treeGuide).Render(prefix) + labelStyle.Render(truncate(line, room))
			rows = append(rows, agentDisplayRow{entry, text})
		}
		pending := agent.ApprovalPending
		for _, approval := range m.snapshot.PendingApprovals {
			pending = pending || approval.AgentID == agent.ID
		}
		if pending {
			entry.approvalStatus = true
			rows = append(rows, agentDisplayRow{entry, render.Dim().Render(truncate(entry.prefix+"  waiting for approval", width))})
		}
	}
	return rows
}

// agentVulnCount counts vulnerabilities attributed to an agent, matching the
// " (N)" suffix _update_agent_node appends to each tree node.
func (m Model) agentVulnCount(agentID string) int {
	count := 0
	for _, vuln := range m.snapshot.Vulnerabilities {
		if render.StringValue(vuln["agent_id"]) == agentID {
			count++
		}
	}
	return count
}

func (m *Model) ensureAgentVisible() {
	entries := m.agentDisplayRows(m.agentListWidth())
	if len(entries) == 0 {
		m.agentOffset = 0
		return
	}
	rows := m.agentPageSize()
	row, last := selectedAgentDisplayBounds(entries, m.selectedAgent)
	if row < m.agentOffset {
		m.agentOffset = row
	} else if row >= m.agentOffset+rows {
		m.agentOffset = row - rows + 1
	} else if last >= m.agentOffset+rows {
		m.agentOffset = min(row, last-rows+1)
	}
	m.agentOffset = min(m.agentOffset, max(0, len(entries)-rows))
}

func (m Model) agentPageSize() int {
	_, _, _, agentHeight := m.sidebarHeights()
	return max(1, sidebarBodyRows(agentHeight))
}

func selectedAgentDisplayBounds(entries []agentDisplayRow, selected int) (first, last int) {
	for i, row := range entries {
		if row.index == selected {
			last = i
			for last+1 < len(entries) && entries[last+1].index == selected {
				last++
			}
			return i, last
		}
	}
	return 0, 0
}

func (m *Model) keepAgentSelectionInWindow() {
	entries := m.agentDisplayRows(m.agentListWidth())
	if len(entries) == 0 {
		return
	}
	rows := m.agentPageSize()
	row, last := selectedAgentDisplayBounds(entries, m.selectedAgent)
	if last < m.agentOffset {
		m.selectedAgent = entries[m.agentOffset].index
	} else if row >= m.agentOffset+rows {
		m.selectedAgent = entries[min(len(entries)-1, m.agentOffset+rows-1)].index
	}
}

func (m Model) agentHasEvents(agentID string) bool {
	for _, event := range m.snapshot.Events {
		if event.AgentID == agentID {
			return true
		}
	}
	return false
}

// sweepView ports _get_sweep_animation: a triangle-wave sweep of six squares
// across an 8-color palette (dimmest shows a "·"), matching the Python cadence
// and motion exactly.
