package app

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
)

func panelsModel(t *testing.T) Model {
	t.Helper()
	m := New(nil)
	m.width, m.height = 130, 40
	m.showSplash = false
	m.ready = true
	root := "root"
	agents := []protocol.Agent{{ID: root, Name: "Root Agent", Status: "running"}}
	for i := 0; i < 30; i++ {
		name := fmt.Sprintf("Worker %02d", i)
		agents = append(agents, protocol.Agent{ID: name, Name: name, ParentID: &root, Status: "running"})
	}
	conns := make([]protocol.Connection, 0, 12)
	for i := 0; i < 12; i++ {
		conns = append(conns, protocol.Connection{Name: fmt.Sprintf("conn-%02d", i), ToolCount: 2})
	}
	url := "http://127.0.0.1:57388/?token=abc"
	m.snapshot = protocol.Snapshot{
		ScanStarted: true, ScanState: "running", Agents: agents, Connections: conns,
		ViewerStatus: "running", ViewerURL: &url, Model: "openrouter/z-ai/glm-5.3",
		Vulnerabilities: []map[string]any{{"id": "v1", "title": "Finding one", "severity": "high"}},
	}
	m.resizeViewport()
	return m
}

func click(t *testing.T, m Model, x, y int) Model {
	t.Helper()
	updated, _ := m.updateMouse(tea.MouseMsg{X: x, Y: y, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
	return updated.(Model)
}

func panelRectOf(t *testing.T, m Model, panel sidebarPanel) panelRect {
	t.Helper()
	for _, rect := range m.sidebarPanels() {
		if rect.panel == panel {
			return rect
		}
	}
	t.Fatalf("panel %d not in sidebar", panel)
	return panelRect{}
}

func TestSidebarPanelsRenderHeadersWithControls(t *testing.T) {
	m := panelsModel(t)
	_, sidebarWidth, _, _ := m.layout()
	view := ansi.Strip(m.sidebarView(sidebarWidth, m.height))
	for _, want := range []string{"▾ Agents (31)", "▾ Findings (1)", "▾ MCP (12)", "⤢"} {
		if !strings.Contains(view, want) {
			t.Fatalf("sidebar missing %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "⤡") {
		t.Fatalf("nothing is zoomed, yet a restore glyph is drawn:\n%s", view)
	}
}

func TestClickingPanelHeaderCollapsesAndExpands(t *testing.T) {
	m := panelsModel(t)
	_, _, chatWidth, _ := m.layout()
	rect := panelRectOf(t, m, panelFindings)
	before := panelRectOf(t, m, panelAgents).height

	m = click(t, m, chatWidth+4, rect.top+1)
	collapsed := panelRectOf(t, m, panelFindings)
	if collapsed.height != 1 || !m.collapsedPanels[panelFindings] {
		t.Fatalf("header click did not collapse the panel: %+v", collapsed)
	}
	if got := panelRectOf(t, m, panelAgents).height; got <= before {
		t.Fatalf("agent panel did not grow into the freed rows: %d -> %d", before, got)
	}
	_, sidebarWidth, _, _ := m.layout()
	view := ansi.Strip(m.sidebarView(sidebarWidth, m.height))
	if !strings.Contains(view, "▸ Findings (1)") || strings.Contains(view, "Finding one") {
		t.Fatalf("collapsed panel should be a one-line header without its rows:\n%s", view)
	}

	m = click(t, m, chatWidth+4, collapsed.top)
	if panelRectOf(t, m, panelFindings).height == 1 || m.collapsedPanels[panelFindings] {
		t.Fatalf("clicking the collapsed row did not expand the panel")
	}
	if m.focus != focusVulnerabilities {
		t.Fatalf("expanded panel did not take focus: %v", m.focus)
	}
}

func TestClickingZoomGlyphGivesPanelTheSidebar(t *testing.T) {
	m := panelsModel(t)
	_, sidebarWidth, chatWidth, _ := m.layout()
	rect := panelRectOf(t, m, panelMcp)

	m = click(t, m, m.width-3, rect.top+1)
	if m.zoomedPanel != panelMcp {
		t.Fatalf("zoom glyph click did not zoom the panel: %d", m.zoomedPanel)
	}
	for _, other := range []sidebarPanel{panelAgents, panelFindings} {
		if got := panelRectOf(t, m, other).height; got != 1 {
			t.Fatalf("panel %d should shrink to its header while another is zoomed, got %d", other, got)
		}
	}
	zoomed := panelRectOf(t, m, panelMcp)
	rects := m.sidebarPanels()
	if last := rects[len(rects)-1]; last.top+last.height != m.height || zoomed.height < m.height-12 {
		t.Fatalf("zoomed panel does not fill the sidebar: %+v screen=%d", rects, m.height)
	}
	view := ansi.Strip(m.sidebarView(sidebarWidth, m.height))
	if !strings.Contains(view, "⤡") || !strings.Contains(view, "conn-11") {
		t.Fatalf("zoomed roster should show every connection and the restore glyph:\n%s", view)
	}
	if m.focus != focusMcp {
		t.Fatalf("zoomed panel did not take focus: %v", m.focus)
	}

	m = click(t, m, m.width-3, zoomed.top+1)
	if m.zoomedPanel != panelNone || panelRectOf(t, m, panelAgents).height == 1 {
		t.Fatalf("restore glyph did not unzoom")
	}

	m = click(t, m, m.width-3, panelRectOf(t, m, panelAgents).top+1)
	m = click(t, m, chatWidth+4, panelRectOf(t, m, panelFindings).top)
	if m.zoomedPanel != panelNone || m.collapsedPanels[panelFindings] {
		t.Fatalf("clicking a shrunk row should restore the whole sidebar")
	}
}

func TestToggleButtonsHideAndShowSidebar(t *testing.T) {
	m := panelsModel(t)
	m.focus = focusAgents
	showSidebar, sidebarWidth, chatWidth, _ := m.layout()
	if !showSidebar {
		t.Fatalf("precondition: sidebar visible")
	}
	rows := strings.Split(ansi.Strip(m.sidebarView(sidebarWidth, m.height)), "\n")
	if !strings.HasSuffix(rows[1], " »  │") || strings.Contains(rows[2], "»") {
		t.Fatalf("viewer panel lacks the one-row hide button:\n%s", strings.Join(rows[:3], "\n"))
	}
	if strings.Contains(ansi.Strip(m.View()), "«") || strings.Contains(ansi.Strip(m.statusView(chatWidth)), "sidebar") {
		t.Fatalf("show button or text hint drawn while the sidebar is visible")
	}

	m = click(t, m, m.width-4, 1)
	if showSidebar, _, width, _ := m.layout(); showSidebar || width != m.width-sidebarRailWidth-1 {
		t.Fatalf("hide button click did not hide the sidebar: show=%v chatWidth=%d", showSidebar, width)
	}
	if m.focus != focusInput {
		t.Fatalf("focus stayed on a hidden panel: %v", m.focus)
	}
	frame := ansi.Strip(m.View())
	rows = strings.Split(frame, "\n")
	if !strings.HasSuffix(rows[1], "  «  ") || strings.Contains(rows[0], "«") || strings.Contains(rows[3], "«") || lipgloss.Width(rows[0]) != m.width {
		t.Fatalf("hidden sidebar should leave a %d-row show button in the rail:\n%s", railButtonHeight, strings.Join(rows[:4], "\n"))
	}
	if !m.toggleButtonHit(m.width-railButtonWidth, railButtonHeight-1) || m.toggleButtonHit(m.width-railButtonWidth-1, 0) || m.toggleButtonHit(m.width-1, railButtonHeight) {
		t.Fatalf("show button hit zone does not match the drawn button")
	}
	if strings.Contains(frame, "»") {
		t.Fatalf("hide button drawn while the sidebar is hidden")
	}

	m = click(t, m, m.width-3, 2)
	if showSidebar, _, _, _ := m.layout(); !showSidebar {
		t.Fatalf("show button click did not bring the sidebar back")
	}
}

func TestFocusCyclingSkipsShrunkPanels(t *testing.T) {
	m := panelsModel(t)
	m.collapsedPanels[panelFindings] = true
	seen := map[focusMode]bool{}
	for range 6 {
		m.cycleFocus(1)
		seen[m.focus] = true
	}
	if seen[focusVulnerabilities] || !seen[focusAgents] || !seen[focusMcp] {
		t.Fatalf("tab order wrong with findings collapsed: %v", seen)
	}

	m.zoomedPanel = panelAgents
	seen = map[focusMode]bool{}
	for range 6 {
		m.cycleFocus(1)
		seen[m.focus] = true
	}
	if seen[focusMcp] || !seen[focusAgents] {
		t.Fatalf("tab order wrong with agents zoomed: %v", seen)
	}

	m.sidebarHidden = true
	seen = map[focusMode]bool{}
	for range 4 {
		m.cycleFocus(1)
		seen[m.focus] = true
	}
	if seen[focusAgents] || len(seen) != 2 {
		t.Fatalf("tab order should stay in the chat column with the sidebar hidden: %v", seen)
	}
}

func TestScrollbarHitTestFollowsPanelState(t *testing.T) {
	m := panelsModel(t)
	showSidebar, _, chatWidth, chatHeight := m.layout()
	agents := panelRectOf(t, m, panelAgents)
	at := func(y int) scrollbarTarget {
		return m.scrollbarAt(tea.MouseMsg{X: m.width - 3, Y: y}, showSidebar, chatWidth, chatHeight)
	}
	if at(agents.top+2) != scrollbarAgents {
		t.Fatalf("overflowing agent tree should expose its scrollbar")
	}
	if at(agents.top+1) != scrollbarNone {
		t.Fatalf("the header row is a control, not a scrollbar")
	}
	findings := panelRectOf(t, m, panelFindings)
	if at(findings.top+2) != scrollbarNone {
		t.Fatalf("a findings list that fits has no scrollbar to grab")
	}

	m.collapsedPanels[panelAgents] = true
	agents = panelRectOf(t, m, panelAgents)
	if agents.height != 1 || at(agents.top) != scrollbarNone {
		t.Fatalf("collapsed panel still reports a scrollbar")
	}
}

func TestSidebarFitsShortTerminal(t *testing.T) {
	m := panelsModel(t)
	m.height = 19
	m.snapshot.Connections = m.snapshot.Connections[:1]
	m.resizeViewport()
	_, sidebarWidth, _, _ := m.layout()
	rects := m.sidebarPanels()
	last := rects[len(rects)-1]
	if last.top+last.height > m.height {
		t.Fatalf("panels run past the screen: %+v (height %d)", rects, m.height)
	}
	if got := lipgloss.Height(m.sidebarView(sidebarWidth, m.height)); got > m.height {
		t.Fatalf("sidebar renders %d rows on a %d-row terminal", got, m.height)
	}
	squeezed := panelRectOf(t, m, panelMcp)
	if squeezed.height != 1 {
		t.Fatalf("expected the MCP panel squeezed to its header, got %+v", squeezed)
	}
	if last.panel != panelStats || last.height < 3 {
		t.Fatalf("Model panel must keep its box on short terminals: %+v", last)
	}
	m = click(t, m, m.width-6, squeezed.top)
	if m.zoomedPanel != panelMcp {
		t.Fatalf("clicking a squeezed header should zoom it, zoomed=%v", m.zoomedPanel)
	}
}

func TestModelPanelHasNoControlsAndNeverShrinks(t *testing.T) {
	m := panelsModel(t)
	_, sidebarWidth, _, _ := m.layout()
	stats := panelRectOf(t, m, panelStats)
	rows := strings.Split(ansi.Strip(m.sidebarView(sidebarWidth, m.height)), "\n")
	if first := rows[stats.top+1]; strings.ContainsAny(first, "▾▸⤢⤡") || strings.Contains(first, "Model") || !strings.Contains(first, m.snapshot.Model[:8]) {
		t.Fatalf("Model panel should start with the model name and carry no controls: %q", first)
	}
	before := m.sidebarPanels()
	m = click(t, m, m.width-3, stats.top+1)
	m = click(t, m, m.width-10, stats.top+1)
	if m.zoomedPanel != panelNone || len(m.collapsedPanels) != 0 {
		t.Fatalf("clicks on the Model header changed panel state: zoom=%v collapsed=%v", m.zoomedPanel, m.collapsedPanels)
	}
	m = click(t, m, m.width-3, panelRectOf(t, m, panelAgents).top+1)
	if m.zoomedPanel != panelAgents {
		t.Fatalf("precondition: agents zoomed")
	}
	after := panelRectOf(t, m, panelStats)
	if after.height != before[len(before)-1].height {
		t.Fatalf("Model panel shrank under zoom: %+v -> %+v", before[len(before)-1], after)
	}
}

func TestModelPanelSticksToBottom(t *testing.T) {
	m := panelsModel(t)
	m = click(t, m, m.width-10, panelRectOf(t, m, panelAgents).top+1)
	if !m.collapsedPanels[panelAgents] {
		t.Fatalf("precondition: agents collapsed")
	}
	stats := panelRectOf(t, m, panelStats)
	if stats.top+stats.height != m.height {
		t.Fatalf("Model panel not at the bottom: %+v (height %d)", stats, m.height)
	}
	_, sidebarWidth, _, _ := m.layout()
	rows := strings.Split(ansi.Strip(m.sidebarView(sidebarWidth, m.height)), "\n")
	if len(rows) != m.height {
		t.Fatalf("sidebar renders %d rows, want %d", len(rows), m.height)
	}
	if !strings.Contains(rows[stats.top+1], m.snapshot.Model[:8]) {
		t.Fatalf("Model panel not where its rect says:\n%s", strings.Join(rows[stats.top-2:], "\n"))
	}
}

func TestStatsPanelKeepsAssignedHeight(t *testing.T) {
	m := panelsModel(t)
	m.snapshot.Model = strings.Repeat("openrouter/some-vendor/a-very-long-model-name ", 12)
	m.resizeViewport()
	_, sidebarWidth, _, _ := m.layout()
	statsHeight, _, _, _ := m.sidebarHeights()
	if statsHeight != 15 {
		t.Fatalf("stats panel should hit its cap, got %d", statsHeight)
	}
	if got := lipgloss.Height(m.sidebarView(sidebarWidth, m.height)); got != m.height {
		t.Fatalf("sidebar renders %d rows, want %d", got, m.height)
	}
}

func TestHeadersAreFollowedByABlankRow(t *testing.T) {
	m := panelsModel(t)
	_, sidebarWidth, _, _ := m.layout()
	rows := strings.Split(ansi.Strip(m.sidebarView(sidebarWidth, m.height)), "\n")
	for _, panel := range []sidebarPanel{panelAgents, panelFindings, panelMcp} {
		rect := panelRectOf(t, m, panel)
		header, blank, first := rows[rect.top+1], rows[rect.top+2], rows[rect.top+3]
		if !strings.Contains(header, m.panelTitle(panel)) || strings.TrimSpace(strings.Trim(blank, "│")) != "" || strings.TrimSpace(strings.Trim(first, "│")) == "" {
			t.Fatalf("panel %d should render header, blank row, content:\n%s", panel, strings.Join(rows[rect.top:rect.top+4], "\n"))
		}
	}
}

func TestLonePanelHasNoControls(t *testing.T) {
	m := panelsModel(t)
	m.snapshot.Vulnerabilities = nil
	m.snapshot.Connections = nil
	_, sidebarWidth, _, _ := m.layout()
	view := ansi.Strip(m.sidebarView(sidebarWidth, m.height))
	if strings.ContainsAny(view, "▾▸⤢⤡") || !strings.Contains(view, "Agents (31)") {
		t.Fatalf("a lone Agents panel should carry no collapse or zoom controls:\n%s", view)
	}
	rect := panelRectOf(t, m, panelAgents)
	m = click(t, m, m.width-3, rect.top+1)
	m = click(t, m, m.width-10, rect.top+1)
	if m.zoomedPanel != panelNone || len(m.collapsedPanels) != 0 || panelRectOf(t, m, panelAgents) != rect {
		t.Fatalf("header clicks changed a lone panel: zoom=%v collapsed=%v", m.zoomedPanel, m.collapsedPanels)
	}
	if m.sidebarGap() != 0 {
		t.Fatalf("lone Agents panel should take the spare rows, gap=%d", m.sidebarGap())
	}
	m.snapshot.Connections = panelsModel(t).snapshot.Connections
	if !strings.Contains(ansi.Strip(m.sidebarView(sidebarWidth, m.height)), "▾ Agents (31)") {
		t.Fatalf("controls should return once a second panel exists")
	}
}
