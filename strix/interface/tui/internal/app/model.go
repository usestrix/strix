package app

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
	"github.com/usestrix/strix/tui/internal/render"
)

type wireMsg protocol.Envelope
type wireErrMsg struct{ err error }
type sentMsg struct {
	requestID  string
	command    string
	collection string
	err        error
}
type splashTickMsg time.Time
type sweepTickMsg time.Time
type vulnerabilityCopiedMsg struct{ err error }

var writeClipboard = clipboard.WriteAll

type collectionAssembly struct {
	kind         string
	revision     int
	baseRevision int
	cursor       int
	agents       []protocol.Agent
	events       []protocol.Event
	findings     []map[string]any
	operations   []protocol.CollectionOperation
	ids          map[string]bool
}

type modelListingAssembly struct {
	listingID     string
	cursor        int
	groups        []protocol.ModelGroup
	groupIndexes  map[string]int
	providers     []protocol.Provider
	providerNames map[string]bool
}

// appVersion is the package version string shown on the splash and stats panel.
// It is set by main from the STRIX_VERSION env var (see go_tui.py), matching
// Python's get_package_version() which reads the installed "strix-agent" version
// and falls back to "dev".
var appVersion = "dev"

// SetVersion overrides the displayed version; empty values are ignored so the
// "dev" fallback survives when the launcher does not provide one.
func SetVersion(v string) {
	if strings.TrimSpace(v) != "" {
		appVersion = strings.TrimSpace(v)
	}
}

type pickerMode int

const (
	pickerNone pickerMode = iota
	pickerProvider
	pickerModel
	pickerManualModel
	pickerScanMode
	pickerAPIKey
	pickerCustomKind
	pickerCustomName
	pickerCustomURL
	pickerCustomAPIKey
)

type modalMode int

const (
	modalNone modalMode = iota
	modalHelp
	modalQuit
	modalStop
	modalVulnerability
)

type focusMode int

const (
	focusInput focusMode = iota
	focusChat
	focusAgents
	focusVulnerabilities
)

type scrollbarTarget int

const (
	scrollbarNone scrollbarTarget = iota
	scrollbarTrace
	scrollbarAgents
	scrollbarFindings
)

type Model struct {
	client                 *Client
	width, height          int
	snapshot               protocol.Snapshot
	input                  textinput.Model
	pickerInput            textinput.Model
	viewport               viewport.Model
	viewportContent        string
	vulnViewport           viewport.Model
	picker                 pickerMode
	modal                  modalMode
	focus                  focusMode
	options                []string
	filtered               []string
	cursor                 int
	configProvider         string
	configProviderLabel    string
	configProviderState    string
	configProviderDetail   string
	keyEnv                 string
	providerConfigured     map[string]bool
	providerLabels         map[string]string
	providerStates         map[string]string
	providerDetails        map[string]string
	providerDisconnectable map[string]bool
	modelOptions           map[string]modelPickerOption
	manualModelProvider    string
	manualModelLabel       string
	customKind             string
	customName             string
	customURL              string
	collapsedAgents        map[string]bool
	setupLog               []string
	errorText              string
	fatalError             error
	selectedAgent          int
	selectedVuln           int
	agentOffset            int
	vulnOffset             int
	commandCursor          int
	modalChoice            int
	ready                  bool
	quitting               bool
	showSplash             bool
	splashStarted          time.Time
	splashFrame            int
	sweepFrame             int
	followOutput           bool
	draggingScrollbar      scrollbarTarget
	stateRevision          int
	collectionRevisions    map[string]int
	collectionAssemblies   map[string]*collectionAssembly
	resyncRequested        map[string]bool
	resyncRequests         map[string]string
	modelListing           *modelListingAssembly
	seenMessages           map[string]bool
	vulnerabilityCopied    bool
	vulnerabilityCopyError string
}

type modelPickerOption struct {
	provider string
	label    string
	model    string
	manual   bool
}

var (
	green       = lipgloss.Color("#22c55e")
	brightGreen = lipgloss.Color("#4ade80")
	blue        = lipgloss.Color("#3b82f6")
	lightBlue   = lipgloss.Color("#60a5fa")
	red         = lipgloss.Color("#ef4444")
	orange      = lipgloss.Color("#ea580c")
	amber       = lipgloss.Color("#d97706")
	white       = lipgloss.Color("#fafaf9")
	brightWhite = lipgloss.Color("#ffffff")
	textColor   = lipgloss.Color("#d4d4d4")
	dim         = lipgloss.Color("#737373")
	mid         = lipgloss.Color("#a3a3a3")
	dark        = lipgloss.Color("#333333")
	black       = lipgloss.Color("#000000")
)

const banner = ` ███████╗████████╗██████╗ ██╗██╗  ██╗
 ██╔════╝╚══██╔══╝██╔══██╗██║╚██╗██╔╝
 ███████╗   ██║   ██████╔╝██║ ╚███╔╝
 ╚════██║   ██║   ██╔══██╗██║ ██╔██╗
 ███████║   ██║   ██║  ██║██║██╔╝ ██╗
 ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝`

func New(client *Client) Model {
	newInput := func() textinput.Model {
		input := textinput.New()
		input.Prompt = ""
		input.CharLimit = 4096
		input.TextStyle = lipgloss.NewStyle().Foreground(textColor)
		input.Cursor.Style = lipgloss.NewStyle().Foreground(green)
		return input
	}
	input := newInput()
	input.Placeholder = "Type / to configure your scan"
	input.PlaceholderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#525252"))
	input.Focus()
	return Model{
		client: client, input: input, pickerInput: newInput(), viewport: viewport.New(80, 20), vulnViewport: viewport.New(80, 20),
		collapsedAgents: map[string]bool{}, providerConfigured: map[string]bool{}, providerLabels: map[string]string{}, providerStates: map[string]string{}, providerDetails: map[string]string{}, providerDisconnectable: map[string]bool{}, showSplash: true, splashStarted: time.Now(), followOutput: true,
		collectionRevisions: map[string]int{}, collectionAssemblies: map[string]*collectionAssembly{}, resyncRequested: map[string]bool{}, resyncRequests: map[string]string{},
		seenMessages: map[string]bool{},
	}
}

func (m Model) Init() tea.Cmd { return tea.Batch(readWire(m.client), splashTick(), sweepTick()) }

// splashTick drives the splash "Starting Strix Agent" shimmer at Python's 0.1s cadence.
func splashTick() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg { return splashTickMsg(t) })
}

// sweepTick drives the running-status sweep animation at Python's 0.06s cadence.
func sweepTick() tea.Cmd {
	return tea.Tick(60*time.Millisecond, func(t time.Time) tea.Msg { return sweepTickMsg(t) })
}

func readWire(client *Client) tea.Cmd {
	return func() tea.Msg {
		envelope, err := client.Read()
		if err != nil {
			return wireErrMsg{err}
		}
		return wireMsg(envelope)
	}
}

func send(client *Client, command string, payload any) tea.Cmd {
	return func() tea.Msg {
		requestID, err := client.Send(command, payload)
		collection := ""
		if values, ok := payload.(map[string]any); ok {
			collection, _ = values["collection"].(string)
		}
		return sentMsg{requestID: requestID, command: command, collection: collection, err: err}
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case splashTickMsg:
		m.splashFrame++
		if m.showSplash && time.Since(m.splashStarted) >= 4500*time.Millisecond {
			m.showSplash = false
		}
		return m, splashTick()
	case sweepTickMsg:
		m.sweepFrame++
		return m, sweepTick()
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resizeViewport()
		m.resizeVulnerabilityViewport()
		m.ensureAgentVisible()
		m.ensureVulnerabilityVisible()
	case wireErrMsg:
		if !m.quitting {
			m.errorText = "Backend disconnected: " + msg.err.Error()
			m.fatalError = fmt.Errorf("backend disconnected: %w", msg.err)
		}
		return m, tea.Quit
	case wireMsg:
		envelope := protocol.Envelope(msg)
		if envelope.Version != protocol.Version {
			m.errorText = fmt.Sprintf("Protocol mismatch: backend=%d client=%d", envelope.Version, protocol.Version)
			m.fatalError = fmt.Errorf("protocol mismatch: backend=%d client=%d", envelope.Version, protocol.Version)
			return m, tea.Quit
		}
		if cmd := m.handleEnvelope(envelope); cmd != nil {
			cmds = append(cmds, cmd)
		}
		cmds = append(cmds, readWire(m.client))
	case sentMsg:
		if msg.err != nil {
			m.errorText = msg.err.Error()
			if msg.command == "collection.resync" && msg.collection != "" {
				m.resyncRequested[msg.collection] = false
			}
		} else if msg.command == "collection.resync" && msg.requestID != "" && msg.collection != "" {
			m.resyncRequests[msg.requestID] = msg.collection
		}
	case vulnerabilityCopiedMsg:
		m.vulnerabilityCopied = msg.err == nil
		m.vulnerabilityCopyError = ""
		if msg.err != nil {
			m.vulnerabilityCopyError = msg.err.Error()
		}
		return m, nil
	case tea.KeyMsg:
		if m.showSplash {
			return m, nil
		}
		if m.picker != pickerNone {
			return m.updatePicker(msg)
		}
		if m.modal != modalNone {
			return m.updateModal(msg)
		}
		return m.updateMain(msg)
	case tea.MouseMsg:
		if m.showSplash || !m.ready {
			return m, nil
		}
		return m.updateMouse(msg)
	}
	var cmd tea.Cmd
	if m.picker != pickerNone {
		m.pickerInput, cmd = m.pickerInput.Update(msg)
	} else if m.modal == modalNone {
		m.input, cmd = m.input.Update(msg)
	}
	cmds = append(cmds, cmd)
	return m, tea.Batch(cmds...)
}

func (m Model) FatalError() error { return m.fatalError }

func (m Model) updateMain(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "f1":
		m.openModal(modalHelp)
		return m, nil
	case "ctrl+c", "ctrl+q":
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
		if m.focus == focusInput {
			matches := m.matchingSetupCommands()
			if len(matches) > 0 {
				delta := 1
				if key.String() == "up" {
					delta = -1
				}
				m.commandCursor = clampCycle(m.commandCursor+delta, len(matches))
				return m, nil
			}
		}
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
			if matches := m.matchingSetupCommands(); len(matches) > 0 {
				selection := min(m.commandCursor, len(matches)-1)
				value = strings.Fields(matches[selection][0])[0]
			}
			m.input.SetValue("")
			m.commandCursor = 0
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
	oldValue := m.input.Value()
	m.input, cmd = m.input.Update(key)
	// A changed query starts selection at the best (top) match. Slash-command
	// recommendations occupy space above the input, so resize while typing.
	if m.input.Value() != oldValue {
		m.commandCursor = 0
	}
	m.resizeViewport()
	return m, cmd
}

// updateMouse routes wheel and click events to the pane under the pointer.
func (m Model) updateMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	if m.picker != pickerNone {
		return m.updatePickerMouse(msg)
	}
	if m.modal != modalNone {
		return m.updateModalMouse(msg)
	}
	if m.snapshot.SetupMode {
		return m.updateSetupMouse(msg)
	}
	showSidebar, _, chatWidth, chatHeight := m.layout()
	viewerHeight := m.viewerHeight()
	_, vulnHeight, agentHeight := m.sidebarHeights()
	x, y := msg.X, msg.Y
	if m.updateMainScrollbarMouse(
		msg, showSidebar, chatWidth, chatHeight, viewerHeight, agentHeight, vulnHeight,
	) {
		return m, nil
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
				m.vulnOffset = min(max(0, len(m.snapshot.Vulnerabilities)-1), m.vulnOffset+3)
				m.keepVulnerabilitySelectionInWindow()
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
	inputTop := chatHeight + statusH + m.commandMenuHeight()
	// Chat column: chat box on top, input box below the (optional) status row.
	if x < chatWidth {
		switch {
		case y >= inputTop:
			m.focus = focusInput
			m.input.Focus()
		case y < chatHeight:
			m.focus = focusChat
			m.input.Blur()
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
	chatWidth, chatHeight, viewerHeight, agentHeight, vulnHeight int,
) bool {
	if msg.Action == tea.MouseActionRelease {
		if m.draggingScrollbar == scrollbarNone {
			return false
		}
		m.draggingScrollbar = scrollbarNone
		return true
	}
	if msg.Action == tea.MouseActionMotion && m.draggingScrollbar != scrollbarNone {
		m.scrollFromMouse(m.draggingScrollbar, msg.Y, chatHeight, viewerHeight, agentHeight)
		return true
	}
	if msg.Action != tea.MouseActionPress || msg.Button != tea.MouseButtonLeft {
		return false
	}

	target := scrollbarNone
	switch {
	case msg.X == chatWidth-2 && msg.Y >= 1 && msg.Y < chatHeight-1 &&
		m.viewport.TotalLineCount() > m.viewport.VisibleLineCount():
		target = scrollbarTrace
	case showSidebar && msg.X == m.width-3 && msg.Y >= viewerHeight+2 &&
		msg.Y < viewerHeight+agentHeight-2 &&
		len(agentTreeEntries(m.snapshot.Agents, m.collapsedAgents)) > m.agentPageSize():
		target = scrollbarAgents
	case showSidebar && vulnHeight > 0 && msg.X == m.width-3 &&
		msg.Y >= viewerHeight+agentHeight+1 &&
		msg.Y < viewerHeight+agentHeight+vulnHeight-1:
		totalRows, _ := m.vulnerabilityScrollRows()
		if totalRows > m.vulnerabilityPageSize() {
			target = scrollbarFindings
		}
	}
	if target == scrollbarNone {
		return false
	}
	m.draggingScrollbar = target
	m.scrollFromMouse(target, msg.Y, chatHeight, viewerHeight, agentHeight)
	return true
}

func (m *Model) scrollFromMouse(
	target scrollbarTarget,
	y, chatHeight, viewerHeight, agentHeight int,
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
		rowOffset := scrollbarOffset(y-viewerHeight-agentHeight-1, height, totalRows, height)
		m.focus = focusVulnerabilities
		m.input.Blur()
		m.vulnOffset = m.vulnerabilityOffsetAtRow(rowOffset)
		m.keepVulnerabilitySelectionInWindow()
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

// updatePickerMouse keeps all pointer events inside the active picker. Clicking
// an option selects it, while the wheel moves the highlighted option.
func (m Model) updatePickerMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	if m.picker == pickerManualModel || m.picker == pickerAPIKey || m.picker == pickerCustomName || m.picker == pickerCustomURL || m.picker == pickerCustomAPIKey {
		return m, nil
	}
	switch msg.Button {
	case tea.MouseButtonWheelUp:
		if m.cursor > 0 {
			m.cursor--
		}
		return m, nil
	case tea.MouseButtonWheelDown:
		if m.cursor+1 < len(m.filtered) {
			m.cursor++
		}
		return m, nil
	}
	if msg.Action != tea.MouseActionPress || msg.Button != tea.MouseButtonLeft {
		return m, nil
	}

	view := m.pickerView()
	left, top, width, height := m.centeredViewBounds(view)
	if msg.X < left || msg.X >= left+width || msg.Y < top || msg.Y >= top+height {
		return m, nil
	}
	// Provider/model dialogs have one border row, one padding row, the title,
	// a blank line, the three-row search box, and a blank line before options.
	const firstOptionRow = 8
	start, end := optionWindow(m.cursor, len(m.filtered), 18)
	index := start + msg.Y - top - firstOptionRow
	if index < start || index >= end {
		return m, nil
	}
	m.cursor = index
	if m.picker == pickerProvider && m.providerDisconnectable[m.filtered[index]] {
		lines := strings.Split(view, "\n")
		row := msg.Y - top
		if row >= 0 && row < len(lines) {
			plain := ansi.Strip(lines[row])
			if button := strings.Index(plain, "[disconnect]"); button >= 0 {
				start := ansi.StringWidth(plain[:button])
				end := start + len("[disconnect]")
				x := msg.X - left
				if x >= start && x < end {
					return m, send(m.client, "setup.disconnect_provider", map[string]any{"provider": m.filtered[index]})
				}
			}
		}
	}
	return m.selectPickerOption(index)
}

// updateModalMouse captures pointer input while a modal is open and activates
// the same confirmation actions as Enter. Non-interactive modal areas consume
// the event without affecting the screen behind them.
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
	case modalVulnerability:
		if m.centeredLabelHit(view, "Copy", msg.X, msg.Y) {
			m.modalChoice = 0
			cmd := m.startVulnerabilityCopy()
			return m, cmd
		}
		if m.centeredLabelHit(view, "Done", msg.X, msg.Y) {
			m.modalChoice = 1
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
	for row, line := range strings.Split(view, "\n") {
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
		case "left", "right", "tab", "shift+tab":
			m.modalChoice = 1 - m.modalChoice
		case "enter":
			if m.modalChoice == 0 {
				cmd := m.startVulnerabilityCopy()
				return m, cmd
			}
			m.closeModal()
		case "c":
			m.modalChoice = 0
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
		m.closeModal()
		return m, nil
	case "left", "right", "up", "down", "tab":
		m.modalChoice = 1 - m.modalChoice
		return m, nil
	case "enter":
		modal, choice := m.modal, m.modalChoice
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
	if mode == modalVulnerability {
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

func (m *Model) handleEnvelope(envelope protocol.Envelope) tea.Cmd {
	switch envelope.Type {
	case "state":
		var update protocol.StateUpdate
		if err := json.Unmarshal(envelope.Payload, &update); err != nil {
			m.errorText = err.Error()
			return nil
		}
		if update.Revision <= m.stateRevision {
			return nil
		}
		selectedAgentID := ""
		if m.selectedAgent >= 0 && m.selectedAgent < len(m.snapshot.Agents) {
			selectedAgentID = m.snapshot.Agents[m.selectedAgent].ID
		}
		update.State.Events = m.snapshot.Events
		update.State.Vulnerabilities = m.snapshot.Vulnerabilities
		update.State.Agents = m.snapshot.Agents
		m.consumeMessages(update.State.Messages, update.State.SetupMode)
		wasSetup := m.snapshot.SetupMode
		m.snapshot = update.State
		m.stateRevision = update.Revision
		if m.snapshot.Error != nil {
			m.errorText = *m.snapshot.Error
		}
		if m.snapshot.SetupMode {
			m.input.Placeholder = "Type / to configure your scan"
		} else {
			if wasSetup && m.picker != pickerNone {
				m.closePicker()
			}
			m.input.Placeholder = "Send a message"
		}
		m.selectedAgent = selectedAgentIndex(m.snapshot.Agents, selectedAgentID)
		m.selectedVuln = min(m.selectedVuln, max(0, len(m.snapshot.Vulnerabilities)-1))
		if m.modal == modalStop && !m.selectedAgentCanStop() {
			m.closeModal()
		}
		m.ensureAgentVisible()
		m.ensureVulnerabilityVisible()
		m.ready = true
		// resize (not just refresh): status-row visibility changes the chat height.
		m.resizeViewport()
		m.resizeVulnerabilityViewport()
	case "collection_bootstrap":
		return m.handleCollectionBootstrap(envelope.Payload)
	case "collection_delta":
		return m.handleCollectionDelta(envelope.Payload)
	case "command_result":
		if m.client == nil {
			return nil
		}
		expectedCommand, pending := m.client.ExpectedCommand(envelope.RequestID)
		if !pending {
			return nil
		}
		var result protocol.CommandResult
		if err := json.Unmarshal(envelope.Payload, &result); err != nil {
			m.errorText = err.Error()
			return nil
		}
		if result.Command != expectedCommand || !m.client.Resolve(envelope.RequestID, result.Command) {
			return nil
		}
		if !result.OK {
			if result.Command == "models.list" {
				m.modelListing = nil
			}
			if result.Command == "collection.resync" {
				if collection := m.resyncRequests[envelope.RequestID]; collection != "" {
					m.resyncRequested[collection] = false
					delete(m.resyncRequests, envelope.RequestID)
				}
			}
			message := "Command failed"
			if result.Error != nil && strings.TrimSpace(result.Error.Message) != "" {
				message = result.Error.Message
			}
			// Setup-mode errors live in the scrollback (red), like Python; during
			// a scan they surface on the status line.
			if m.snapshot.SetupMode {
				m.setupMsg(message, render.Col(red))
			} else {
				m.errorText = message
			}
			return nil
		}
		if m.snapshot.ScanStarted && !m.snapshot.SetupMode && (strings.HasPrefix(result.Command, "setup.") || result.Command == "providers.list" || result.Command == "models.list") {
			return nil
		}
		m.errorText = ""
		switch result.Command {
		case "providers.list":
			var data protocol.ProvidersResult
			_ = json.Unmarshal(result.Result, &data)
			m.options = m.options[:0]
			m.providerConfigured = map[string]bool{}
			m.providerLabels = map[string]string{}
			m.providerStates = map[string]string{}
			m.providerDetails = map[string]string{}
			m.providerDisconnectable = map[string]bool{}
			for _, p := range data.Providers {
				m.options = append(m.options, p.Name)
				m.providerConfigured[p.Name] = p.Configured
				m.providerLabels[p.Name] = p.Label
				m.providerStates[p.Name] = p.State
				m.providerDetails[p.Name] = p.Detail
				m.providerDisconnectable[p.Name] = p.Disconnectable
			}
			m.openPicker(pickerProvider)
		case "models.list":
			var data protocol.ModelsResult
			if err := json.Unmarshal(result.Result, &data); err != nil {
				m.setupMsg(err.Error(), render.Col(red))
				m.modelListing = nil
				return nil
			}
			return m.handleModelListingPage(data)
		case "setup.select_provider":
			var data struct {
				Provider       string  `json:"provider"`
				Label          string  `json:"label"`
				Configured     bool    `json:"configured"`
				KeyEnv         *string `json:"key_env"`
				State          string  `json:"state"`
				Detail         string  `json:"detail"`
				Disconnectable bool    `json:"disconnectable"`
			}
			_ = json.Unmarshal(result.Result, &data)
			if data.Provider != "" {
				m.configProvider = data.Provider
			}
			if data.Label != "" {
				m.configProviderLabel = data.Label
			}
			m.configProviderState, m.configProviderDetail = data.State, data.Detail
			m.providerConfigured[data.Provider] = data.Configured
			m.providerLabels[data.Provider] = data.Label
			m.providerStates[data.Provider] = data.State
			m.providerDetails[data.Provider] = data.Detail
			m.providerDisconnectable[data.Provider] = data.Disconnectable
			if data.Configured {
				m.setupMsg("✓ "+m.providerStatusText(m.configProvider, m.configProviderLabel, m.configProviderDetail)+" Use /model to pick a model.", render.Col(green))
			} else if data.KeyEnv != nil {
				m.keyEnv = *data.KeyEnv
				m.openPicker(pickerAPIKey)
			} else {
				m.setupMsg(m.providerStatusText(m.configProvider, m.configProviderLabel, m.configProviderDetail), render.Col(red))
			}
		case "setup.save_api_key":
			var data struct {
				Provider       string `json:"provider"`
				Label          string `json:"label"`
				Configured     bool   `json:"configured"`
				State          string `json:"state"`
				Detail         string `json:"detail"`
				Disconnectable bool   `json:"disconnectable"`
			}
			_ = json.Unmarshal(result.Result, &data)
			if data.Provider != "" {
				m.configProvider = data.Provider
			}
			if data.Label != "" {
				m.configProviderLabel = data.Label
			}
			m.configProviderState, m.configProviderDetail = data.State, data.Detail
			m.providerConfigured[data.Provider] = data.Configured
			m.providerLabels[data.Provider] = data.Label
			m.providerStates[data.Provider] = data.State
			m.providerDetails[data.Provider] = data.Detail
			m.providerDisconnectable[data.Provider] = data.Disconnectable
			if m.picker == pickerAPIKey {
				m.closePicker()
			}
			if data.Configured {
				m.setupMsg("✓ Saved credentials. "+m.providerStatusText(m.configProvider, m.configProviderLabel, m.configProviderDetail)+" Use /model to pick a model.", render.Col(green))
			} else {
				m.setupMsg("Saved the API key, but more configuration is required. "+m.providerStatusText(m.configProvider, m.configProviderLabel, m.configProviderDetail), render.Col(amber))
			}
		case "setup.disconnect_provider":
			var data protocol.Provider
			_ = json.Unmarshal(result.Result, &data)
			m.providerConfigured[data.Name] = data.Configured
			m.providerStates[data.Name] = data.State
			m.providerDetails[data.Name] = data.Detail
			m.providerDisconnectable[data.Name] = data.Disconnectable
			m.setupMsg("Disconnected "+data.Label+".", render.Col(amber))
		case "setup.add_custom_provider":
			var data struct {
				Provider       string `json:"provider"`
				Label          string `json:"label"`
				State          string `json:"state"`
				Detail         string `json:"detail"`
				Disconnectable bool   `json:"disconnectable"`
			}
			_ = json.Unmarshal(result.Result, &data)
			if m.picker == pickerCustomAPIKey {
				m.closePicker()
			}
			m.customKind, m.customName, m.customURL = "", "", ""
			m.configProvider, m.configProviderLabel = data.Provider, data.Label
			m.configProviderState, m.configProviderDetail = data.State, data.Detail
			m.providerDisconnectable[data.Provider] = data.Disconnectable
			m.setupMsg("✓ Added custom provider. "+m.providerStatusText(data.Provider, data.Label, data.Detail)+" Use /model to pick a model.", render.Col(green))
		case "setup.select_model":
			var data struct {
				Model string `json:"model"`
			}
			_ = json.Unmarshal(result.Result, &data)
			if m.picker == pickerModel || m.picker == pickerManualModel {
				m.closePicker()
			}
			if data.Model != "" {
				m.setupMsg("✓ Model set to "+data.Model+" (saved to your config).", render.Col(green))
			}
		case "setup.set_mode":
			var data struct {
				Mode string `json:"mode"`
			}
			_ = json.Unmarshal(result.Result, &data)
			if data.Mode != "" {
				m.closePicker()
				m.snapshot.ScanMode = data.Mode
				m.setupMsg("✓ Scan mode set to "+data.Mode+".", render.Col(green))
			}
		case "setup.add_mount":
			var data struct {
				Mount string `json:"mount"`
			}
			_ = json.Unmarshal(result.Result, &data)
			if data.Mount != "" {
				m.setupMsg("✓ Added read-only mount: "+data.Mount, render.Col(green))
			}
		case "setup.load_target_list":
			var data struct {
				Path  string `json:"path"`
				Added int    `json:"added"`
				Total int    `json:"total"`
			}
			_ = json.Unmarshal(result.Result, &data)
			m.setupMsg(fmt.Sprintf("✓ Added %d target(s) from %s (%d total).", data.Added, data.Path, data.Total), render.Col(green))
		case "setup.load_instruction_file":
			var data struct {
				Path       string `json:"path"`
				Characters int    `json:"characters"`
			}
			_ = json.Unmarshal(result.Result, &data)
			m.setupMsg(fmt.Sprintf("✓ Loaded %d instruction characters from %s.", data.Characters, data.Path), render.Col(green))
		case "setup.set_budget":
			var data struct {
				Budget *float64 `json:"budget"`
			}
			_ = json.Unmarshal(result.Result, &data)
			m.snapshot.MaxBudgetUSD = data.Budget
			if data.Budget == nil {
				m.setupMsg("Budget limit disabled.", render.Dim())
			} else {
				m.setupMsg(fmt.Sprintf("✓ Budget set to $%.2f.", *data.Budget), render.Col(green))
			}
		case "setup.set_max_turns":
			var data struct {
				Turns int `json:"turns"`
			}
			_ = json.Unmarshal(result.Result, &data)
			m.snapshot.MaxTurns = data.Turns
			m.setupMsg(fmt.Sprintf("✓ Maximum turns set to %d per agent.", data.Turns), render.Col(green))
		case "setup.set_scope":
			var data struct {
				Mode string  `json:"mode"`
				Base *string `json:"base"`
			}
			_ = json.Unmarshal(result.Result, &data)
			m.snapshot.ScopeMode = data.Mode
			m.snapshot.DiffBase = ""
			if data.Base != nil {
				m.snapshot.DiffBase = *data.Base
			}
			message := "✓ Scope mode set to " + data.Mode
			if m.snapshot.DiffBase != "" {
				message += " against " + m.snapshot.DiffBase
			}
			m.setupMsg(message+".", render.Col(green))
		case "viewer.open":
			var data struct {
				Status string  `json:"status"`
				URL    *string `json:"url"`
			}
			_ = json.Unmarshal(result.Result, &data)
			m.snapshot.ViewerStatus = data.Status
			m.snapshot.ViewerURL = data.URL
		}
	}
	return nil
}

func (m *Model) consumeMessages(messages []protocol.Message, setupMode bool) {
	if m.seenMessages == nil {
		m.seenMessages = map[string]bool{}
	}
	for _, message := range messages {
		key := message.ID
		if key == "" {
			key = message.Level + "\x00" + message.Text
		}
		if m.seenMessages[key] {
			continue
		}
		m.seenMessages[key] = true
		if !setupMode || strings.TrimSpace(message.Text) == "" {
			continue
		}
		style := render.Dim()
		switch message.Level {
		case "error":
			style = render.Col(red)
		case "warning":
			style = render.Col(amber)
		}
		m.setupMsg(message.Text, style)
	}
}

func (m *Model) handleModelListingPage(data protocol.ModelsResult) tea.Cmd {
	if data.ListingID == "" || data.Cursor < 0 || data.NextCursor != data.Cursor+1 {
		m.modelListing = nil
		m.setupMsg("Invalid paged model listing received from backend.", render.Col(red))
		return nil
	}
	if data.Cursor == 0 {
		m.modelListing = &modelListingAssembly{
			listingID: data.ListingID, groupIndexes: map[string]int{}, providerNames: map[string]bool{},
		}
	}
	listing := m.modelListing
	if listing == nil || listing.listingID != data.ListingID || listing.cursor != data.Cursor {
		m.modelListing = nil
		m.setupMsg("Model listing page mismatch; run /model again.", render.Col(red))
		return nil
	}
	for _, group := range data.Groups {
		if index, exists := listing.groupIndexes[group.Provider]; exists {
			listing.groups[index].Models = append(listing.groups[index].Models, group.Models...)
			listing.groups[index].AllowManual = listing.groups[index].AllowManual || group.AllowManual
			if listing.groups[index].Error == "" {
				listing.groups[index].Error = group.Error
			}
			continue
		}
		listing.groupIndexes[group.Provider] = len(listing.groups)
		listing.groups = append(listing.groups, group)
	}
	for _, provider := range data.Providers {
		if listing.providerNames[provider.Name] {
			continue
		}
		listing.providerNames[provider.Name] = true
		listing.providers = append(listing.providers, provider)
	}
	listing.cursor = data.NextCursor
	if !data.Done {
		return send(m.client, "models.list", map[string]any{
			"listing_id": listing.listingID,
			"cursor":     listing.cursor,
		})
	}
	groups, providers := listing.groups, listing.providers
	m.modelListing = nil
	m.installModelListing(groups, providers)
	return nil
}

func (m *Model) installModelListing(groups []protocol.ModelGroup, providers []protocol.Provider) {
	m.options = m.options[:0]
	m.modelOptions = map[string]modelPickerOption{}
	if len(groups) == 0 && len(providers) > 0 {
		m.providerConfigured = map[string]bool{}
		m.providerLabels = map[string]string{}
		m.providerStates = map[string]string{}
		m.providerDetails = map[string]string{}
		m.providerDisconnectable = map[string]bool{}
		for _, provider := range providers {
			m.options = append(m.options, provider.Name)
			m.providerConfigured[provider.Name] = provider.Configured
			m.providerLabels[provider.Name] = provider.Label
			m.providerStates[provider.Name] = provider.State
			m.providerDetails[provider.Name] = provider.Detail
			m.providerDisconnectable[provider.Name] = provider.Disconnectable
		}
		m.openPicker(pickerProvider)
		return
	}
	for groupIndex, group := range groups {
		label := group.Label
		if label == "" {
			label = group.Provider
		}
		if strings.TrimSpace(group.Error) != "" {
			m.setupMsg(label+": "+strings.TrimSpace(group.Error), render.Col(amber))
		}
		for modelIndex, model := range group.Models {
			token := fmt.Sprintf("model:%d:%d", groupIndex, modelIndex)
			m.options = append(m.options, token)
			m.modelOptions[token] = modelPickerOption{provider: group.Provider, label: label, model: model}
		}
		if group.AllowManual {
			token := fmt.Sprintf("manual:%d", groupIndex)
			m.options = append(m.options, token)
			m.modelOptions[token] = modelPickerOption{provider: group.Provider, label: label, manual: true}
		}
	}
	if len(m.options) == 0 {
		m.setupMsg("No configured providers or models are available. Run /provider to connect one.", render.Dim())
		return
	}
	m.openPicker(pickerModel)
}

func validCollection(name string) bool {
	return name == "agents" || name == "events" || name == "vulnerabilities"
}

func (m *Model) collectionMismatch(name string) tea.Cmd {
	delete(m.collectionAssemblies, name)
	if !validCollection(name) || m.resyncRequested[name] || m.client == nil {
		return nil
	}
	m.resyncRequested[name] = true
	return send(m.client, "collection.resync", map[string]any{"collection": name})
}

func (m *Model) clearCollectionResync(name string) {
	m.resyncRequested[name] = false
	for requestID, collection := range m.resyncRequests {
		if collection == name {
			delete(m.resyncRequests, requestID)
		}
	}
}

func (m *Model) handleCollectionBootstrap(payload json.RawMessage) tea.Cmd {
	var chunk protocol.CollectionBootstrap
	if err := json.Unmarshal(payload, &chunk); err != nil {
		m.errorText = err.Error()
		return nil
	}
	if !validCollection(chunk.Collection) {
		m.errorText = "Unknown collection: " + chunk.Collection
		return nil
	}
	if chunk.Cursor == 0 {
		m.resyncRequested[chunk.Collection] = false
	}
	if chunk.Cursor == 0 {
		if chunk.Revision <= m.collectionRevisions[chunk.Collection] {
			return nil
		}
		m.collectionAssemblies[chunk.Collection] = &collectionAssembly{
			kind: "bootstrap", revision: chunk.Revision, ids: map[string]bool{},
		}
	}
	assembly := m.collectionAssemblies[chunk.Collection]
	if assembly == nil || assembly.kind != "bootstrap" || assembly.revision != chunk.Revision || assembly.cursor != chunk.Cursor {
		return m.collectionMismatch(chunk.Collection)
	}
	if chunk.NextCursor != chunk.Cursor+len(chunk.Items) {
		return m.collectionMismatch(chunk.Collection)
	}
	for _, raw := range chunk.Items {
		if chunk.Collection == "agents" {
			var agent protocol.Agent
			if err := json.Unmarshal(raw, &agent); err != nil || agent.ID == "" {
				return m.collectionMismatch(chunk.Collection)
			}
			if assembly.ids[agent.ID] {
				return m.collectionMismatch(chunk.Collection)
			}
			assembly.ids[agent.ID] = true
			assembly.agents = append(assembly.agents, agent)
		} else if chunk.Collection == "events" {
			var event protocol.Event
			if err := json.Unmarshal(raw, &event); err != nil || event.ID == "" {
				return m.collectionMismatch(chunk.Collection)
			}
			if assembly.ids[event.ID] {
				return m.collectionMismatch(chunk.Collection)
			}
			assembly.ids[event.ID] = true
			assembly.events = append(assembly.events, event)
		} else {
			var finding map[string]any
			if err := json.Unmarshal(raw, &finding); err != nil || collectionItemID(finding) == "" {
				return m.collectionMismatch(chunk.Collection)
			}
			id := collectionItemID(finding)
			if assembly.ids[id] {
				return m.collectionMismatch(chunk.Collection)
			}
			assembly.ids[id] = true
			assembly.findings = append(assembly.findings, finding)
		}
	}
	assembly.cursor = chunk.NextCursor
	if !chunk.Done {
		return nil
	}
	if chunk.Collection == "agents" {
		selectedAgentID := m.selectedAgentID()
		m.snapshot.Agents = assembly.agents
		m.selectedAgent = selectedAgentIndex(m.snapshot.Agents, selectedAgentID)
	} else if chunk.Collection == "events" {
		m.snapshot.Events = assembly.events
	} else {
		m.snapshot.Vulnerabilities = assembly.findings
	}
	m.collectionRevisions[chunk.Collection] = chunk.Revision
	delete(m.collectionAssemblies, chunk.Collection)
	m.clearCollectionResync(chunk.Collection)
	m.refreshAfterCollection(chunk.Collection)
	return nil
}

func (m *Model) handleCollectionDelta(payload json.RawMessage) tea.Cmd {
	var chunk protocol.CollectionDelta
	if err := json.Unmarshal(payload, &chunk); err != nil {
		m.errorText = err.Error()
		return nil
	}
	if !validCollection(chunk.Collection) {
		m.errorText = "Unknown collection: " + chunk.Collection
		return nil
	}
	if chunk.Cursor == 0 {
		if chunk.BaseRevision != m.collectionRevisions[chunk.Collection] || chunk.Revision <= chunk.BaseRevision {
			return m.collectionMismatch(chunk.Collection)
		}
		m.collectionAssemblies[chunk.Collection] = &collectionAssembly{
			kind: "delta", revision: chunk.Revision, baseRevision: chunk.BaseRevision,
		}
	}
	assembly := m.collectionAssemblies[chunk.Collection]
	if assembly == nil || assembly.kind != "delta" || assembly.revision != chunk.Revision ||
		assembly.baseRevision != chunk.BaseRevision || assembly.cursor != chunk.Cursor {
		return m.collectionMismatch(chunk.Collection)
	}
	if chunk.NextCursor != chunk.Cursor+len(chunk.Operations) {
		return m.collectionMismatch(chunk.Collection)
	}
	assembly.operations = append(assembly.operations, chunk.Operations...)
	assembly.cursor = chunk.NextCursor
	if !chunk.Done {
		return nil
	}
	if !m.applyCollectionOperations(chunk.Collection, assembly.operations) {
		return m.collectionMismatch(chunk.Collection)
	}
	m.collectionRevisions[chunk.Collection] = chunk.Revision
	delete(m.collectionAssemblies, chunk.Collection)
	m.clearCollectionResync(chunk.Collection)
	m.refreshAfterCollection(chunk.Collection)
	return nil
}

func (m *Model) applyCollectionOperations(name string, operations []protocol.CollectionOperation) bool {
	seen := make(map[string]bool, len(operations))
	if name == "agents" {
		selectedAgentID := m.selectedAgentID()
		values := append([]protocol.Agent(nil), m.snapshot.Agents...)
		positions := make(map[string]int, len(values))
		for index, agent := range values {
			positions[agent.ID] = index
		}
		for _, operation := range operations {
			if operation.Op == "delete" {
				if operation.ID == "" || seen[operation.ID] {
					return false
				}
				seen[operation.ID] = true
				index, exists := positions[operation.ID]
				if !exists {
					return false
				}
				values = append(values[:index], values[index+1:]...)
				positions = make(map[string]int, len(values))
				for position, value := range values {
					positions[value.ID] = position
				}
				continue
			}
			if operation.Op != "upsert" {
				return false
			}
			var agent protocol.Agent
			if err := json.Unmarshal(operation.Item, &agent); err != nil || agent.ID == "" || seen[agent.ID] {
				return false
			}
			seen[agent.ID] = true
			if index, exists := positions[agent.ID]; exists {
				values[index] = agent
			} else {
				positions[agent.ID] = len(values)
				values = append(values, agent)
			}
		}
		m.snapshot.Agents = values
		m.selectedAgent = selectedAgentIndex(values, selectedAgentID)
		return true
	}
	if name == "events" {
		values := append([]protocol.Event(nil), m.snapshot.Events...)
		positions := make(map[string]int, len(values))
		for index, event := range values {
			positions[event.ID] = index
		}
		for _, operation := range operations {
			if operation.Op == "delete" {
				if operation.ID == "" || seen[operation.ID] {
					return false
				}
				seen[operation.ID] = true
				index, exists := positions[operation.ID]
				if !exists {
					return false
				}
				values = append(values[:index], values[index+1:]...)
				positions = make(map[string]int, len(values))
				for position, value := range values {
					positions[value.ID] = position
				}
				continue
			}
			if operation.Op != "upsert" {
				return false
			}
			var event protocol.Event
			if err := json.Unmarshal(operation.Item, &event); err != nil || event.ID == "" || event.Version < 0 || seen[event.ID] {
				return false
			}
			seen[event.ID] = true
			if index, exists := positions[event.ID]; exists {
				current := values[index]
				if event.Version <= current.Version {
					return false
				}
				values[index] = event
			} else {
				positions[event.ID] = len(values)
				values = append(values, event)
			}
		}
		m.snapshot.Events = values
		return true
	}

	values := append([]map[string]any(nil), m.snapshot.Vulnerabilities...)
	positions := make(map[string]int, len(values))
	for index, finding := range values {
		positions[collectionItemID(finding)] = index
	}
	for _, operation := range operations {
		if operation.Op == "delete" {
			if operation.ID == "" || seen[operation.ID] {
				return false
			}
			seen[operation.ID] = true
			index, exists := positions[operation.ID]
			if !exists {
				return false
			}
			values = append(values[:index], values[index+1:]...)
			positions = make(map[string]int, len(values))
			for position, value := range values {
				positions[collectionItemID(value)] = position
			}
			continue
		}
		if operation.Op != "upsert" {
			return false
		}
		var finding map[string]any
		if err := json.Unmarshal(operation.Item, &finding); err != nil {
			return false
		}
		id := collectionItemID(finding)
		if id == "" {
			return false
		}
		if seen[id] {
			return false
		}
		seen[id] = true
		if index, exists := positions[id]; exists {
			values[index] = finding
		} else {
			positions[id] = len(values)
			values = append(values, finding)
		}
	}
	m.snapshot.Vulnerabilities = values
	return true
}

func collectionItemID(item map[string]any) string {
	id, _ := item["id"].(string)
	return id
}

func (m *Model) refreshAfterCollection(name string) {
	if name == "agents" {
		m.ensureAgentVisible()
		m.refreshViewport()
		return
	}
	if name == "events" {
		m.refreshViewport()
		return
	}
	m.selectedVuln = min(m.selectedVuln, max(0, len(m.snapshot.Vulnerabilities)-1))
	m.ensureVulnerabilityVisible()
	m.resizeVulnerabilityViewport()
}

func (m *Model) openPicker(mode pickerMode) {
	m.picker, m.cursor = mode, 0
	m.input.Blur()
	m.pickerInput.SetValue("")
	m.pickerInput.Focus()
	if mode == pickerAPIKey || mode == pickerCustomAPIKey {
		m.pickerInput.EchoMode = textinput.EchoPassword
	} else {
		m.pickerInput.EchoMode = textinput.EchoNormal
	}
	m.filterOptions()
}

func (m *Model) closePicker() {
	m.picker = pickerNone
	m.pickerInput.EchoMode = textinput.EchoNormal
	m.pickerInput.SetValue("")
	m.pickerInput.Blur()
	if m.focus == focusInput {
		m.input.Focus()
	}
}

// pickerPlaceholder returns the search/entry placeholder for the current picker.
func (m Model) pickerPlaceholder() string {
	switch m.picker {
	case pickerModel:
		return "Search models..."
	case pickerManualModel:
		return "Enter model ID..."
	case pickerScanMode:
		return "Search scan modes..."
	case pickerAPIKey:
		return m.keyEnv
	case pickerCustomName:
		return "My local provider"
	case pickerCustomURL:
		return "http://localhost:8000/v1"
	case pickerCustomAPIKey:
		return "Optional — press Enter to skip"
	}
	return "Search providers..."
}

// providerOptionLabel uses the backend's auth state and detail verbatim.
func (m Model) providerOptionLabel(name string) string {
	label := m.providerLabels[name]
	if label == "" {
		label = name
	}
	if name == "__add_custom__" {
		return label
	}
	mark := map[string]string{
		"configured":  "●",
		"missing":     "○",
		"invalid":     "!",
		"external":    "◇",
		"local":       "◇",
		"unavailable": "○",
		"unsupported": "x",
	}[m.providerStates[name]]
	if mark == "" {
		if m.providerConfigured[name] {
			mark = "●"
		} else {
			mark = "○"
		}
	}
	detail := strings.TrimSpace(m.providerDetails[name])
	if detail != "" {
		return mark + " " + label + "  (" + detail + ")"
	}
	return mark + " " + label
}

func (m Model) providerRowLabel(name string, width int) string {
	label := m.providerOptionLabel(name)
	if !m.providerDisconnectable[name] {
		return truncate(label, width)
	}
	const button = "[disconnect]"
	label = truncate(label, max(1, width-len(button)-1))
	gap := max(1, width-ansi.StringWidth(label)-len(button))
	return label + strings.Repeat(" ", gap) + button
}

func (m Model) providerStatusText(provider, label, detail string) string {
	if label == "" {
		label = provider
	}
	if strings.TrimSpace(detail) != "" {
		return providerStatusSentence(label + ": " + strings.TrimSpace(detail))
	}
	state := m.providerStates[provider]
	if provider == m.configProvider && m.configProviderState != "" {
		state = m.configProviderState
	}
	if state != "" {
		return providerStatusSentence(label + ": " + state)
	}
	return label + "."
}

func providerStatusSentence(value string) string {
	if strings.HasSuffix(value, ".") || strings.HasSuffix(value, "!") || strings.HasSuffix(value, "?") {
		return value
	}
	return value + "."
}

func (m Model) modelOptionLabel(token string) string {
	option, ok := m.modelOptions[token]
	if !ok {
		return token
	}
	marker := "  "
	if !option.manual && option.model == m.snapshot.Model {
		marker = "→ "
	}
	if option.manual {
		return marker + option.label + "  Enter model ID..."
	}
	return marker + option.label + "  " + option.model
}

func (m Model) updatePicker(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "esc":
		if m.picker == pickerAPIKey && m.configProvider != "" {
			m.setupMsg(m.providerStatusText(m.configProvider, m.configProviderLabel, m.configProviderDetail), render.Col(red))
		}
		m.closePicker()
		return m, nil
	case "up", "ctrl+k":
		if m.cursor > 0 {
			m.cursor--
		}
		return m, nil
	case "down", "ctrl+j":
		if m.cursor+1 < len(m.filtered) {
			m.cursor++
		}
		return m, nil
	case "ctrl+d":
		if m.picker == pickerProvider && len(m.filtered) > 0 {
			provider := m.filtered[m.cursor]
			if m.providerDisconnectable[provider] {
				return m, send(m.client, "setup.disconnect_provider", map[string]any{"provider": provider})
			}
		}
		return m, nil
	case "enter":
		if m.picker == pickerManualModel {
			value := strings.TrimSpace(m.pickerInput.Value())
			prefix := m.manualModelProvider + "/"
			for strings.HasPrefix(value, prefix) {
				value = strings.TrimPrefix(value, prefix)
			}
			if value == "" {
				return m, nil
			}
			return m, send(m.client, "setup.select_model", map[string]any{"provider": m.manualModelProvider, "model": prefix + value})
		}
		if m.picker == pickerAPIKey {
			value := strings.TrimSpace(m.pickerInput.Value())
			m.pickerInput.SetValue("")
			if value == "" {
				return m, nil
			}
			return m, send(m.client, "setup.save_api_key", map[string]any{"provider": m.configProvider, "api_key": value})
		}
		if m.picker == pickerCustomName {
			value := strings.TrimSpace(m.pickerInput.Value())
			if value == "" {
				return m, nil
			}
			m.customName = value
			m.openPicker(pickerCustomURL)
			return m, nil
		}
		if m.picker == pickerCustomURL {
			value := strings.TrimSpace(m.pickerInput.Value())
			if value == "" {
				return m, nil
			}
			m.customURL = value
			m.openPicker(pickerCustomAPIKey)
			return m, nil
		}
		if m.picker == pickerCustomAPIKey {
			value := strings.TrimSpace(m.pickerInput.Value())
			m.pickerInput.SetValue("")
			return m, send(m.client, "setup.add_custom_provider", map[string]any{
				"name": m.customName, "api_base": m.customURL, "api_key": value, "kind": m.customKind,
			})
		}
		if len(m.filtered) == 0 {
			return m, nil
		}
		return m.selectPickerOption(m.cursor)
	}
	var cmd tea.Cmd
	m.pickerInput, cmd = m.pickerInput.Update(key)
	m.filterOptions()
	return m, cmd
}

func (m Model) selectPickerOption(index int) (tea.Model, tea.Cmd) {
	if index < 0 || index >= len(m.filtered) {
		return m, nil
	}
	selected, mode := m.filtered[index], m.picker
	if mode == pickerModel {
		option, ok := m.modelOptions[selected]
		if !ok {
			return m, nil
		}
		if option.manual {
			m.manualModelProvider, m.manualModelLabel = option.provider, option.label
			m.openPicker(pickerManualModel)
			return m, nil
		}
		return m, send(m.client, "setup.select_model", map[string]any{"provider": option.provider, "model": option.model})
	}
	m.closePicker()
	if mode == pickerScanMode {
		return m, send(m.client, "setup.set_mode", map[string]any{"mode": selected})
	}
	if mode == pickerCustomKind {
		switch selected {
		case "llama.cpp":
			m.customKind = "llama_cpp"
		case "vLLM":
			m.customKind = "vllm"
		default:
			m.customKind = "openai"
		}
		m.openPicker(pickerCustomName)
		return m, nil
	}
	if selected == "__add_custom__" {
		m.customKind, m.customName, m.customURL = "", "", ""
		m.options = []string{"OpenAI-compatible", "llama.cpp", "vLLM"}
		m.openPicker(pickerCustomKind)
		return m, nil
	}
	m.configProvider = selected
	m.configProviderLabel = m.providerLabels[selected]
	m.configProviderState = m.providerStates[selected]
	m.configProviderDetail = m.providerDetails[selected]
	return m, send(m.client, "setup.select_provider", map[string]any{"provider": selected})
}

func (m *Model) filterOptions() {
	query := strings.ToLower(strings.TrimSpace(m.pickerInput.Value()))
	m.filtered = m.filtered[:0]
	for _, option := range m.options {
		searchValue := option
		if m.picker == pickerProvider && m.providerLabels[option] != "" {
			searchValue += " " + m.providerLabels[option]
		} else if m.picker == pickerModel {
			row := m.modelOptions[option]
			searchValue = row.label + " " + row.model
			if row.manual {
				searchValue += " Enter model ID"
			}
		}
		if query == "" || strings.Contains(strings.ToLower(searchValue), query) {
			m.filtered = append(m.filtered, option)
		}
	}
	if m.cursor >= len(m.filtered) {
		m.cursor = max(0, len(m.filtered)-1)
	}
}

func (m Model) submit(value string) (tea.Model, tea.Cmd) {
	if m.snapshot.SetupMode {
		return m.submitSetup(value)
	}
	if len(m.snapshot.Agents) == 0 {
		m.errorText = "No agent is available"
		return m, nil
	}
	if m.selectedAgent >= len(m.snapshot.Agents) {
		m.selectedAgent = 0
	}
	return m, send(m.client, "agent.send_message", map[string]any{"agent_id": m.snapshot.Agents[m.selectedAgent].ID, "message": value})
}

// submitSetup handles a setup-mode slash command. Commands themselves are not
// copied into the output pane; only useful results and errors are recorded.
func (m Model) submitSetup(value string) (tea.Model, tea.Cmd) {
	if !strings.HasPrefix(value, "/") {
		m.setupMsg("Commands start with '/'. Type /help to see them.", render.Col(red))
		return m, nil
	}
	parts := strings.SplitN(value, " ", 2)
	command := strings.ToLower(parts[0])
	arg := ""
	if len(parts) == 2 {
		arg = strings.TrimSpace(parts[1])
	}
	switch command {
	case "/help":
		// The live command menu above the input is the command reference.
		return m, nil
	case "/quit", "/exit":
		m.quitting = true
		return m, tea.Batch(send(m.client, "app.quit", map[string]any{}), tea.Quit)
	case "/provider", "/providers", "/connect":
		return m, send(m.client, "providers.list", map[string]any{})
	case "/model", "/models":
		return m, send(m.client, "models.list", map[string]any{})
	case "/mode", "/scan-mode":
		if arg == "" {
			m.options = append([]string(nil), scanModes...)
			m.openPicker(pickerScanMode)
			return m, nil
		}
		return m, send(m.client, "setup.set_mode", map[string]any{"mode": strings.ToLower(arg)})
	case "/budget":
		if arg == "" {
			if m.snapshot.MaxBudgetUSD == nil {
				m.setupMsg("No budget limit is configured.", render.Dim())
			} else {
				m.setupMsg(fmt.Sprintf("Current budget limit: $%.2f.", *m.snapshot.MaxBudgetUSD), render.Dim())
			}
			return m, nil
		}
		if strings.EqualFold(arg, "off") || strings.EqualFold(arg, "none") {
			return m, send(m.client, "setup.set_budget", map[string]any{"budget": nil})
		}
		budget, err := strconv.ParseFloat(arg, 64)
		if err != nil || budget <= 0 || math.IsNaN(budget) || math.IsInf(budget, 0) {
			m.setupMsg("Budget must be a number greater than 0, or 'off'.", render.Col(red))
			return m, nil
		}
		return m, send(m.client, "setup.set_budget", map[string]any{"budget": budget})
	case "/turns", "/max-turns":
		if arg == "" {
			m.setupMsg(fmt.Sprintf("Current maximum turns: %d per agent.", m.snapshot.MaxTurns), render.Dim())
			return m, nil
		}
		turns, err := strconv.Atoi(arg)
		if err != nil || turns <= 0 {
			m.setupMsg("Maximum turns must be an integer greater than 0.", render.Col(red))
			return m, nil
		}
		return m, send(m.client, "setup.set_max_turns", map[string]any{"turns": turns})
	case "/scope", "/scope-mode":
		fields := strings.Fields(arg)
		if len(fields) == 0 {
			message := "Current scope mode: " + m.snapshot.ScopeMode
			if m.snapshot.DiffBase != "" {
				message += " against " + m.snapshot.DiffBase
			}
			m.setupMsg(message+".", render.Dim())
			return m, nil
		}
		mode := strings.ToLower(fields[0])
		if len(fields) > 2 || (mode != "auto" && mode != "diff" && mode != "full") {
			m.setupMsg("Usage: /scope <auto|diff|full> [base|default]", render.Col(red))
			return m, nil
		}
		payload := map[string]any{"mode": mode}
		if len(fields) == 2 {
			if strings.EqualFold(fields[1], "default") {
				payload["base"] = nil
			} else {
				payload["base"] = fields[1]
			}
		} else if mode == "full" {
			payload["base"] = nil
		}
		return m, send(m.client, "setup.set_scope", payload)
	case "/target":
		if arg == "" {
			if len(m.snapshot.Targets) > 0 {
				var b strings.Builder
				b.WriteString(render.Bold(green).Render("Targets"))
				for _, t := range m.snapshot.Targets {
					b.WriteString("\n" + render.Col(white).Render("  "+t))
				}
				if hidden := m.snapshot.TargetCount - len(m.snapshot.Targets); hidden > 0 {
					b.WriteString(fmt.Sprintf("\n  ...and %d more", hidden))
				}
				m.setupLogAppend(b.String())
			} else {
				m.setupMsg("No targets yet. Add one with /target <url|repo|path|domain|ip>", render.Dim())
			}
			return m, nil
		}
		for _, t := range m.snapshot.Targets {
			if t == arg {
				m.setupMsg("'"+arg+"' is already in the target list.", render.Dim())
				return m, nil
			}
		}
		m.setupMsg("✓ Added target: "+arg, render.Col(green))
		return m, send(m.client, "setup.add_target", map[string]any{"target": arg})
	case "/mount":
		if arg == "" {
			if len(m.snapshot.Mounts) == 0 {
				m.setupMsg("No read-only mounts configured. Add one with /mount <path>.", render.Dim())
			} else {
				message := "Read-only mounts:\n  " + strings.Join(m.snapshot.Mounts, "\n  ")
				if hidden := m.snapshot.MountCount - len(m.snapshot.Mounts); hidden > 0 {
					message += fmt.Sprintf("\n  ...and %d more", hidden)
				}
				m.setupMsg(message, render.Dim())
			}
			return m, nil
		}
		return m, send(m.client, "setup.add_mount", map[string]any{"path": arg})
	case "/target-list":
		if arg == "" {
			m.setupMsg("Usage: /target-list <path>", render.Col(red))
			return m, nil
		}
		return m, send(m.client, "setup.load_target_list", map[string]any{"path": arg})
	case "/prompt", "/instruction":
		if arg != "" {
			m.setupMsg("✓ Prompt set.", render.Col(green))
		} else {
			m.setupMsg("Prompt cleared.", render.Dim())
		}
		return m, send(m.client, "setup.set_instruction", map[string]any{"instruction": arg})
	case "/prompt-file", "/instruction-file":
		if arg == "" {
			m.setupMsg("Usage: /prompt-file <path>", render.Col(red))
			return m, nil
		}
		return m, send(m.client, "setup.load_instruction_file", map[string]any{"path": arg})
	case "/clear":
		m.setupMsg("Cleared all targets.", render.Dim())
		return m, send(m.client, "setup.clear_targets", map[string]any{})
	case "/start", "/run":
		m.setupMsg("Verifying model connection...", render.Col(amber))
		return m, send(m.client, "setup.start", map[string]any{})
	default:
		m.setupMsg("Unknown command '"+command+"'. Type /help.", render.Col(red))
		return m, nil
	}
}

// matchingSetupCommands returns live recommendations for the slash command
// currently being typed. A bare slash shows every command; subsequent command
// characters narrow the list. Arguments do not hide the selected command.
func (m Model) matchingSetupCommands() [][2]string {
	if !m.snapshot.SetupMode || m.focus != focusInput {
		return nil
	}
	rawValue := m.input.Value()
	value := strings.ToLower(strings.TrimSpace(rawValue))
	// A space means a command has been completed and its arguments are being
	// entered. Hide recommendations so Enter submits it normally.
	if !strings.HasPrefix(value, "/") || strings.ContainsAny(rawValue, " \t\n") {
		return nil
	}
	query := value
	matches := make([][2]string, 0, len(setupCommands))
	for _, command := range setupCommands {
		name := strings.Fields(command[0])[0]
		if strings.HasPrefix(name, query) {
			matches = append(matches, command)
		}
	}
	return matches
}

func (m Model) commandMenuHeight() int { return len(m.matchingSetupCommands()) }

func (m Model) commandMenuView(width int) string {
	matches := m.matchingSetupCommands()
	if len(matches) == 0 {
		return ""
	}
	return m.commandMenuViewLimit(width, len(matches))
}

func (m Model) commandMenuViewLimit(width, limit int) string {
	matches := m.matchingSetupCommands()
	if len(matches) == 0 || limit <= 0 {
		return ""
	}
	start, end := optionWindow(m.commandCursor, len(matches), limit)
	lines := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		command := matches[i]
		prefix := "  "
		commandStyle := render.Col(render.InfoBlue)
		descriptionStyle := render.Dim()
		if i == m.commandCursor {
			prefix = "› "
			commandStyle = lipgloss.NewStyle().Bold(true).Foreground(brightGreen)
			descriptionStyle = lipgloss.NewStyle().Foreground(mid)
		}
		line := commandStyle.Render(fmt.Sprintf("%s%-18s", prefix, command[0])) + descriptionStyle.Render(command[1])
		lines = append(lines, padToWidth(ansi.Truncate(line, max(1, width), ""), width))
	}
	return strings.Join(lines, "\n")
}

// statusVisible mirrors #agent_status_display: shown only when an agent is
// selected during a scan; hidden (display:none) in setup mode.
func (m Model) statusVisible() bool {
	return !m.snapshot.SetupMode && len(m.snapshot.Agents) > 0
}

// layout returns the shared geometry used by both the viewport sizing and the
// rendered chat box. The chat box, optional status row and 3-row input stack
// inside the chat column; the sidebar spans the full screen height alongside
// them, matching the Textual container tree.
func (m Model) layout() (showSidebar bool, sidebarWidth, chatWidth, chatHeight int) {
	showSidebar = m.width >= 120
	if showSidebar {
		sidebarWidth = max(24, m.width/5)
		chatWidth = m.width - sidebarWidth - 1
	} else {
		chatWidth = m.width
	}
	statusH := 0
	if m.statusVisible() {
		statusH = 1
	}
	chatHeight = max(4, m.height-statusH-3-m.commandMenuHeight())
	return
}

func (m *Model) resizeViewport() {
	if m.snapshot.SetupMode {
		contentWidth, historyHeight := m.setupLayout()
		m.input.Width = max(1, contentWidth-5)
		m.viewport.Width = max(10, contentWidth)
		m.viewport.Height = max(1, historyHeight)
		m.refreshViewport()
		return
	}
	_, _, chatWidth, chatHeight := m.layout()
	m.input.Width = max(1, chatWidth-5)
	// Reserve two columns inside the border for the scrollbar gap and track.
	m.viewport.Width = max(10, chatWidth-4)
	m.viewport.Height = max(3, chatHeight-2)
	m.refreshViewport()
}

func (m *Model) refreshViewport() {
	wasBottom := m.viewport.AtBottom()
	content := m.setupContent()
	if !m.snapshot.SetupMode {
		content = m.chatContent()
	}
	m.viewportContent = content
	m.viewport.SetContent(content)
	if m.followOutput && wasBottom {
		m.viewport.GotoBottom()
	}
}

// setupCommands mirrors _SETUP_COMMANDS: the ordered command list shown in the
// setup intro and by /help.
var setupCommands = [][2]string{
	{"/provider", "Configure or connect an LLM provider"},
	{"/model", "Search + select a model across configured providers (saved)"},
	{"/mode [quick|standard|deep]", "Set scan depth (default: deep)"},
	{"/budget <USD|off>", "Set or disable the scan cost limit"},
	{"/turns <N>", "Set maximum turns per agent"},
	{"/scope <auto|diff|full> [base]", "Set code scope and optional diff base"},
	{"/target <value>", "Add a target: URL, repo, path, domain, or IP"},
	{"/mount <path>", "Add a read-only local directory mount"},
	{"/target-list <path>", "Load targets from a file"},
	{"/prompt <text>", "Set an optional instruction for the scan"},
	{"/prompt-file <path>", "Load scan instructions from a file"},
	{"/clear", "Remove all targets"},
	{"/start", "Launch the scan"},
	{"/help", "Show this command list"},
	{"/quit", "Exit without scanning"},
}

var scanModes = []string{"quick", "standard", "deep"}

func (m Model) setupContent() string {
	if len(m.setupLog) == 0 {
		return render.Dim().Render("Type / to see setup commands.")
	}
	var b strings.Builder
	for _, line := range m.setupLog {
		b.WriteString(line + "\n")
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// setupLogAppend records a chronological line in the setup scrollback.
func (m *Model) setupLogAppend(line string) { m.setupLog = append(m.setupLog, line) }

// setupMsg appends a styled feedback line (success green, error red, notice dim).
func (m *Model) setupMsg(text string, style lipgloss.Style) {
	m.setupLogAppend(style.Render(text))
}

func (m Model) chatContent() string {
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
	for _, event := range events {
		if event.AgentID != agentID {
			continue
		}
		var block string
		if event.Type == "chat" {
			block = render.Chat(event.Data)
		} else if event.Type == "tool" {
			block = render.Tool(event.Data)
		}
		if block == "" {
			continue
		}
		blocks = append(blocks, wrapBlock(block, contentWidth))
	}
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
		return m.overlay(main, m.pickerView(), false)
	}
	if m.modal != modalNone {
		// Only the vulnerability detail dims its backdrop (#000000 80%); Help,
		// Quit and Stop are transparent.
		return m.overlay(main, m.modalView(), m.modal == modalVulnerability)
	}
	return main
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

func (m Model) setupLayout() (contentWidth, historyHeight int) {
	contentWidth, historyHeight, _, _ = m.setupGeometry()
	return
}

func (m Model) setupGeometry() (contentWidth, historyHeight, menuRows int, showSummary bool) {
	contentWidth = min(88, max(20, m.width-4))
	headerHeight := strings.Count(m.setupHeaderView(contentWidth), "\n") + 1
	menuRows = m.commandMenuHeight()
	showSummary = m.height >= 22 || menuRows == 0
	summaryHeight := 0
	if showSummary {
		summaryHeight = strings.Count(m.setupSummaryView(contentWidth), "\n") + 1
	}
	bodyHeight := min(38, max(1, m.height))
	partCount := 3 // header, feedback viewport, and composer
	if showSummary {
		partCount++
	}
	if menuRows > 0 {
		partCount++
	}
	// Joined sections have one blank line between them; reserve one feedback row.
	fixedWithoutMenu := headerHeight + summaryHeight + 3 + partCount - 1
	menuRows = min(menuRows, max(0, bodyHeight-fixedWithoutMenu-1))
	if menuRows == 0 && m.commandMenuHeight() > 0 {
		partCount--
		fixedWithoutMenu--
	}
	fixedHeight := fixedWithoutMenu + menuRows
	historyHeight = max(1, bodyHeight-fixedHeight)
	return
}

func (m Model) setupHeaderView(width int) string {
	logo := lipgloss.NewStyle().Bold(true).Foreground(green).Render("STRIX")
	if m.height < 22 {
		return lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Render(logo)
	}
	if m.width >= 50 && m.height >= 28 {
		logo = lipgloss.NewStyle().Foreground(green).Render(banner)
	}
	title := lipgloss.NewStyle().Bold(true).Foreground(brightWhite).Render("Configure your pentest")
	subtitle := render.Dim().Render("Choose a model and target, then type /start")
	return lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Render(logo + "\n\n" + title + "\n" + subtitle)
}

func (m Model) setupSummaryView(width int) string {
	valueWidth := max(8, width-12)
	row := func(label, value string, configured bool) string {
		valueStyle := render.Col(white)
		if !configured {
			valueStyle = render.Col(amber)
		}
		return render.Dim().Render(fmt.Sprintf("%-9s", label)) + valueStyle.Render(truncate(value, valueWidth))
	}

	model := strings.TrimSpace(m.snapshot.Model)
	modelSet := model != ""
	if !modelSet {
		model = "Not set"
	}
	targets := "Not set"
	targetsSet := len(m.snapshot.Targets) > 0
	if targetsSet {
		mounts := make(map[string]bool, len(m.snapshot.Mounts))
		for _, mount := range m.snapshot.Mounts {
			mounts[mount] = true
		}
		values := make([]string, 0, len(m.snapshot.Targets))
		for _, target := range m.snapshot.Targets {
			if mounts[target] {
				target += " [mount]"
			}
			values = append(values, target)
		}
		targets = strings.Join(values, ", ")
		if hidden := m.snapshot.TargetCount - len(m.snapshot.Targets); hidden > 0 {
			targets += fmt.Sprintf(", ...and %d more", hidden)
		}
	}
	prompt := strings.TrimSpace(m.snapshot.Instruction)
	promptSet := prompt != ""
	if !promptSet {
		prompt = "Optional"
	}
	mode := strings.TrimSpace(m.snapshot.ScanMode)
	if mode == "" {
		mode = "deep"
	}
	budget := "No limit"
	if m.snapshot.MaxBudgetUSD != nil {
		budget = fmt.Sprintf("$%.2f", *m.snapshot.MaxBudgetUSD)
	}
	turns := strconv.Itoa(m.snapshot.MaxTurns)
	if m.snapshot.MaxTurns <= 0 {
		turns = "500"
	}
	scope := m.snapshot.ScopeMode
	if scope == "" {
		scope = "auto"
	}
	if m.snapshot.DiffBase != "" {
		scope += " @ " + m.snapshot.DiffBase
	}
	return row("model", model, modelSet) + "\n" +
		row("targets", targets, targetsSet) + "\n" +
		row("mode", mode, true) + "\n" +
		row("budget", budget, true) + "\n" +
		row("turns", turns, true) + "\n" +
		row("scope", scope, true) + "\n" +
		row("prompt", prompt, promptSet)
}

func (m Model) setupView() string {
	contentWidth, _, menuRows, showSummary := m.setupGeometry()
	inputBorder := dark
	prompt := render.Col(dim).Render("> ")
	if m.focus == focusInput {
		inputBorder = green
		prompt = render.Bold(green).Render("> ")
	}
	composer := lipgloss.NewStyle().Width(contentWidth - 2).Height(1).
		Border(lipgloss.RoundedBorder()).BorderForeground(inputBorder).PaddingLeft(1).
		Render(prompt + m.input.View())

	parts := []string{m.setupHeaderView(contentWidth)}
	if showSummary {
		parts = append(parts, m.setupSummaryView(contentWidth))
	}
	parts = append(parts, m.viewport.View())
	if menu := m.commandMenuViewLimit(contentWidth, menuRows); menu != "" {
		parts = append(parts, menu)
	}
	parts = append(parts, composer)
	body := strings.Join(parts, "\n\n")
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, body,
		lipgloss.WithWhitespaceBackground(black))
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
		visibleContent(m.viewportContent, m.viewport.YOffset, traceHeight),
		chatWidth-2,
		traceHeight,
		m.viewport.TotalLineCount(),
		m.viewport.VisibleLineCount(),
		m.viewport.YOffset,
	)
	chat := lipgloss.NewStyle().Width(chatWidth - 2).Height(traceHeight).Border(lipgloss.RoundedBorder()).BorderForeground(chatBorder).Render(trace)

	inputBorder := dark
	prompt := lipgloss.NewStyle().Foreground(dim).Render("> ")
	if m.focus == focusInput {
		inputBorder, prompt = green, lipgloss.NewStyle().Bold(true).Foreground(green).Render("> ")
	}
	input := lipgloss.NewStyle().Width(chatWidth - 2).Height(1).Border(lipgloss.RoundedBorder()).BorderForeground(inputBorder).PaddingLeft(1).Render(prompt + m.input.View())

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

type agentTreeEntry struct {
	index  int
	depth  int
	prefix string
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
	// The tree's root ("Agents") is hidden (show_root = False), so no header row
	// is drawn — only the agent nodes.
	var lines []string
	statusIcons := map[string]string{"running": "⚪", "waiting": "⏸", "budget_paused": "⏸", "completed": "🟢", "failed": "🔴", "crashed": "🔴", "stopped": "■"}
	entries := agentTreeEntries(m.snapshot.Agents, m.collapsedAgents)
	start := windowStart(m.agentOffset, len(entries), height)
	end := min(len(entries), start+height)
	for _, entry := range entries[start:end] {
		agent := m.snapshot.Agents[entry.index]
		icon := statusIcons[agent.Status]
		if icon == "" {
			icon = "○"
		}
		vulnSuffix := ""
		if count := m.agentVulnCount(agent.ID); count > 0 {
			vulnSuffix = fmt.Sprintf(" (%d)", count)
		}
		disclosure := "  "
		if hasAgentChildren(agent.ID, m.snapshot.Agents) {
			disclosure = "⏷ "
			if m.collapsedAgents[agent.ID] {
				disclosure = "⏵ "
			}
		}
		label := entry.prefix + disclosure + icon + " " + agent.Name + vulnSuffix
		// Reserve the left border and padding on every row so selection changes
		// only color/weight, never the node's horizontal position.
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("#d6d3d1")).BorderLeft(true).BorderStyle(lipgloss.ThickBorder()).BorderForeground(black).PaddingLeft(1)
		if entry.depth > 0 {
			style = style.Foreground(lipgloss.Color("#a8a29e"))
		}
		if entry.index == m.selectedAgent {
			style = style.Bold(true).Foreground(white).BorderForeground(lipgloss.Color("#d6d3d1"))
		}
		lines = append(lines, style.Render(truncate(label, max(1, width-2))))
	}
	return strings.Join(lines, "\n")
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

func (m *Model) ensureAgentVisible() {
	entries := agentTreeEntries(m.snapshot.Agents, m.collapsedAgents)
	if len(entries) == 0 {
		m.agentOffset = 0
		return
	}
	_, _, agentHeight := m.sidebarHeights()
	rows := max(1, agentHeight-4)
	row := selectedAgentRow(entries, m.selectedAgent)
	if row < m.agentOffset {
		m.agentOffset = row
	} else if row >= m.agentOffset+rows {
		m.agentOffset = row - rows + 1
	}
	m.agentOffset = min(m.agentOffset, max(0, len(entries)-rows))
}

func (m Model) agentPageSize() int {
	_, _, agentHeight := m.sidebarHeights()
	return max(1, agentHeight-4)
}

func (m *Model) keepAgentSelectionInWindow() {
	entries := agentTreeEntries(m.snapshot.Agents, m.collapsedAgents)
	if len(entries) == 0 {
		return
	}
	rows := m.agentPageSize()
	row := selectedAgentRow(entries, m.selectedAgent)
	if row < m.agentOffset {
		m.selectedAgent = entries[m.agentOffset].index
	} else if row >= m.agentOffset+rows {
		m.selectedAgent = entries[min(len(entries)-1, m.agentOffset+rows-1)].index
	}
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
func (m Model) statsView() string {
	w := lipgloss.NewStyle().Foreground(white)
	var b strings.Builder
	if model := m.snapshot.Model; model != "" {
		b.WriteString(w.Render(model))
	}
	total := numberValue(m.snapshot.Usage["total_tokens"])
	if total > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(w.Render(fmt.Sprintf("%s tokens", formatCount(total))))
		if cost := floatValue(m.snapshot.Usage["cost"]); cost > 0 {
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

func (m Model) pickerView() string {
	const interior = 64
	title, subtitle := "Select a provider", ""
	switch m.picker {
	case pickerModel:
		title = "Select a model"
	case pickerManualModel:
		provider := m.manualModelLabel
		if provider == "" {
			provider = m.manualModelProvider
		}
		title, subtitle = "Enter model ID — "+provider, "The provider prefix is added automatically"
	case pickerScanMode:
		title = "Select scan mode"
	case pickerAPIKey:
		provider := m.configProviderLabel
		if provider == "" {
			provider = m.configProvider
		}
		title, subtitle = "API key for "+provider, m.configProviderDetail
		if subtitle == "" {
			subtitle = "Sets " + m.keyEnv
		}
	case pickerCustomKind:
		title, subtitle = "Custom provider compatibility", "Choose the server implementation"
	case pickerCustomName:
		title, subtitle = "Custom provider name", "A label used in the provider list"
	case pickerCustomURL:
		title, subtitle = "Custom provider URL", "Required OpenAI-compatible API base URL"
	case pickerCustomAPIKey:
		title, subtitle = "Custom provider API key", "Optional; press Enter to skip"
	}
	// The picker search box is always focused while open, so its border is green
	// (#picker_search:focus) over the #0a0a0a input background. The placeholder is
	// rendered here rather than on the input model so it never becomes its value.
	inner := m.pickerInput.View()
	if m.pickerInput.Value() == "" {
		inner = lipgloss.NewStyle().Foreground(lipgloss.Color("#525252")).Render(m.pickerPlaceholder())
	}
	search := lipgloss.NewStyle().Width(interior - 2).Border(lipgloss.RoundedBorder()).BorderForeground(green).Background(lipgloss.Color("#0a0a0a")).PaddingLeft(1).Render(inner)

	content := lipgloss.NewStyle().Bold(true).Foreground(green).Render(title)
	if subtitle != "" {
		content += "\n" + lipgloss.NewStyle().Foreground(dim).Render(subtitle)
	}
	content += "\n\n" + search

	if m.picker != pickerManualModel && m.picker != pickerAPIKey && m.picker != pickerCustomName && m.picker != pickerCustomURL && m.picker != pickerCustomAPIKey {
		content += "\n"
		if len(m.filtered) == 0 {
			content += "\n" + lipgloss.NewStyle().Foreground(dim).Render(" No matches")
		} else {
			start, end := optionWindow(m.cursor, len(m.filtered), 18)
			for i := start; i < end; i++ {
				raw := m.filtered[i]
				if m.picker == pickerProvider {
					raw = m.providerRowLabel(raw, interior-2)
				} else if m.picker == pickerModel {
					raw = m.modelOptionLabel(raw)
				}
				label := truncate(raw, interior-2)
				if i == m.cursor {
					label = lipgloss.NewStyle().Background(lipgloss.Color("#15803d")).Foreground(brightWhite).Width(interior).Render(" " + label)
				} else {
					label = " " + label
				}
				content += "\n" + label
			}
		}
	}
	return lipgloss.NewStyle().Width(interior+4).Border(lipgloss.RoundedBorder()).BorderForeground(green).Background(black).Padding(1, 2).Render(content)
}

// optionWindow returns a [start,end) slice that keeps the cursor visible within
// a scrolling window of at most size rows (matching OptionList scroll behavior).
func optionWindow(cursor, length, size int) (int, int) {
	if length <= size {
		return 0, length
	}
	start := cursor - size + 1
	if start < 0 {
		start = 0
	}
	if start > length-size {
		start = length - size
	}
	return start, start + size
}

func (m Model) modalView() string {
	switch m.modal {
	case modalHelp:
		title := lipgloss.NewStyle().Bold(true).Foreground(green).Width(34).Align(lipgloss.Center).Render("Strix Help")
		body := lipgloss.NewStyle().Foreground(textColor).Render("F1        Help\nCtrl+O    Open viewer\nCtrl+Q/C  Quit\nESC       Stop Agent\nEnter     Send / expand node\nTab       Switch panels\n↑/↓       Navigate tree")
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
	case modalVulnerability:
		if len(m.snapshot.Vulnerabilities) == 0 {
			return ""
		}
		return m.vulnerabilityDetail()
	}
	return ""
}

func (m Model) confirmView(title string, width int, border, titleColor lipgloss.Color) string {
	// Yes = error variant (#ef4444), No = default variant (#737373); the focused
	// button fills its background (#ef4444 / #363636) with white text.
	yes := lipgloss.NewStyle().Foreground(red).Bold(true).Render("Yes")
	no := lipgloss.NewStyle().Foreground(dim).Bold(true).Render("No")
	if m.modalChoice == 0 {
		yes = lipgloss.NewStyle().Background(red).Foreground(brightWhite).Bold(true).Render(" Yes ")
	} else {
		no = lipgloss.NewStyle().Background(lipgloss.Color("#363636")).Foreground(brightWhite).Bold(true).Render(" No ")
	}
	content := lipgloss.NewStyle().Bold(true).Foreground(titleColor).Width(width-4).Align(lipgloss.Center).Render(title) +
		"\n\n" + lipgloss.NewStyle().Width(width-4).Align(lipgloss.Center).Render(yes+"     "+no)
	return lipgloss.NewStyle().Width(width).Border(lipgloss.RoundedBorder()).BorderForeground(border).Background(black).Padding(1).Render(content)
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
		b.WriteString("\n\n" + fieldStyle.Render("PoC Code") + "\n" + render.Col(textColor).Render(poc))
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
	report := ansi.Strip(vulnerabilityBody(m.snapshot.Vulnerabilities[m.selectedVuln])) + "\n"
	return func() tea.Msg {
		return vulnerabilityCopiedMsg{err: writeClipboard(report)}
	}
}

// titleCase upper-cases the first letter of each word (Python str.title()).
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
