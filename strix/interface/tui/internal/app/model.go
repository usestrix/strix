package app

import (
	"fmt"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
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

type modalMode int

const (
	modalNone modalMode = iota
	modalHelp
	modalQuit
	modalStop
	modalConfirmMount
	modalVulnerability
)

type focusMode int

const (
	focusInput focusMode = iota
	focusChat
	focusAgents
	focusVulnerabilities
	focusMcp
)

type scrollbarTarget int

const (
	scrollbarNone scrollbarTarget = iota
	scrollbarTrace
	scrollbarAgents
	scrollbarFindings
	scrollbarMcp
)

type Model struct {
	client                 *Client
	width, height          int
	snapshot               protocol.Snapshot
	input                  textarea.Model
	viewport               viewport.Model
	viewportContent        string
	vulnViewport           viewport.Model
	modal                  modalMode
	focus                  focusMode
	options                []string
	filtered               []string
	cursor                 int
	collapsedAgents        map[string]bool
	expandedEvents         map[string]bool
	blockCache             map[string]renderedBlock
	eventSpans             []eventSpan
	setupLog               []string
	pendingPrompt          string
	errorText              string
	fatalError             error
	selectedAgent          int
	selectedVuln           int
	agentOffset            int
	vulnOffset             int
	mcpOffset              int
	modalChoice            int
	reportFocus            string
	ready                  bool
	quitting               bool
	showSplash             bool
	splashStarted          time.Time
	splashFrame            int
	sweepFrame             int
	budgetPauseNotified    bool
	followOutput           bool
	selection              selectionState
	toast                  string
	toastID                int
	draggingScrollbar      scrollbarTarget
	stateRevision          int
	collectionRevisions    map[string]int
	collectionAssemblies   map[string]*collectionAssembly
	resyncRequested        map[string]bool
	resyncRequests         map[string]string
	seenMessages           map[string]bool
	vulnerabilityCopied    bool
	vulnerabilityCopyError string
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

// Agent tree colors: a uniform label, dim guides, and a filled block cursor.
const (
	treeLabel    = lipgloss.Color("#e7e5e4")
	treeGuide    = lipgloss.Color("#4f4f4f")
	treeCursorFg = lipgloss.Color("#ddedf9")
	treeCursorBg = lipgloss.Color("#0178d4")
)

// Scrollbar thumbs. The track stays blank so a scrollable panel does not gain a
// visible rule down its edge, and the thumb brightens while it is dragged, which
// is the feedback Textual gave through scrollbar-color-active.
//
// One resting color for every panel, rather than the three the stylesheet named.
// The chat pane's was #1a1a1a on black, which is invisible - the bar could not be
// found, let alone grabbed (#1005).
const (
	thumbResting = lipgloss.Color("#3f3f46")
	thumbActive  = lipgloss.Color("#9ca3af")
)

// Composer placeholders. The launch screen falls back to the short prompt when
// the column is too narrow to show the full one without clipping it.
const (
	setupPlaceholder      = "Describe what to test, or name a target"
	setupPlaceholderShort = "What should Strix test?"
	chatPlaceholder       = "Send a message"
)

// The composer opens at minInputLines rows for breathing room and grows with
// its content up to maxInputLines.
const (
	minInputLines = 3
	maxInputLines = 8
)

// newChatInput builds the multi-line chat composer. Enter submits (handled by
// the update loop before the textarea sees it); Shift/Alt+Enter and Ctrl+J
// insert a newline.
func newChatInput() textarea.Model {
	input := textarea.New()
	input.ShowLineNumbers = false
	input.CharLimit = 4096
	input.MaxHeight = maxInputLines
	input.SetHeight(1)
	input.KeyMap.InsertNewline = key.NewBinding(
		key.WithKeys("shift+enter", "alt+enter", "ctrl+j"),
		key.WithHelp("shift+enter", "insert newline"),
	)
	plain := lipgloss.NewStyle()
	text := lipgloss.NewStyle().Foreground(textColor)
	placeholder := lipgloss.NewStyle().Foreground(lipgloss.Color("#525252"))
	for _, style := range []*textarea.Style{&input.FocusedStyle, &input.BlurredStyle} {
		style.Base = plain
		style.CursorLine = text
		style.EndOfBuffer = plain
		style.Placeholder = placeholder
		style.Text = text
	}
	input.FocusedStyle.Prompt = lipgloss.NewStyle().Bold(true).Foreground(green)
	input.BlurredStyle.Prompt = lipgloss.NewStyle().Foreground(dim)
	input.SetPromptFunc(2, func(lineIdx int) string {
		if lineIdx == 0 {
			return "> "
		}
		return "  "
	})
	input.Cursor.Style = lipgloss.NewStyle().Foreground(green)
	return input
}

// composerBounds returns the floor and ceiling row counts for the composer at
// the current terminal height. A short terminal shrinks the ceiling so a long
// prompt cannot crowd out everything above it.
//
// Only the launch screen opens taller than a single row: there the composer is
// the whole screen and wants breathing room, while during a scan it sits under
// the trace and stays out of the way until there is something to show.
func (m Model) composerBounds() (floor, ceiling int) {
	ceiling = maxInputLines
	if m.height > 0 {
		ceiling = max(minInputLines, min(maxInputLines, m.height/3))
	}
	floor = 1
	if m.snapshot.SetupMode {
		floor = min(minInputLines, ceiling)
	}
	return floor, ceiling
}

// syncInputHeight grows or shrinks the composer with its content, between the
// floor and ceiling.
func (m *Model) syncInputHeight() {
	floor, ceiling := m.composerBounds()
	m.input.SetHeight(max(floor, min(composerHeight(m.input), ceiling)))
}

// composerHeight is how many rows the composer needs to show all of its
// content, capped at maxInputLines. Soft-wrapped rows count: a single long
// line still grows the box. LineCount only counts hard newlines, and the
// wrapped height the textarea does report covers just the line the cursor is
// on, so a scratch copy measures each line with the composer's own wrapping.
func composerHeight(input textarea.Model) int {
	probe, rows := input, 0
	for _, line := range strings.Split(input.Value(), "\n") {
		// A line narrower than the text column cannot wrap, which is the case
		// for nearly every keystroke; only measure the ones that might.
		if ansi.StringWidth(line) < input.Width() {
			rows++
		} else {
			probe.SetValue(line)
			rows += probe.LineInfo().Height
		}
		if rows >= maxInputLines {
			return maxInputLines
		}
	}
	return max(1, rows)
}

func New(client *Client) Model {
	input := newChatInput()
	input.Placeholder = setupPlaceholder
	input.Focus()
	return Model{
		client: client, input: input, viewport: viewport.New(80, 20), vulnViewport: viewport.New(80, 20),
		collapsedAgents: map[string]bool{}, expandedEvents: map[string]bool{}, blockCache: map[string]renderedBlock{}, showSplash: true, splashStarted: time.Now(), followOutput: true,
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
	case selectionCopiedMsg:
		text := "Copied to clipboard"
		if msg.err != nil {
			text = "Copy failed: " + msg.err.Error()
		}
		return m, m.showToast(text)
	case toastExpiredMsg:
		if msg.id == m.toastID {
			m.toast = ""
			if !m.selection.dragging {
				m.selection.active = false
			}
		}
		return m, nil
	case vulnerabilityCopiedMsg:
		m.vulnerabilityCopied = msg.err == nil
		m.vulnerabilityCopyError = ""
		if msg.err != nil {
			m.vulnerabilityCopyError = msg.err.Error()
		}
		return m, nil
	case tea.KeyMsg:
		if m.showSplash {
			switch msg.String() {
			case "ctrl+c", "ctrl+q", "q", "esc":
				m.quitting = true
				return m, tea.Batch(send(m.client, "app.quit", map[string]any{}), tea.Quit)
			}
			m.showSplash = false
			return m, nil
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
	if m.modal == modalNone {
		m.input, cmd = m.input.Update(msg)
	}
	cmds = append(cmds, cmd)
	return m, tea.Batch(cmds...)
}

func (m Model) FatalError() error { return m.fatalError }
