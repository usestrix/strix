package app

import (
	"fmt"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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
	input                  textarea.Model
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
	expandedEvents         map[string]bool
	blockCache             map[string]renderedBlock
	eventSpans             []eventSpan
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
	deepGreen   = lipgloss.Color("#166534")
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

// maxInputLines caps the auto-growing chat composer, matching the old
// Textual ChatTextArea (grows with content up to 8 lines).
const maxInputLines = 8

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

// syncInputHeight grows or shrinks the composer with its content.
func (m *Model) syncInputHeight() {
	m.input.SetHeight(min(max(1, m.input.LineCount()), maxInputLines))
}

func New(client *Client) Model {
	newInput := func() textinput.Model {
		input := textinput.New()
		input.Prompt = ""
		input.CharLimit = 4096
		input.TextStyle = lipgloss.NewStyle().Foreground(textColor)
		input.Cursor.Style = lipgloss.NewStyle().Foreground(green)
		return input
	}
	input := newChatInput()
	input.Placeholder = "Type / to configure your scan"
	input.Focus()
	return Model{
		client: client, input: input, pickerInput: newInput(), viewport: viewport.New(80, 20), vulnViewport: viewport.New(80, 20),
		collapsedAgents: map[string]bool{}, expandedEvents: map[string]bool{}, blockCache: map[string]renderedBlock{}, providerConfigured: map[string]bool{}, providerLabels: map[string]string{}, providerStates: map[string]string{}, providerDetails: map[string]string{}, providerDisconnectable: map[string]bool{}, showSplash: true, splashStarted: time.Now(), followOutput: true,
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
