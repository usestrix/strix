package app

import (
	"fmt"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/render"
)

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
		return m.submitSetupPrompt(value)
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
			m.setupMsg("/mount <path> adds a local directory as a target.", render.Dim())
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
		// With no target the scan would mount the working directory; confirm
		// that first, exactly as a bare prompt does.
		if len(m.snapshot.Targets) == 0 {
			m.pendingPrompt = ""
			m.openModal(modalConfirmMount)
			return m, nil
		}
		m.setupMsg("Verifying model connection...", render.Col(amber))
		return m, send(m.client, "setup.start", map[string]any{"verify": true})
	default:
		m.setupMsg("Unknown command '"+command+"'. Type /help.", render.Col(red))
		return m, nil
	}
}

// submitSetupPrompt handles free text the way a coding agent's prompt does:
// anything that looks like a target is added, the rest becomes the scan
// instruction, and the prompt alone is enough to launch. With no target, the
// backend scans the current working directory.
func (m *Model) submitSetupPrompt(value string) (tea.Model, tea.Cmd) {
	var commands []tea.Cmd
	fields := strings.Fields(value)
	targets := 0
	for _, field := range fields {
		token := strings.Trim(field, ",;")
		if !looksLikeTarget(token) || m.hasTarget(token) {
			continue
		}
		targets++
		commands = append(commands, send(m.client, "setup.add_target", map[string]any{"target": token}))
	}
	// With no target at all the scan would mount the working directory, so ask
	// before doing that rather than mounting it silently.
	if targets == 0 && len(m.snapshot.Targets) == 0 {
		m.pendingPrompt = value
		m.openModal(modalConfirmMount)
		return *m, nil
	}
	if len(fields) > targets {
		commands = append(commands, send(m.client, "setup.set_instruction", map[string]any{"instruction": value}))
	}
	// A named target verifies the model connection before the scan commits to
	// it; see launchCommands for the confirmed target-less case.
	m.setupMsg("Verifying model connection...", render.Col(amber))
	commands = append(commands, send(m.client, "setup.start", map[string]any{"verify": true}))
	// Ordered, not batched: setup.start leaves setup mode, so it must be the
	// last command to reach the backend. Batched sends race, and once the
	// preflight is skipped setup.start wins, making the target and instruction
	// commands land after the guard closes and fail with a red error.
	return *m, tea.Sequence(commands...)
}

// launchWorkingDir starts the scan against the working directory once the user
// has confirmed mounting it. A bare prompt launches optimistically, like a
// coding agent: no model preflight, so any model error surfaces live.
func (m *Model) launchWorkingDir() tea.Cmd {
	var commands []tea.Cmd
	if prompt := strings.TrimSpace(m.pendingPrompt); prompt != "" {
		commands = append(commands, send(m.client, "setup.set_instruction", map[string]any{"instruction": prompt}))
	}
	m.pendingPrompt = ""
	commands = append(commands, send(m.client, "setup.start", map[string]any{
		"verify": false, "mount_working_dir": true,
	}))
	// Ordered so setup.start cannot close the setup guard before the
	// instruction lands.
	return tea.Sequence(commands...)
}

// restorePendingPrompt puts a prompt back in the composer after the mount
// confirmation is declined, so it can be edited or given a target instead.
func (m *Model) restorePendingPrompt() {
	if m.pendingPrompt == "" {
		return
	}
	m.input.SetValue(m.pendingPrompt)
	m.pendingPrompt = ""
	m.resizeViewport()
}

func (m Model) hasTarget(candidate string) bool {
	for _, target := range m.snapshot.Targets {
		if target == candidate {
			return true
		}
	}
	return false
}

// looksLikeTarget reports whether a whitespace-delimited token names something
// scannable: a URL, repo, filesystem path, domain, or IP address.
func looksLikeTarget(token string) bool {
	if token == "" {
		return false
	}
	if strings.Contains(token, "://") || strings.HasSuffix(token, ".git") {
		return true
	}
	if strings.HasPrefix(token, "/") || strings.HasPrefix(token, "./") || strings.HasPrefix(token, "~/") || strings.HasPrefix(token, "../") {
		return true
	}
	if ip := net.ParseIP(token); ip != nil {
		return true
	}
	host := token
	if at := strings.LastIndex(host, "@"); at >= 0 {
		host = host[at+1:]
	}
	host = strings.SplitN(host, "/", 2)[0]
	host = strings.SplitN(host, ":", 2)[0]
	if !domainPattern.MatchString(host) {
		return false
	}
	tld := host[strings.LastIndex(host, ".")+1:]
	return len(tld) >= 2 && !isNumeric(tld)
}

var domainPattern = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z0-9]{2,}$`)

func isNumeric(value string) bool {
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
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

// selectionBackground is the raised surface behind the highlighted menu row.
const selectionBackground = "\x1b[48;2;20;20;20m"

// surfaceRow paints a row onto a background surface. The background is
// re-applied after every style reset so styled runs inside the row do not punch
// holes in it, and the row is padded out to the full width.
func surfaceRow(line string, width int, background string) string {
	line = background + strings.ReplaceAll(line, "\x1b[0m", "\x1b[0m"+background)
	if pad := width - lipgloss.Width(line); pad > 0 {
		line += strings.Repeat(" ", pad)
	}
	return line + "\x1b[0m"
}

func (m Model) commandMenuView(width int) string {
	matches := m.matchingSetupCommands()
	if len(matches) == 0 {
		return ""
	}
	return m.commandMenuViewLimit(width, len(matches))
}

// commandMenuViewLimit lays the command list out in two columns: the command
// itself in a gutter sized to the longest visible name, then its description in
// whatever space is left. The selected row is marked and lifted onto a surface.
func (m Model) commandMenuViewLimit(width, limit int) string {
	matches := m.matchingSetupCommands()
	if len(matches) == 0 || limit <= 0 {
		return ""
	}
	start, end := optionWindow(m.commandCursor, len(matches), limit)
	gutter := 0
	for i := start; i < end; i++ {
		gutter = max(gutter, lipgloss.Width(matches[i][0]))
	}
	gutter = min(gutter, max(10, width/2))
	lines := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		command := matches[i]
		prefix, commandStyle, descriptionStyle := "  ", render.Col(render.InfoBlue), render.Dim()
		selected := i == m.commandCursor
		if selected {
			prefix = render.Col(green).Render("› ")
			commandStyle = lipgloss.NewStyle().Bold(true).Foreground(brightGreen)
			descriptionStyle = lipgloss.NewStyle().Foreground(mid)
		}
		name := padToWidth(truncate(command[0], gutter), gutter)
		line := prefix + commandStyle.Render(name) + "   " +
			descriptionStyle.Render(truncate(command[1], max(0, width-gutter-6)))
		if selected {
			lines = append(lines, surfaceRow(line, width, selectionBackground))
			continue
		}
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
	chatHeight = max(4, m.height-statusH-(m.input.Height()+2)-m.commandMenuHeight())
	return
}

// resizeViewport refits the composer and the scrollback to the terminal. The
// composer is sized width first: how far its content wraps, and so how tall it
// needs to be, depends on the width it is given.
func (m *Model) resizeViewport() {
	if m.snapshot.SetupMode {
		contentWidth := setupColumnWidth(m.width)
		// The composer's border and padding each take a column per side.
		m.input.SetWidth(max(3, contentWidth-4))
		// A clipped placeholder reads as an unfinished sentence, so a narrow
		// composer gets the short prompt instead.
		m.input.Placeholder = setupPlaceholder
		if contentWidth-6 < lipgloss.Width(setupPlaceholder) {
			m.input.Placeholder = setupPlaceholderShort
		}
		m.syncInputHeight()
		m.viewport.Width = max(10, contentWidth)
		m.viewport.Height = max(1, setupLogRows(m.setupLog))
		m.refreshViewport()
		return
	}
	_, _, chatWidth, _ := m.layout()
	// The accent bar and its padding each take a column.
	m.input.SetWidth(max(3, chatWidth-3))
	m.syncInputHeight()
	_, _, _, chatHeight := m.layout()
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

// setupLogRows is how many feedback lines the launch column shows before the
// fit starts trimming them. It is a launch pad, not a scrollback.
func setupLogRows(log []string) int { return min(len(log), 6) }

// Logo treatments, largest last. The launch column steps down through them as
// the terminal runs out of room.
const (
	logoNone = iota
	logoCompact
	logoFull
)

// setupColumnWidth is the width of the centered launch column. It widens to
// the banner rather than lose it, as long as the terminal can still spare a
// margin either side.
func setupColumnWidth(terminal int) int {
	width := min(72, max(24, terminal-8))
	if terminal >= wordmarkWidth()+2 {
		width = max(width, wordmarkWidth())
	}
	return width
}

// setupFit records how much of the launch column survives at the current
// terminal size: the wordmark treatment, whether the tagline is shown, and how
// many command-menu and feedback-log rows fit.
type setupFit struct {
	width    int
	logo     int
	tagline  bool
	menuRows int
	logRows  int
}

// setupFit picks the richest layout that still fits the terminal. Sections are
// surrendered in the order of shrink below - never the composer, which is the
// only thing on this screen the user has to reach.
func (m Model) setupFit() setupFit {
	fit := setupFit{
		width:    setupColumnWidth(m.width),
		logo:     logoFull,
		tagline:  true,
		menuRows: m.commandMenuHeight(),
		logRows:  setupLogRows(m.setupLog),
	}
	if m.width < wordmarkWidth()+2 {
		fit.logo = logoCompact
	}
	if m.height < 18 {
		fit.logo, fit.tagline = min(fit.logo, logoCompact), false
	}
	shrink := []func(*setupFit) bool{
		func(f *setupFit) bool { return trimTo(&f.logRows, 3) },
		func(f *setupFit) bool { return trimTo(&f.menuRows, 6) },
		func(f *setupFit) bool { return clearFlag(&f.tagline) },
		func(f *setupFit) bool { return trimTo(&f.logRows, 0) },
		func(f *setupFit) bool { return trimTo(&f.menuRows, 3) },
		func(f *setupFit) bool { return trimTo(&f.logo, logoCompact) },
		func(f *setupFit) bool { return trimTo(&f.menuRows, 1) },
		func(f *setupFit) bool { return trimTo(&f.logo, logoNone) },
	}
	for step := 0; step < len(shrink) && lipgloss.Height(m.setupBody(fit)) > m.height; {
		if !shrink[step](&fit) {
			step++
		}
	}
	return fit
}

func trimTo(value *int, floor int) bool {
	if *value <= floor {
		return false
	}
	*value--
	return true
}

func clearFlag(flag *bool) bool {
	if !*flag {
		return false
	}
	*flag = false
	return true
}

func (m Model) setupView() string {
	fit := m.setupFit()
	rows := strings.Split(m.setupBody(fit), "\n")
	if len(rows) > m.height {
		rows = rows[:max(0, m.height)]
	}
	// Anchor the column on its resting height rather than its current one, so a
	// growing composer, an open command menu and new feedback all push downward.
	// Centering on the live height walks the whole page up under the cursor,
	// one row at a time, as the prompt wraps.
	top := (m.height - m.setupRestingHeight(fit, len(rows))) / 2
	top = min(max(top, 0), max(0, m.height-len(rows)))
	left := max(0, (m.width-fit.width)/2)
	frame := make([]string, m.height)
	for row := range frame {
		line := ""
		if index := row - top; index >= 0 && index < len(rows) {
			line = strings.Repeat(" ", left) + rows[index]
		}
		frame[row] = padToWidth(line, m.width)
	}
	return strings.Join(frame, "\n")
}

// setupRestingHeight is the column's height with the composer at its opening
// size and the transient sections closed: the layout the screen sits at when
// idle. Anchoring on this keeps the column still as the composer grows.
func (m Model) setupRestingHeight(fit setupFit, height int) int {
	floor, _ := m.composerBounds()
	height -= max(0, m.input.Height()-floor)
	if fit.menuRows > 0 {
		height -= fit.menuRows + 1 // the menu and the blank line above it
	}
	if fit.logRows > 0 && len(m.setupLog) > 0 {
		height -= fit.logRows + 1
	}
	return height
}

// setupBody stacks the launch column: wordmark, composer with its scan summary,
// the target list, the live command menu, feedback and the key hints. Sections
// are separated by a blank line; the composer and its summary read as one unit.
func (m Model) setupBody(fit setupFit) string {
	parts := make([]string, 0, 6)
	if header := m.setupHeaderView(fit); header != "" {
		parts = append(parts, header)
	}
	parts = append(parts, m.setupComposer(fit.width))
	if menu := m.commandMenuViewLimit(fit.width, fit.menuRows); menu != "" {
		parts = append(parts, menu)
	}
	if log := m.setupLogView(fit); log != "" {
		parts = append(parts, log)
	}
	parts = append(parts, m.setupHintsView(fit.width))
	// Every row is padded to the column width: lipgloss.Place centers each line
	// on its own, which would otherwise stagger the short rows.
	rows := strings.Split(strings.Join(parts, "\n\n"), "\n")
	for index, row := range rows {
		rows[index] = padToWidth(row, fit.width)
	}
	return strings.Join(rows, "\n")
}

// setupHeaderView centers the wordmark over the tagline.
func (m Model) setupHeaderView(fit setupFit) string {
	center := lipgloss.NewStyle().Width(fit.width).Align(lipgloss.Center)
	var rows []string
	switch fit.logo {
	case logoFull:
		// The banner is tall enough to want air under it.
		rows = append(rows, center.Render(wordmark()))
		if fit.tagline {
			rows = append(rows, "")
		}
	case logoCompact:
		rows = append(rows, center.Render(lipgloss.NewStyle().Bold(true).Foreground(brightGreen).Render("STRIX")))
	}
	if fit.tagline {
		rows = append(rows, center.Render(render.Dim().Render("Open-source AI hackers for your apps")))
	}
	return strings.Join(rows, "\n")
}

// banner is the Strix wordmark: block letters with a bevelled edge.
const banner = ` ███████╗████████╗██████╗ ██╗██╗  ██╗
 ██╔════╝╚══██╔══╝██╔══██╗██║╚██╗██╔╝
 ███████╗   ██║   ██████╔╝██║ ╚███╔╝
 ╚════██║   ██║   ██╔══██╗██║ ██╔██╗
 ███████║   ██║   ██║  ██║██║██╔╝ ██╗
 ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝`

// wordmark renders the banner in solid brand green. Every row is padded out to
// the full block so centering cannot ripple the letterforms out of alignment.
var wordmarkOnce = sync.OnceValue(func() string {
	green := lipgloss.NewStyle().Foreground(green)
	lines := strings.Split(banner, "\n")
	rows := make([]string, len(lines))
	for index, line := range lines {
		rows[index] = green.Render(line + strings.Repeat(" ", wordmarkWidth()-lipgloss.Width(line)))
	}
	return strings.Join(rows, "\n")
})

func wordmark() string { return wordmarkOnce() }

// wordmarkWidth is the cell width of the widest banner row.
var wordmarkWidth = sync.OnceValue(func() int {
	block := 0
	for _, line := range strings.Split(banner, "\n") {
		block = max(block, lipgloss.Width(line))
	}
	return block
})

// setupComposer draws the prompt as a rounded panel that lights up green while
// it holds focus. The scan meta and targets live inside the panel, flush under
// the input, so everything shares one left edge - the way opencode aligns its
// home prompt.
func (m Model) setupComposer(width int) string {
	border := dark
	if m.focus == focusInput {
		border = green
	}
	// Width covers the padding but not the border, so a box of the given total
	// width sets width-2 here and hands the interior the width-4 that is left.
	inner := max(1, width-4)
	body := m.highlightInputSelection(m.input.View())
	body += "\n\n" + m.setupSummaryView(inner)
	if targets := m.setupTargetsView(inner); targets != "" {
		body += "\n" + targets
	}
	return lipgloss.NewStyle().Width(max(1, width-2)).Padding(0, 1).
		Border(lipgloss.RoundedBorder()).BorderForeground(border).
		Render(body)
}

// setupSummaryView is the quiet meta line inside the panel: what the scan will
// run as, or what is still missing before it can run.
func (m Model) setupSummaryView(width int) string {
	chips := []string{}
	if model := strings.TrimSpace(m.snapshot.Model); model != "" {
		name, provider := model, ""
		if slash := strings.LastIndex(model, "/"); slash >= 0 {
			provider, name = model[:slash], model[slash+1:]
		}
		chip := render.Col(green).Render("● ") + render.Col(white).Render(name)
		if provider != "" {
			chips = append(chips, chip, render.Dim().Render(provider))
		} else {
			chips = append(chips, chip)
		}
	} else {
		chips = append(chips, render.Col(amber).Render("○ no model")+render.Dim().Render(" · /model to connect"))
	}
	if m.snapshot.MaxBudgetUSD != nil {
		chips = append(chips, render.Dim().Render(fmt.Sprintf("$%.2f budget", *m.snapshot.MaxBudgetUSD)))
	}
	return truncate(strings.Join(chips, render.Dim().Render(" · ")), max(1, width))
}

// setupTargetsView lists what the scan is pointed at, once anything is queued.
func (m Model) setupTargetsView(width int) string {
	if len(m.snapshot.Targets) == 0 {
		return ""
	}
	const visible = 4
	total := max(m.snapshot.TargetCount, len(m.snapshot.Targets))
	rows := []string{render.Bold(green).Render("Targets") + render.Dim().Render(fmt.Sprintf(" %d", total))}
	for _, target := range m.snapshot.Targets[:min(visible, len(m.snapshot.Targets))] {
		rows = append(rows, render.Col(dim).Render("▸ ")+render.Col(white).Render(truncate(target, max(1, width-2))))
	}
	if hidden := total - visible; hidden > 0 {
		rows = append(rows, render.Dim().Render(fmt.Sprintf("+%d more", hidden)))
	}
	return strings.Join(rows, "\n")
}

// setupLogView shows the tail of the feedback log. The launch screen is a
// launch pad, not a scrollback, so only the most recent lines are kept.
func (m Model) setupLogView(fit setupFit) string {
	if fit.logRows <= 0 || len(m.setupLog) == 0 {
		return ""
	}
	tail := m.setupLog[max(0, len(m.setupLog)-fit.logRows):]
	rows := make([]string, 0, len(tail))
	for _, line := range tail {
		// Align with the panel interior [2, width-2].
		rows = append(rows, "  "+truncate(line, max(1, fit.width-4)))
	}
	return strings.Join(rows, "\n")
}

// setupHintsView is the closing key hint row, aligned to the panel's inner
// edges: keys flush under the input, the version at the far right.
func (m Model) setupHintsView(width int) string {
	// The panel's interior spans [2, width-2]; match it so the row reads as a
	// footer under the input rather than a stray line.
	const pad = "  "
	inner := max(1, width-4)
	key := lipgloss.NewStyle().Foreground(white).Render
	label := render.Dim().Render
	hint := func(k, text string) string { return key(k) + label(" "+text) }
	left := hint("enter", "launch scan") + label("   ") + hint("/", "commands") +
		label("   ") + hint("ctrl+c", "quit")
	if lipgloss.Width(left) > inner {
		left = hint("/", "commands")
	}
	right := label("v" + appVersion)
	gap := inner - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 2 {
		return pad + left
	}
	return pad + left + strings.Repeat(" ", gap) + right
}
