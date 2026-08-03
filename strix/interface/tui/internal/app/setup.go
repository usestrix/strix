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
		m.setupMsg("Verifying model connection...", render.Col(amber))
		return m, send(m.client, "setup.start", map[string]any{})
	default:
		m.setupMsg("Unknown command '"+command+"'. Type /help.", render.Col(red))
		return m, nil
	}
}

// submitSetupPrompt handles free text the way opencode's home prompt does:
// anything that looks like a target is added, the rest becomes the scan
// instruction, and the scan launches once a target is known.
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
		m.setupMsg("✓ Added target: "+token, render.Col(green))
		commands = append(commands, send(m.client, "setup.add_target", map[string]any{"target": token}))
	}
	if len(fields) > targets {
		commands = append(commands, send(m.client, "setup.set_instruction", map[string]any{"instruction": value}))
	}
	if targets > 0 || len(m.snapshot.Targets) > 0 {
		m.setupMsg("Verifying model connection...", render.Col(amber))
		commands = append(commands, send(m.client, "setup.start", map[string]any{}))
	} else {
		m.setupMsg("Prompt saved. Add a target (URL, repo, path, domain, or IP) to launch.", render.Dim())
	}
	return *m, tea.Batch(commands...)
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
		line := commandStyle.Render(fmt.Sprintf("%s%-21s", prefix, command[0])) + descriptionStyle.Render(command[1])
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

func (m *Model) resizeViewport() {
	m.syncInputHeight()
	if m.snapshot.SetupMode {
		contentWidth, historyHeight := m.setupLayout()
		m.input.SetWidth(max(3, contentWidth-3))
		m.viewport.Width = max(10, contentWidth)
		m.viewport.Height = max(1, historyHeight)
		m.refreshViewport()
		return
	}
	_, _, chatWidth, chatHeight := m.layout()
	m.input.SetWidth(max(3, chatWidth-3))
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

func (m Model) setupLayout() (contentWidth, historyHeight int) {
	contentWidth, historyHeight, _ = m.setupGeometry()
	return
}

// setupGeometry sizes the centered setup column: wordmark, composer, an
// optional command menu and the feedback log, all inside a narrow column.
func (m Model) setupGeometry() (contentWidth, historyHeight, menuRows int) {
	contentWidth = min(64, max(24, m.width-8))
	logoHeight := strings.Count(m.setupLogoView(contentWidth), "\n") + 1
	composerHeight := m.input.Height() + 3 // meta row, blank line and the bar
	menuRows = m.commandMenuHeight()
	// Sections are separated by a blank line; the hint row closes the column.
	fixed := logoHeight + 1 + composerHeight + 2
	available := max(0, min(m.height, 40)-fixed)
	menuRows = min(menuRows, available)
	historyHeight = min(m.setupLogHeight(), max(0, available-menuRows-1))
	return
}

// setupLogHeight keeps the feedback log to the recent lines; the setup screen
// is a launch pad, not a scrollback.
func (m Model) setupLogHeight() int { return min(len(m.setupLog), 8) }

// setupLogoView renders the wordmark two-tone - solid cells bright, bevel
// cells recessed - the way opencode shades its home logo.
func (m Model) setupLogoView(width int) string {
	if m.height < 20 {
		return lipgloss.NewStyle().Width(width).Align(lipgloss.Center).
			Render(lipgloss.NewStyle().Bold(true).Foreground(brightGreen).Render("STRIX"))
	}
	return lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Render(shadedBanner())
}

var shadedBannerOnce = sync.OnceValue(func() string {
	glyph := lipgloss.NewStyle().Bold(true).Foreground(brightGreen)
	bevel := lipgloss.NewStyle().Foreground(deepGreen)
	lines := strings.Split(banner, "\n")
	block := 0
	for _, line := range lines {
		block = max(block, lipgloss.Width(line))
	}
	var b strings.Builder
	for index, line := range lines {
		if index > 0 {
			b.WriteString("\n")
		}
		line += strings.Repeat(" ", block-lipgloss.Width(line))
		for _, char := range line {
			switch char {
			case ' ':
				b.WriteString(" ")
			case '█':
				b.WriteString(glyph.Render("█"))
			default:
				b.WriteString(bevel.Render(string(char)))
			}
		}
	}
	return b.String()
})

func shadedBanner() string { return shadedBannerOnce() }

// setupComposer draws the input the way opencode draws its prompt: no box, a
// single accent bar down the left edge and the scan settings underneath.
func (m Model) setupComposer(width int) string {
	bar := dark
	if m.focus == focusInput {
		bar = green
	}
	body := m.input.View() + "\n\n" + m.setupSummaryView(max(8, width-4))
	composer := lipgloss.NewStyle().
		Border(lipgloss.Border{Left: "▎"}, false, false, false, true).
		BorderForeground(bar).
		Width(width - 1).PaddingLeft(1).PaddingRight(1).
		Render(body)
	return composer + "\n" + lipgloss.NewStyle().Foreground(bar).Width(width).Render("╹")
}

// setupSummaryView is the quiet meta row under the composer: just the model,
// plus the targets once some are added.
func (m Model) setupSummaryView(width int) string {
	wrap := lipgloss.NewStyle().Width(width)
	model := strings.TrimSpace(m.snapshot.Model)
	row := render.Col(mid).Render(model)
	if model == "" {
		row = render.Dim().Render("no model · /model to choose one")
	}
	rows := []string{wrap.Render(row)}
	if len(m.snapshot.Targets) > 0 {
		targets := strings.Join(m.snapshot.Targets, ", ")
		if hidden := m.snapshot.TargetCount - len(m.snapshot.Targets); hidden > 0 {
			targets += fmt.Sprintf(" +%d more", hidden)
		}
		rows = append(rows, wrap.Render(render.Col(white).Render(targets)))
	}
	return strings.Join(rows, "\n")
}

// setupHintsView is the closing key hint row, mirroring opencode's home footer.
func (m Model) setupHintsView(width int) string {
	hints := []string{"/model  choose model", "enter  launch scan", "/  commands"}
	line := render.Dim().Render(strings.Join(hints, "   "))
	if lipgloss.Width(line) > width {
		line = render.Dim().Render("/help for commands")
	}
	return lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Render(line)
}

func (m Model) setupView() string {
	contentWidth, historyHeight, menuRows := m.setupGeometry()
	body := m.setupBody(contentWidth, historyHeight, menuRows)
	// Shed the optional sections until the column fits the terminal: first the
	// feedback log, then the command menu row by row.
	if lipgloss.Height(body) > m.height && historyHeight > 0 {
		historyHeight = 0
		body = m.setupBody(contentWidth, historyHeight, menuRows)
	}
	for lipgloss.Height(body) > m.height && menuRows > 0 {
		menuRows--
		body = m.setupBody(contentWidth, historyHeight, menuRows)
	}
	if lipgloss.Height(body) > m.height {
		body = strings.Join(strings.Split(body, "\n")[:max(0, m.height)], "\n")
	}
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, body,
		lipgloss.WithWhitespaceBackground(black))
}

func (m Model) setupBody(contentWidth, historyHeight, menuRows int) string {
	parts := []string{m.setupLogoView(contentWidth), m.setupComposer(contentWidth)}
	if menu := m.commandMenuViewLimit(contentWidth, menuRows); menu != "" {
		parts = append(parts, menu)
	}
	if historyHeight > 0 {
		parts = append(parts, m.viewport.View())
	}
	// The command menu is the command reference while it is open.
	if menuRows == 0 {
		parts = append(parts, m.setupHintsView(contentWidth))
	}
	return strings.Join(parts, "\n\n")
}
