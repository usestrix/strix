package app

import (
	"fmt"
	"math"
	"strconv"
	"strings"

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
	fixedWithoutMenu := headerHeight + summaryHeight + m.input.Height() + 2 + partCount - 1
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
		targets = strings.Join(m.snapshot.Targets, ", ")
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
	if m.focus == focusInput {
		inputBorder = green
	}
	composer := lipgloss.NewStyle().Width(contentWidth - 2).Height(m.input.Height()).
		Border(lipgloss.RoundedBorder()).BorderForeground(inputBorder).PaddingLeft(1).
		Render(m.input.View())

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
