package app

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/usestrix/strix/tui/internal/render"
)

func (m Model) submit(value string) (tea.Model, tea.Cmd) {
	if m.snapshot.SetupMode {
		return m.submitSetupPrompt(value)
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

// submitSetupPrompt keeps free text as the task verbatim while passing any
// network references alongside it for the backend to reconcile as targets.
func (m *Model) submitSetupPrompt(value string) (tea.Model, tea.Cmd) {
	targets := networkTargets(value)
	payload := map[string]any{"instruction": value, "targets": targets}
	// A bare prompt mounts the working directory. The backend asks about that
	// from the live view, so the prompt is held here until it is answered.
	if len(targets) == 0 && len(m.snapshot.Targets) == 0 {
		m.pendingPrompt = value
		payload["mount_working_dir"] = true
	}
	return *m, send(m.client, "setup.start", payload)
}

// networkTargets extracts ordered raw candidates. Canonicalization and scope
// reconciliation remain the backend's responsibility.
func networkTargets(instruction string) []string {
	targets := make([]string, 0)
	seen := make(map[string]struct{})
	for _, field := range strings.Fields(instruction) {
		candidate := strings.Trim(field, "\"'`()<> {},;.")
		if _, duplicate := seen[candidate]; candidate == "" || duplicate || !isNetworkTarget(candidate) {
			continue
		}
		seen[candidate] = struct{}{}
		targets = append(targets, candidate)
	}
	return targets
}

func isNetworkTarget(candidate string) bool {
	lower := strings.ToLower(candidate)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		parsed, err := url.Parse(candidate)
		return err == nil && parsed.Host != "" && !strings.HasSuffix(parsed.Host, ":") && validNetworkHost(parsed.Hostname(), true)
	}
	if strings.Contains(candidate, "://") || strings.ContainsAny(candidate, "@\\") {
		return false
	}
	if ip := net.ParseIP(candidate); ip != nil {
		return true
	}
	parsed, err := url.Parse("//" + candidate)
	if err != nil || parsed.Host == "" || parsed.User != nil || strings.HasSuffix(parsed.Host, ":") {
		return false
	}
	if isLikelyFileName(candidate) {
		return false
	}
	return validNetworkHost(parsed.Hostname(), false)
}

func validNetworkHost(host string, allowSingleLabel bool) bool {
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	host = strings.TrimSuffix(host, ".")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if host == "" || len(host) > 253 || (!allowSingleLabel && !strings.Contains(host, ".")) {
		return false
	}
	if strings.IndexFunc(host, func(char rune) bool { return char > 127 }) >= 0 {
		return true
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || !isASCIILetterOrDigit(label[0]) || !isASCIILetterOrDigit(label[len(label)-1]) {
			return false
		}
		for i := 1; i < len(label)-1; i++ {
			if !isASCIILetterOrDigit(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 || strings.HasPrefix(tld, "-") || strings.HasSuffix(tld, "-") {
		return false
	}
	if strings.HasPrefix(strings.ToLower(tld), "xn--") {
		return len(tld) > len("xn--")
	}
	for i := range len(tld) {
		if !isASCIILetter(tld[i]) {
			return false
		}
	}
	return true
}

func isLikelyFileName(candidate string) bool {
	if strings.ContainsAny(candidate, "/:?#") {
		return false
	}
	dot := strings.LastIndex(candidate, ".")
	if dot < 0 {
		return false
	}
	_, found := nonHostFileExtensions[strings.ToLower(candidate[dot+1:])]
	return found
}

var nonHostFileExtensions = map[string]struct{}{
	"cfg": {}, "conf": {}, "css": {}, "csv": {}, "env": {}, "gif": {}, "go": {},
	"htm": {}, "html": {}, "ini": {}, "jpeg": {}, "jpg": {}, "js": {}, "json": {},
	"jsx": {}, "less": {}, "lock": {}, "log": {}, "md": {}, "markdown": {}, "pdf": {},
	"png": {}, "py": {}, "pyc": {}, "rst": {}, "scss": {}, "sql": {}, "svg": {},
	"toml": {}, "ts": {}, "tsx": {}, "txt": {}, "vue": {}, "xml": {}, "yaml": {},
	"yml": {},
}

func isASCIILetterOrDigit(char byte) bool {
	return isASCIILetter(char) || char >= '0' && char <= '9'
}

func isASCIILetter(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z'
}

// answerMountConfirmation replies to the working-directory mount the backend is
// waiting on. Either answer starts the scan - declining only means it runs
// without the directory - so the prompt stays with the run rather than coming
// back to the composer.
func (m *Model) answerMountConfirmation(approved bool) tea.Cmd {
	m.pendingPrompt = ""
	return send(m.client, "setup.confirm_mount", map[string]any{"approved": approved})
}

// statusVisible mirrors #agent_status_display: shown only when an agent is
// selected during a scan; hidden (display:none) in setup mode.
func (m Model) statusVisible() bool {
	return !m.snapshot.SetupMode && len(m.snapshot.Agents) > 0
}

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
	chatHeight = max(4, m.height-statusH-(m.input.Height()+2))
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

func (m Model) setupContent() string {
	var b strings.Builder
	for _, line := range m.setupLog {
		b.WriteString(line + "\n")
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// setupLogAppend records a chronological line in the setup scrollback. A line
// that is already there moves to the end instead of being repeated: retrying a
// launch that cannot succeed yet - no model configured, no target - would
// otherwise push the same pair of lines until they were all the log held.
func (m *Model) setupLogAppend(line string) {
	for i, existing := range m.setupLog {
		if existing == line {
			m.setupLog = append(m.setupLog[:i], m.setupLog[i+1:]...)
			break
		}
	}
	m.setupLog = append(m.setupLog, line)
}

// setupMsg appends a styled feedback line (success green, error red, notice dim).
// The log budgets rows by entry, so a message is flattened to one line first: a
// wrapped exception would otherwise render as several rows and push the launch
// column past the bottom of the terminal.
func (m *Model) setupMsg(text string, style lipgloss.Style) {
	m.setupLogAppend(style.Render(flattenStatus(text)))
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
// many feedback-log rows fit.
type setupFit struct {
	width   int
	logo    int
	tagline bool
	logRows int
}

// setupFit picks the richest layout that still fits the terminal. Sections are
// surrendered in the order of shrink below - never the composer, which is the
// only thing on this screen the user has to reach.
func (m Model) setupFit() setupFit {
	fit := setupFit{
		width:   setupColumnWidth(m.width),
		logo:    logoFull,
		tagline: true,
		logRows: setupLogRows(m.setupLog),
	}
	if m.width < wordmarkWidth()+2 {
		fit.logo = logoCompact
	}
	if m.height < 18 {
		fit.logo, fit.tagline = min(fit.logo, logoCompact), false
	}
	shrink := []func(*setupFit) bool{
		func(f *setupFit) bool { return trimTo(&f.logRows, 3) },
		func(f *setupFit) bool { return clearFlag(&f.tagline) },
		func(f *setupFit) bool { return trimTo(&f.logRows, 0) },
		func(f *setupFit) bool { return trimTo(&f.logo, logoCompact) },
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
	// growing composer and new feedback both push downward.
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
	if fit.logRows > 0 && len(m.setupLog) > 0 {
		height -= fit.logRows + 1
	}
	return height
}

// setupBody stacks the launch column: wordmark, composer with its scan summary,
// the target list, feedback and the key hints. Sections
// are separated by a blank line; the composer and its summary read as one unit.
func (m Model) setupBody(fit setupFit) string {
	parts := make([]string, 0, 6)
	if header := m.setupHeaderView(fit); header != "" {
		parts = append(parts, header)
	}
	parts = append(parts, m.setupComposer(fit.width))
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
		chips = append(chips, render.Col(amber).Render("○ no model")+
			render.Dim().Render(" · set STRIX_LLM or configure one in your config"))
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
	left := hint("enter", "launch scan") + label("   ") + hint("ctrl+c", "quit")
	if lipgloss.Width(left) > inner {
		left = hint("enter", "launch scan")
	}
	right := label("v" + appVersion)
	gap := inner - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 2 {
		return pad + left
	}
	return pad + left + strings.Repeat(" ", gap) + right
}

// syncMountPrompt raises or clears the working-directory prompt to match the
// backend, which asks for it from the live view once a target-less scan is
// waiting on the answer. Following the snapshot rather than the keystroke keeps
// the prompt right across redraws and reconnects.
func (m *Model) syncMountPrompt() {
	switch {
	case m.snapshot.PendingMount != "" && m.modal != modalConfirmMount:
		m.openModal(modalConfirmMount)
	case m.snapshot.PendingMount == "" && m.modal == modalConfirmMount:
		m.closeModal()
	}
}
