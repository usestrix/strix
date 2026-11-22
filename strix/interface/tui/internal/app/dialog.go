package app

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
)

type dialogKind int

const (
	dialogNone dialogKind = iota
	dialogPalette
	dialogModels
	dialogProviders
	dialogMethods
	dialogBaseInput
	dialogKeyInput
	dialogLogin
	dialogEffort
	dialogSettings
	dialogBudget
)

var (
	dialogBg       = lipgloss.Color("#141414")
	dialogFooterBg = lipgloss.Color("#1e1e1e")
	dialogSelectBg = lipgloss.Color("#16301f")
)

const (
	dialogWidth   = 60
	dialogPadding = 4
	dialogMaxRows = 14
)

var efforts = []string{"none", "minimal", "low", "medium", "high", "xhigh", "max"}
var scanModes = []string{"quick", "standard", "deep"}
var scopeModes = []string{"auto", "diff", "full"}

type dialogOption struct {
	title       string
	detail      string
	right       string
	category    string
	value       string
	provider    string
	description string
	current     bool
	favorite    bool
	connected   bool
}

type dialogHint struct{ label, key string }

type modelRef struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

type providerModels struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Prefix string   `json:"prefix"`
	Models []string `json:"models"`
}

type modelPicker struct {
	Current   *modelRef        `json:"current"`
	Recent    []modelRef       `json:"recent"`
	Favorite  []modelRef       `json:"favorite"`
	Providers []providerModels `json:"providers"`
}

type authMethod struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type providerEntry struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Connected   bool         `json:"connected"`
	Methods     []authMethod `json:"methods"`
	NeedsBase   bool         `json:"needs_base"`
	DefaultBase string       `json:"default_base"`
	KeyOptional bool         `json:"key_optional"`
	search      bool
}

type providerDirectory struct {
	Popular   []providerEntry `json:"popular"`
	Providers []providerEntry `json:"providers"`
	Local     []providerEntry `json:"local"`
	Search    []providerEntry `json:"search"`
}

type dialogState struct {
	kind           dialogKind
	title          string
	placeholder    string
	query          string
	secret         bool
	options        []dialogOption
	visible        []int
	cursor         int
	loading        bool
	errorText      string
	note           string
	hints          []dialogHint
	picker         modelPicker
	directory      providerDirectory
	provider       providerEntry
	apiBase        string
	filterProvider string
}

func (d dialogState) selectable() bool {
	switch d.kind {
	case dialogBaseInput, dialogKeyInput, dialogLogin, dialogBudget:
		return false
	}
	return true
}

func (d dialogState) selected() (dialogOption, bool) {
	if d.cursor < 0 || d.cursor >= len(d.visible) {
		return dialogOption{}, false
	}
	return d.options[d.visible[d.cursor]], true
}

func (d *dialogState) refilter() {
	terms := strings.Fields(strings.ToLower(d.query))
	d.visible = d.visible[:0]
	for index, option := range d.options {
		haystack := strings.ToLower(option.title + " " + option.detail + " " + option.category + " " + option.value)
		match := true
		for _, term := range terms {
			if !strings.Contains(haystack, term) {
				match = false
				break
			}
		}
		if match && (len(terms) == 0 || !option.duplicateOf(d.options[:index])) {
			d.visible = append(d.visible, index)
		}
	}
	d.cursor = max(0, min(d.cursor, len(d.visible)-1))
}

func (o dialogOption) duplicateOf(earlier []dialogOption) bool {
	for _, other := range earlier {
		if other.value == o.value && other.provider == o.provider {
			return true
		}
	}
	return false
}

func (m *Model) openDialog(kind dialogKind) {
	m.dialog = dialogState{kind: kind}
	m.openModal(modalDialog)
}

func (m *Model) closeDialog() {
	m.dialog = dialogState{}
	m.closeModal()
}

func (m *Model) openPalette() {
	m.openDialog(dialogPalette)
	m.dialog.placeholder = "Search commands"
	options := []dialogOption{}
	if m.snapshot.SetupMode {
		options = append(options,
			dialogOption{title: "Switch model", right: "ctrl+x m", category: "Suggested", value: "models"},
			dialogOption{title: "Connect provider", category: "Suggested", value: "connect"},
			dialogOption{title: "Switch effort", category: "Suggested", value: "effort"},
			dialogOption{title: "Open settings", category: "Suggested", value: "settings"},
		)
	}
	options = append(options,
		dialogOption{title: "Open viewer", right: "ctrl+o", category: "System", value: "viewer"},
		dialogOption{title: "Help", right: "f1", category: "System", value: "help"},
		dialogOption{title: "Quit", right: "ctrl+c", category: "System", value: "quit"},
	)
	m.dialog.options = options
	m.dialog.refilter()
}

func (m *Model) openModels(filterProvider string) tea.Cmd {
	m.openDialog(dialogModels)
	m.dialog.placeholder = "Search models"
	m.dialog.loading = true
	m.dialog.filterProvider = filterProvider
	m.dialog.hints = []dialogHint{{"connect provider", "ctrl+a"}, {"favorite", "ctrl+f"}}
	return send(m.client, "models.list", map[string]any{})
}

func (m *Model) openProviders() tea.Cmd {
	m.openDialog(dialogProviders)
	m.dialog.title = "Connect a provider"
	m.dialog.placeholder = "Search"
	m.dialog.loading = true
	return send(m.client, "providers.list", map[string]any{})
}

func (m *Model) openEffort() {
	m.openDialog(dialogEffort)
	m.dialog.title = "Select effort"
	for index, effort := range efforts {
		current := effort == m.snapshot.Effort
		m.dialog.options = append(m.dialog.options, dialogOption{title: effort, value: effort, current: current})
		if current {
			m.dialog.cursor = index
		}
	}
	m.dialog.refilter()
}

func (m *Model) openSettings() {
	cursor := 0
	if m.dialog.kind == dialogSettings {
		cursor = m.dialog.cursor
	}
	m.openDialog(dialogSettings)
	m.dialog.placeholder = "Search settings"
	model := "none"
	if m.snapshot.Model != "" {
		model = m.snapshot.Model
		if runes := []rune(model); len(runes) > 34 {
			model = "…" + string(runes[len(runes)-33:])
		}
	}
	budget := "none"
	if m.snapshot.MaxBudgetUSD != nil {
		budget = fmt.Sprintf("$%.2f", *m.snapshot.MaxBudgetUSD)
	}
	m.dialog.options = []dialogOption{
		{title: "Model", right: model, category: "Model", value: "model", description: "Model the scan runs on"},
		{title: "Effort", right: m.snapshot.Effort, category: "Model", value: "effort", description: "How hard the model reasons"},
		{title: "Providers", category: "Model", value: "connect", description: "Connect or disconnect a provider"},
		{title: "Mode", right: m.snapshot.ScanMode, category: "Scan", value: "scan_mode", description: "How deep the scan goes"},
		{title: "Scope", right: m.snapshot.ScopeMode, category: "Scan", value: "scope_mode", description: "Whole target or only what changed"},
		{title: "Budget", right: budget, category: "Scan", value: "budget", description: "Stop the scan at this spend"},
	}
	m.dialog.cursor = cursor
	m.dialog.refilter()
}

func modelName(model, prefix string) string {
	return strings.TrimPrefix(model, prefix+"/")
}

func (d *dialogState) buildModelOptions() {
	names := map[string]string{}
	prefixes := map[string]string{}
	for _, provider := range d.picker.Providers {
		names[provider.ID] = provider.Name
		prefixes[provider.ID] = provider.Prefix
	}
	favorite := map[modelRef]bool{}
	for _, ref := range d.picker.Favorite {
		favorite[ref] = true
	}
	option := func(ref modelRef, category string, detail bool) (dialogOption, bool) {
		name, connected := names[ref.Provider]
		if !connected {
			return dialogOption{}, false
		}
		built := dialogOption{
			title:    modelName(ref.Model, prefixes[ref.Provider]),
			category: category,
			value:    ref.Model,
			provider: ref.Provider,
			favorite: favorite[ref],
			current:  d.picker.Current != nil && *d.picker.Current == ref,
		}
		if detail {
			built.detail = name
		}
		if built.favorite {
			built.right = "*"
		}
		return built, true
	}
	options := []dialogOption{}
	if d.filterProvider == "" {
		for _, ref := range d.picker.Favorite {
			if built, ok := option(ref, "Favorites", true); ok {
				options = append(options, built)
			}
		}
		for _, ref := range d.picker.Recent {
			if built, ok := option(ref, "Recent", true); ok && !favorite[ref] {
				options = append(options, built)
			}
		}
	}
	for _, provider := range d.picker.Providers {
		if d.filterProvider != "" && provider.ID != d.filterProvider {
			continue
		}
		for _, model := range provider.Models {
			built, _ := option(modelRef{Provider: provider.ID, Model: model}, provider.Name, false)
			options = append(options, built)
		}
	}
	d.options = options
	d.refilter()
}

func (d dialogState) customModel() (dialogOption, bool) {
	query := strings.TrimSpace(d.query)
	if d.kind != dialogModels || query == "" || len(d.visible) > 0 || strings.ContainsAny(query, " \t") {
		return dialogOption{}, false
	}
	var target *providerModels
	for index := range d.picker.Providers {
		provider := &d.picker.Providers[index]
		if strings.HasPrefix(query, provider.ID+"/") {
			return dialogOption{title: "Use " + query, value: query, provider: provider.ID}, true
		}
		if provider.ID == d.filterProvider || (d.filterProvider == "" && len(d.picker.Providers) == 1) {
			target = provider
		}
	}
	if target == nil {
		return dialogOption{}, false
	}
	model := query
	if !strings.HasPrefix(model, target.Prefix+"/") {
		model = target.Prefix + "/" + model
	}
	return dialogOption{title: "Use " + model, value: model, provider: target.ID}, true
}

func (d *dialogState) buildProviderOptions() {
	options := []dialogOption{}
	add := func(category string, entries []providerEntry) {
		for _, entry := range entries {
			option := dialogOption{title: entry.Name, category: category, value: entry.ID, connected: entry.Connected}
			if entry.Connected {
				option.right = "connected"
			}
			options = append(options, option)
		}
	}
	add("Popular", d.directory.Popular)
	add("Providers", d.directory.Providers)
	add("Local", d.directory.Local)
	add("Web search", d.directory.Search)
	d.options = options
	d.refilter()
	d.syncProviderHints()
}

func (d *dialogState) syncProviderHints() {
	d.hints = nil
	if option, ok := d.selected(); ok && option.connected {
		d.hints = []dialogHint{{"disconnect", "ctrl+d"}}
	}
}

func (d dialogState) findProvider(id string) (providerEntry, bool) {
	groups := [][]providerEntry{d.directory.Popular, d.directory.Providers, d.directory.Local}
	for _, group := range groups {
		for _, entry := range group {
			if entry.ID == id {
				return entry, true
			}
		}
	}
	for _, entry := range d.directory.Search {
		if entry.ID == id {
			entry.search = true
			return entry, true
		}
	}
	return providerEntry{}, false
}

func (m *Model) openKeyInput(provider providerEntry, apiBase string) {
	directory := m.dialog.directory
	m.openDialog(dialogKeyInput)
	m.dialog.directory = directory
	m.dialog.provider = provider
	m.dialog.apiBase = apiBase
	m.dialog.title = "Connect " + provider.Name
	m.dialog.placeholder = "API key"
	if provider.KeyOptional {
		m.dialog.placeholder = "API key (optional)"
	}
	m.dialog.secret = true
	m.dialog.hints = []dialogHint{{"submit", "enter"}}
}

func (m *Model) openBaseInput(provider providerEntry) {
	directory := m.dialog.directory
	m.openDialog(dialogBaseInput)
	m.dialog.directory = directory
	m.dialog.provider = provider
	m.dialog.title = "Connect " + provider.Name
	m.dialog.placeholder = "Base URL"
	m.dialog.query = provider.DefaultBase
	m.dialog.hints = []dialogHint{{"next", "enter"}}
}

func (m *Model) startConnect(provider providerEntry) tea.Cmd {
	if len(provider.Methods) > 1 {
		directory := m.dialog.directory
		m.openDialog(dialogMethods)
		m.dialog.directory = directory
		m.dialog.provider = provider
		m.dialog.title = "Connect " + provider.Name
		for _, method := range provider.Methods {
			m.dialog.options = append(m.dialog.options, dialogOption{title: method.Label, value: method.ID})
		}
		m.dialog.refilter()
		return nil
	}
	if provider.NeedsBase {
		m.openBaseInput(provider)
		return nil
	}
	m.openKeyInput(provider, "")
	return nil
}

func (m Model) updateDialog(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	dialog := &m.dialog
	switch key.String() {
	case "esc", "ctrl+c":
		return m.dismissDialog()
	case "up", "ctrl+p":
		if dialog.selectable() && len(dialog.visible) > 0 {
			dialog.cursor = (dialog.cursor - 1 + len(dialog.visible)) % len(dialog.visible)
			dialog.syncHints()
		}
		return m, nil
	case "down", "ctrl+n":
		if dialog.selectable() && len(dialog.visible) > 0 {
			dialog.cursor = (dialog.cursor + 1) % len(dialog.visible)
			dialog.syncHints()
		}
		return m, nil
	case "pgup":
		dialog.cursor = max(0, dialog.cursor-dialogMaxRows)
		dialog.syncHints()
		return m, nil
	case "pgdown":
		dialog.cursor = max(0, min(len(dialog.visible)-1, dialog.cursor+dialogMaxRows))
		dialog.syncHints()
		return m, nil
	case "enter":
		return m.submitDialog()
	case "ctrl+a":
		if dialog.kind == dialogModels {
			cmd := m.openProviders()
			return m, cmd
		}
		return m, nil
	case "ctrl+f":
		if option, ok := dialog.selected(); ok && dialog.kind == dialogModels {
			return m, send(m.client, "models.favorite", map[string]any{"provider": option.provider, "model": option.value})
		}
		return m, nil
	case "ctrl+d":
		if option, ok := dialog.selected(); ok && dialog.kind == dialogProviders && option.connected {
			dialog.loading = true
			return m, send(m.client, "providers.disconnect", map[string]any{"provider": option.value})
		}
		return m, nil
	case "backspace":
		if runes := []rune(dialog.query); len(runes) > 0 {
			dialog.setQuery(string(runes[:len(runes)-1]))
		}
		return m, nil
	case "ctrl+u":
		dialog.setQuery("")
		return m, nil
	}
	if key.Type == tea.KeyRunes || key.Type == tea.KeySpace {
		if dialog.kind == dialogMethods || dialog.kind == dialogEffort || dialog.kind == dialogLogin {
			return m, nil
		}
		text := strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, string(key.Runes))
		dialog.setQuery(dialog.query + text)
	}
	return m, nil
}

func (d *dialogState) setQuery(query string) {
	d.query = query
	d.errorText = ""
	if d.selectable() {
		d.cursor = 0
		d.refilter()
		d.syncHints()
	}
}

func (d *dialogState) syncHints() {
	if d.kind == dialogProviders {
		d.syncProviderHints()
	}
}

func (m Model) dismissDialog() (tea.Model, tea.Cmd) {
	switch m.dialog.kind {
	case dialogLogin:
		cmd := send(m.client, "providers.login_cancel", map[string]any{})
		m.closeDialog()
		return m, cmd
	case dialogMethods, dialogBaseInput, dialogKeyInput:
		cmd := m.openProviders()
		return m, cmd
	case dialogBudget:
		m.openSettings()
		return m, nil
	}
	m.closeDialog()
	return m, nil
}

func (m Model) submitDialog() (tea.Model, tea.Cmd) {
	dialog := &m.dialog
	query := strings.TrimSpace(dialog.query)
	switch dialog.kind {
	case dialogBaseInput:
		if query == "" {
			dialog.errorText = "Base URL is required"
			return m, nil
		}
		m.openKeyInput(dialog.provider, query)
		return m, nil
	case dialogKeyInput:
		if query == "" && !dialog.provider.KeyOptional {
			dialog.errorText = "API key is required"
			return m, nil
		}
		dialog.loading = true
		dialog.errorText = ""
		return m, send(m.client, "providers.connect", map[string]any{
			"provider": dialog.provider.ID, "api_key": query, "api_base": dialog.apiBase,
		})
	case dialogBudget:
		dialog.errorText = ""
		return m, send(m.client, "settings.set", map[string]any{"name": "max_budget_usd", "value": query})
	case dialogLogin:
		return m, nil
	}
	option, ok := dialog.selected()
	if !ok {
		if custom, found := dialog.customModel(); found {
			option, ok = custom, true
		}
	}
	if !ok {
		return m, nil
	}
	switch dialog.kind {
	case dialogPalette:
		return m.runCommand(option.value)
	case dialogModels:
		m.closeDialog()
		return m, send(m.client, "models.select", map[string]any{"provider": option.provider, "model": option.value})
	case dialogProviders:
		provider, found := dialog.findProvider(option.value)
		if !found {
			return m, nil
		}
		cmd := m.startConnect(provider)
		return m, cmd
	case dialogMethods:
		if option.value == "chatgpt" {
			provider := dialog.provider
			m.openDialog(dialogLogin)
			m.dialog.provider = provider
			m.dialog.title = "Sign in with ChatGPT"
			m.dialog.loading = true
			return m, send(m.client, "providers.login", map[string]any{})
		}
		m.openKeyInput(dialog.provider, "")
		return m, nil
	case dialogEffort:
		m.closeDialog()
		return m, send(m.client, "settings.set", map[string]any{"name": "effort", "value": option.value})
	case dialogSettings:
		return m.activateSetting(option.value)
	}
	return m, nil
}

func nextValue(values []string, current string) string {
	for index, value := range values {
		if value == current {
			return values[(index+1)%len(values)]
		}
	}
	return values[0]
}

func (m Model) activateSetting(name string) (tea.Model, tea.Cmd) {
	switch name {
	case "model":
		cmd := m.openModels("")
		return m, cmd
	case "effort":
		m.openEffort()
		return m, nil
	case "connect":
		cmd := m.openProviders()
		return m, cmd
	case "scan_mode":
		return m, send(m.client, "settings.set", map[string]any{"name": name, "value": nextValue(scanModes, m.snapshot.ScanMode)})
	case "scope_mode":
		return m, send(m.client, "settings.set", map[string]any{"name": name, "value": nextValue(scopeModes, m.snapshot.ScopeMode)})
	case "budget":
		m.openDialog(dialogBudget)
		m.dialog.title = "Budget"
		m.dialog.placeholder = "Amount in USD, empty for none"
		if m.snapshot.MaxBudgetUSD != nil {
			m.dialog.query = fmt.Sprintf("%.2f", *m.snapshot.MaxBudgetUSD)
		}
		m.dialog.hints = []dialogHint{{"save", "enter"}}
	}
	return m, nil
}

func (m Model) runCommand(name string) (tea.Model, tea.Cmd) {
	switch name {
	case "models":
		cmd := m.openModels("")
		return m, cmd
	case "connect":
		cmd := m.openProviders()
		return m, cmd
	case "effort":
		m.openEffort()
		return m, nil
	case "settings":
		m.openSettings()
		return m, nil
	case "viewer":
		m.closeDialog()
		return m, send(m.client, "viewer.open", map[string]any{})
	case "help":
		m.closeDialog()
		m.openModal(modalHelp)
		return m, nil
	case "quit":
		m.closeDialog()
		m.quitting = true
		return m, tea.Batch(send(m.client, "app.quit", map[string]any{}), tea.Quit)
	}
	return m, nil
}

func isDialogCommand(command string) bool {
	return strings.HasPrefix(command, "models.") || strings.HasPrefix(command, "providers.") || command == "settings.set"
}

func (m *Model) dialogCommandFailed(command, message string) bool {
	if !isDialogCommand(command) || m.modal != modalDialog {
		return false
	}
	m.dialog.loading = false
	m.dialog.errorText = message
	return true
}

func (m *Model) handleDialogResult(result protocol.CommandResult) tea.Cmd {
	dialog := &m.dialog
	open := m.modal == modalDialog
	switch result.Command {
	case "models.list":
		if !open || dialog.kind != dialogModels {
			return nil
		}
		_ = json.Unmarshal(result.Result, &dialog.picker)
		dialog.loading = false
		if len(dialog.picker.Providers) == 0 {
			return m.openProviders()
		}
		dialog.buildModelOptions()
		for index, visible := range dialog.visible {
			if dialog.options[visible].current {
				dialog.cursor = index
				break
			}
		}
	case "models.favorite":
		if !open || dialog.kind != dialogModels {
			return nil
		}
		var data struct {
			modelRef
			Favorite bool `json:"favorite"`
		}
		_ = json.Unmarshal(result.Result, &data)
		kept := dialog.picker.Favorite[:0:0]
		for _, ref := range dialog.picker.Favorite {
			if ref != data.modelRef {
				kept = append(kept, ref)
			}
		}
		if data.Favorite {
			kept = append(kept, data.modelRef)
		}
		dialog.picker.Favorite = kept
		selected, _ := dialog.selected()
		dialog.buildModelOptions()
		for index, visible := range dialog.visible {
			option := dialog.options[visible]
			if option.value == selected.value && option.provider == selected.provider {
				dialog.cursor = index
				break
			}
		}
	case "models.select":
		var data modelRef
		_ = json.Unmarshal(result.Result, &data)
		return m.showToast("Model set to " + data.Model)
	case "providers.list":
		if !open || dialog.kind != dialogProviders {
			return nil
		}
		_ = json.Unmarshal(result.Result, &dialog.directory)
		dialog.loading = false
		dialog.buildProviderOptions()
	case "providers.connect":
		var data struct {
			Provider string `json:"provider"`
			Name     string `json:"name"`
		}
		_ = json.Unmarshal(result.Result, &data)
		toast := m.showToast("Connected " + data.Name)
		if open && dialog.provider.search {
			m.closeDialog()
			return toast
		}
		return tea.Batch(toast, m.openModels(data.Provider))
	case "providers.disconnect":
		if open && dialog.kind == dialogProviders {
			return send(m.client, "providers.list", map[string]any{})
		}
	case "providers.login":
		if !open || dialog.kind != dialogLogin {
			return nil
		}
		var data struct {
			URL string `json:"url"`
		}
		_ = json.Unmarshal(result.Result, &data)
		dialog.loading = false
		dialog.note = data.URL
	case "settings.set":
		var data struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}
		_ = json.Unmarshal(result.Result, &data)
		if open && dialog.kind == dialogBudget {
			m.dialog = dialogState{kind: dialogSettings, cursor: 5}
			m.openSettings()
		}
		if data.Name == "effort" {
			return m.showToast("Effort set to " + data.Value)
		}
	}
	return nil
}

func (m *Model) syncDialogSnapshot() tea.Cmd {
	if m.modal != modalDialog {
		return nil
	}
	switch m.dialog.kind {
	case dialogSettings:
		query, cursor := m.dialog.query, m.dialog.cursor
		m.openSettings()
		m.dialog.setQuery(query)
		m.dialog.cursor = max(0, min(cursor, len(m.dialog.visible)-1))
	case dialogLogin:
		switch m.snapshot.LoginState {
		case "done":
			return tea.Batch(m.showToast("Connected ChatGPT"), m.openModels("chatgpt"))
		case "error":
			m.dialog.loading = false
			m.dialog.errorText = m.snapshot.LoginError
		}
	}
	return nil
}

func (m Model) dialogInnerWidth() int {
	return max(20, min(dialogWidth, m.width-4))
}

func (m Model) dialogListRows() int {
	return max(4, min(dialogMaxRows, m.height-12))
}

type dialogRow struct {
	header string
	blank  bool
	option int
}

func (d dialogState) rows() []dialogRow {
	rows := []dialogRow{}
	category := ""
	grouped := strings.TrimSpace(d.query) == ""
	for position, index := range d.visible {
		option := d.options[index]
		if grouped && option.category != category {
			category = option.category
			if len(rows) > 0 {
				rows = append(rows, dialogRow{blank: true})
			}
			if category != "" {
				rows = append(rows, dialogRow{header: category})
			}
		}
		rows = append(rows, dialogRow{option: position + 1})
	}
	return rows
}

func dialogLine(width int, background lipgloss.Color, left, right string) string {
	fill := lipgloss.NewStyle().Background(background)
	gap := width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		left = ansi.Truncate(left, max(0, width-lipgloss.Width(right)-1), "")
		gap = max(0, width-lipgloss.Width(left)-lipgloss.Width(right))
	}
	return left + fill.Render(strings.Repeat(" ", gap)) + right
}

func (m Model) dialogView() string {
	dialog := m.dialog
	width := m.dialogInnerWidth()
	inner := width - 2*dialogPadding
	paint := func(background lipgloss.Color, foreground lipgloss.Color, bold bool) func(...string) string {
		return lipgloss.NewStyle().Background(background).Foreground(foreground).Bold(bold).Render
	}
	pad := paint(dialogBg, textColor, false)(strings.Repeat(" ", dialogPadding))
	blank := paint(dialogBg, textColor, false)(strings.Repeat(" ", width))
	body := func(left, right string) string {
		return pad + dialogLine(inner, dialogBg, left, right) + pad
	}
	lines := []string{blank}
	if dialog.title != "" {
		lines = append(lines, body(paint(dialogBg, brightWhite, true)(dialog.title), paint(dialogBg, dim, false)("esc")), blank)
	}
	if dialog.kind != dialogMethods && dialog.kind != dialogEffort && dialog.kind != dialogLogin {
		shown := dialog.query
		if dialog.secret {
			shown = strings.Repeat("•", len([]rune(dialog.query)))
		}
		cursor := lipgloss.NewStyle().Background(mid).Foreground(black)
		var input string
		if shown == "" {
			placeholder := []rune(dialog.placeholder)
			input = cursor.Render(string(placeholder[:1])) + paint(dialogBg, dim, false)(string(placeholder[1:]))
		} else {
			if lipgloss.Width(shown) > inner-6 {
				shown = ansi.TruncateLeft(shown, lipgloss.Width(shown)-(inner-6), "")
			}
			input = paint(dialogBg, white, false)(shown) + cursor.Render(" ")
		}
		right := ""
		if dialog.title == "" {
			right = paint(dialogBg, dim, false)("esc")
		}
		lines = append(lines, body(input, right), blank)
	}
	switch {
	case dialog.loading:
		lines = append(lines, body(paint(dialogBg, dim, false)("Loading…"), ""), blank)
	case dialog.kind == dialogLogin:
		lines = append(lines, body(paint(dialogBg, textColor, false)("Finish signing in in your browser"), ""), blank)
		for _, row := range strings.Split(ansi.Hardwrap(dialog.note, inner, true), "\n") {
			lines = append(lines, body(paint(dialogBg, lightBlue, false)(row), ""))
		}
		lines = append(lines, blank)
	case dialog.selectable():
		lines = append(lines, m.dialogListLines(width)...)
		lines = append(lines, blank)
	}
	if dialog.errorText != "" {
		for _, row := range strings.Split(ansi.Wordwrap(dialog.errorText, inner, ""), "\n") {
			lines = append(lines, body(paint(dialogBg, red, false)(row), ""))
		}
		lines = append(lines, blank)
	}
	footer := m.dialogFooter(inner)
	if footer != "" {
		footerPad := paint(dialogFooterBg, textColor, false)(strings.Repeat(" ", dialogPadding))
		footerBlank := paint(dialogFooterBg, textColor, false)(strings.Repeat(" ", width))
		lines = append(lines, footerBlank, footerPad+footer+footerPad, footerBlank)
	}
	return strings.Join(lines, "\n")
}

func (m Model) dialogFooter(inner int) string {
	dialog := m.dialog
	label := lipgloss.NewStyle().Background(dialogFooterBg).Foreground(white).Render
	keyStyle := lipgloss.NewStyle().Background(dialogFooterBg).Foreground(dim).Render
	if len(dialog.hints) > 0 {
		parts := make([]string, 0, len(dialog.hints))
		for _, hint := range dialog.hints {
			parts = append(parts, label(hint.label)+keyStyle(" "+hint.key))
		}
		if len(parts) == 1 {
			return dialogLine(inner, dialogFooterBg, "", parts[0])
		}
		return dialogLine(inner, dialogFooterBg, parts[0], parts[len(parts)-1])
	}
	if option, ok := dialog.selected(); ok && option.description != "" {
		return dialogLine(inner, dialogFooterBg, keyStyle(option.description), "")
	}
	return ""
}

func (m Model) dialogListLines(width int) []string {
	dialog := m.dialog
	inner := width - 2*dialogPadding
	plain := lipgloss.NewStyle().Background(dialogBg)
	pad := plain.Render(strings.Repeat(" ", dialogPadding))
	if len(dialog.visible) == 0 {
		text := "No results"
		if custom, ok := dialog.customModel(); ok {
			row := lipgloss.NewStyle().Background(dialogSelectBg)
			return []string{
				lipgloss.NewStyle().Background(dialogSelectBg).Foreground(green).Render("┃") +
					row.Render(strings.Repeat(" ", dialogPadding-1)) +
					dialogLine(inner, dialogSelectBg, row.Foreground(brightWhite).Render(custom.title), "") +
					row.Render(strings.Repeat(" ", dialogPadding)),
			}
		}
		return []string{pad + dialogLine(inner, dialogBg, plain.Foreground(dim).Render(text), "") + pad}
	}
	rows := dialog.rows()
	limit := m.dialogListRows()
	cursorRow := 0
	for index, row := range rows {
		if row.option == dialog.cursor+1 {
			cursorRow = index
		}
	}
	start := 0
	if len(rows) > limit {
		start = max(0, min(len(rows)-limit, cursorRow-limit/2))
		if cursorRow < limit-2 {
			start = 0
		}
	}
	end := min(len(rows), start+limit)
	lines := make([]string, 0, end-start)
	for _, row := range rows[start:end] {
		switch {
		case row.blank:
			lines = append(lines, plain.Render(strings.Repeat(" ", width)))
		case row.header != "":
			lines = append(lines, pad+dialogLine(inner, dialogBg, plain.Foreground(dim).Bold(true).Render(row.header), "")+pad)
		default:
			option := dialog.options[dialog.visible[row.option-1]]
			selected := row.option-1 == dialog.cursor
			background := dialogBg
			if selected {
				background = dialogSelectBg
			}
			style := lipgloss.NewStyle().Background(background)
			bar := style.Render(" ")
			if selected {
				bar = style.Foreground(green).Render("┃")
			}
			marker := style.Render("  ")
			if option.current {
				marker = style.Foreground(green).Render("▪ ")
			}
			left := style.Foreground(white).Render(option.title)
			if option.detail != "" {
				left += style.Foreground(dim).Render(" " + option.detail)
			}
			rightColor := dim
			if option.connected {
				rightColor = green
			}
			right := style.Foreground(rightColor).Render(option.right)
			lines = append(lines, bar+style.Render(" ")+marker+dialogLine(inner, background, left, right)+style.Render(strings.Repeat(" ", dialogPadding)))
		}
	}
	return lines
}
