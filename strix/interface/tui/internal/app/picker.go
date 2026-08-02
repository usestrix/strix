package app

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
	"github.com/usestrix/strix/tui/internal/render"
)

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

// applyProviderRecord folds one provider status record from the backend
// into the setup screen's provider catalog and current selection.
func (m *Model) applyProviderRecord(data protocol.Provider) {
	if data.Name != "" {
		m.configProvider = data.Name
	}
	if data.Label != "" {
		m.configProviderLabel = data.Label
	}
	m.configProviderState, m.configProviderDetail = data.State, data.Detail
	m.providerConfigured[data.Name] = data.Configured
	m.providerLabels[data.Name] = data.Label
	m.providerStates[data.Name] = data.State
	m.providerDetails[data.Name] = data.Detail
	m.providerDisconnectable[data.Name] = data.Disconnectable
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
