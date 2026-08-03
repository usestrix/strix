package app

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func (m *Model) openPicker(mode pickerMode) {
	m.picker, m.cursor = mode, 0
	m.input.Blur()
	m.pickerInput.SetValue("")
	m.pickerInput.Focus()
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

// pickerPlaceholder returns the search placeholder for the current picker.
func (m Model) pickerPlaceholder() string {
	return "Search scan modes..."
}

func (m Model) updatePicker(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "esc":
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
	case "enter":
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
	selected := m.filtered[index]
	m.closePicker()
	return m, send(m.client, "setup.set_mode", map[string]any{"mode": selected})
}

func (m *Model) filterOptions() {
	query := strings.ToLower(strings.TrimSpace(m.pickerInput.Value()))
	m.filtered = m.filtered[:0]
	for _, option := range m.options {
		if query == "" || strings.Contains(strings.ToLower(option), query) {
			m.filtered = append(m.filtered, option)
		}
	}
	if m.cursor >= len(m.filtered) {
		m.cursor = max(0, len(m.filtered)-1)
	}
}

func (m Model) pickerView() string {
	const interior = 64
	// The picker search box is always focused while open, so its border is green
	// (#picker_search:focus) over the #0a0a0a input background. The placeholder is
	// rendered here rather than on the input model so it never becomes its value.
	inner := m.pickerInput.View()
	if m.pickerInput.Value() == "" {
		inner = lipgloss.NewStyle().Foreground(lipgloss.Color("#525252")).Render(m.pickerPlaceholder())
	}
	search := lipgloss.NewStyle().Width(interior - 2).Border(lipgloss.RoundedBorder()).BorderForeground(green).Background(lipgloss.Color("#0a0a0a")).PaddingLeft(1).Render(inner)

	content := lipgloss.NewStyle().Bold(true).Foreground(green).Render("Select scan mode")
	content += "\n\n" + search + "\n"
	if len(m.filtered) == 0 {
		content += "\n" + lipgloss.NewStyle().Foreground(dim).Render(" No matches")
	} else {
		start, end := optionWindow(m.cursor, len(m.filtered), 18)
		for i := start; i < end; i++ {
			label := truncate(m.filtered[i], interior-2)
			if i == m.cursor {
				label = lipgloss.NewStyle().Background(lipgloss.Color("#15803d")).Foreground(brightWhite).Width(interior).Render(" " + label)
			} else {
				label = " " + label
			}
			content += "\n" + label
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
