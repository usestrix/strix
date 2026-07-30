package main

import (
	"bytes"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

type quitModel struct{}

func (quitModel) Init() tea.Cmd                       { return tea.Quit }
func (quitModel) Update(tea.Msg) (tea.Model, tea.Cmd) { return quitModel{}, nil }
func (quitModel) View() string                        { return "" }

func TestProgramOptionsDoNotEnableMouseReporting(t *testing.T) {
	var output bytes.Buffer
	options := append(programOptions(), tea.WithInput(nil), tea.WithOutput(&output))
	program := tea.NewProgram(quitModel{}, options...)
	if _, err := program.Run(); err != nil {
		t.Fatal(err)
	}

	for _, sequence := range []string{"\x1b[?1002h", "\x1b[?1003h", "\x1b[?1006h"} {
		if strings.Contains(output.String(), sequence) {
			t.Fatalf("program enabled terminal mouse reporting with %q", sequence)
		}
	}
}
