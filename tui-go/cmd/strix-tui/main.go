package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/usestrix/strix/tui/internal/app"
)

func main() {
	app.SetVersion(os.Getenv("STRIX_VERSION"))
	client, err := app.ConnectFromEnvironment()
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect to Strix backend:", err)
		os.Exit(1)
	}
	defer client.Close()
	if err := client.Handshake(); err != nil {
		fmt.Fprintln(os.Stderr, "negotiate Strix TUI protocol:", err)
		os.Exit(1)
	}
	if len(os.Args) > 1 && os.Args[1] == "--handshake-smoke" {
		if err := client.ProtocolSmoke(); err != nil {
			fmt.Fprintln(os.Stderr, "exercise Strix TUI protocol:", err)
			os.Exit(1)
		}
		return
	}
	program := tea.NewProgram(app.New(client), tea.WithAltScreen(), tea.WithMouseCellMotion())
	finalModel, err := program.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "run TUI:", err)
		os.Exit(1)
	}
	if model, ok := finalModel.(interface{ FatalError() error }); ok && model.FatalError() != nil {
		fmt.Fprintln(os.Stderr, "run TUI:", model.FatalError())
		os.Exit(1)
	}
}
