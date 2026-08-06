package render

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// Shell renderer (shell_renderer.py)
// ---------------------------------------------------------------------------

const (
	maxOutputLines = 50
	maxLineLength  = 200
)

var (
	exitRE    = regexp.MustCompile(`Process exited with code (-?\d+)`)
	sessionRE = regexp.MustCompile(`Process running with session ID (\d+)`)
	stripRE   = regexp.MustCompile(`(?m)^(Chunk ID: [0-9a-f]+|Wall time: [\d.]+ seconds|Process exited with code -?\d+|Process running with session ID \d+|Original token count: \d+)\s*$`)
)

const outputHeader = "\nOutput:\n"

type shellParsed struct {
	content     string
	exitCode    int
	hasExitCode bool
}

func parseShellResult(result any) shellParsed {
	if m, ok := result.(map[string]any); ok {
		p := shellParsed{content: StringValue(m["content"])}
		if code, ok := NumericValue(m["exit_code"]); ok {
			p.exitCode, p.hasExitCode = int(code), true
		}
		return p
	}
	s, ok := result.(string)
	if !ok {
		if result == nil {
			return shellParsed{}
		}
		return shellParsed{content: StringValue(result)}
	}
	p := shellParsed{}
	if m := exitRE.FindStringSubmatch(s); m != nil {
		fmt.Sscanf(m[1], "%d", &p.exitCode)
		p.hasExitCode = true
	}
	if idx := strings.Index(s, outputHeader); idx >= 0 {
		p.content = s[idx+len(outputHeader):]
	} else {
		p.content = s
	}
	return p
}

func cleanShellOutput(output string) string {
	cleaned := stripControlsKeepTabs(output)
	cleaned = stripRE.ReplaceAllString(cleaned, "")
	if strings.TrimSpace(cleaned) == "" {
		return ""
	}
	lines := strings.Split(cleaned, "\n")
	var filtered []string
	for _, line := range lines {
		if len(filtered) == 0 && strings.TrimSpace(line) == "" {
			continue
		}
		if strings.TrimSpace(line) == "Output:" {
			continue
		}
		filtered = append(filtered, line)
	}
	for len(filtered) > 0 && strings.TrimSpace(filtered[len(filtered)-1]) == "" {
		filtered = filtered[:len(filtered)-1]
	}
	return strings.TrimSpace(strings.Join(filtered, "\n"))
}

func truncateShellLine(line string) string {
	if len(line) > maxLineLength {
		return line[:maxLineLength-3] + "..."
	}
	return line
}

// formatShellOutput ports _format_output (head/tail truncation with a middle marker).
func formatShellOutput(output string) string {
	lines := strings.Split(output, "\n")
	total := len(lines)
	head := maxOutputLines / 2
	tail := maxOutputLines - head - 1

	var b strings.Builder
	if total <= maxOutputLines {
		for i, line := range lines {
			b.WriteString("  " + Dim().Render(truncateShellLine(line)))
			if i < len(lines)-1 {
				b.WriteString("\n")
			}
		}
		return b.String()
	}

	display := lines[:head]
	hidden := total - head - tail
	for _, line := range display {
		b.WriteString("  " + Dim().Render(truncateShellLine(line)) + "\n")
	}
	b.WriteString(Dim().Italic(true).Render(fmt.Sprintf("  ... %d lines truncated ...", hidden)) + "\n")
	tailLines := lines[total-tail:]
	for i, line := range tailLines {
		b.WriteString("  " + Dim().Render(truncateShellLine(line)))
		if i < len(tailLines)-1 {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func appendShellOutput(b *strings.Builder, p shellParsed, status string) {
	output := cleanShellOutput(p.content)
	if status == "running" {
		if output != "" {
			b.WriteString("\n" + formatShellOutput(output))
		}
		return
	}
	if output == "" {
		if p.hasExitCode && p.exitCode != 0 {
			b.WriteString("\n" + Col(Red).Faint(true).Render(fmt.Sprintf("  exit %d", p.exitCode)))
		}
		return
	}
	b.WriteString("\n" + formatShellOutput(output))
	if p.hasExitCode && p.exitCode != 0 {
		b.WriteString("\n" + Col(Red).Faint(true).Render(fmt.Sprintf("  exit %d", p.exitCode)))
	}
}

func renderTerminal(prompt string, promptColor lipgloss.Color, command string, result any, status, meta string) string {
	var b strings.Builder
	b.WriteString(Dim().Render(">_") + " ")
	if strings.TrimSpace(command) == "" {
		b.WriteString(Dim().Render("getting logs..."))
	} else {
		b.WriteString(Col(promptColor).Render(prompt) + " " + command)
	}
	if meta != "" {
		b.WriteString(Dim().Render("  " + meta))
	}
	if result != nil {
		appendShellOutput(&b, parseShellResult(result), status)
	}
	return b.String()
}

func renderExecCommand(args map[string]any, result any, status string) string {
	cmd := StringValue(args["cmd"])
	var metaParts []string
	if wd := StringValue(args["workdir"]); wd != "" {
		metaParts = append(metaParts, "cwd:"+wd)
	}
	if b, ok := args["tty"].(bool); ok && b {
		metaParts = append(metaParts, "tty")
	}
	meta := strings.Join(metaParts, ", ")
	return renderTerminal("$", Green, HighlightCode(cmd, "bash"), result, status, meta)
}

func renderWriteStdin(args map[string]any, result any, status string) string {
	chars := StringValue(args["chars"])
	meta := ""
	if sid, ok := args["session_id"]; ok && sid != nil {
		meta = "session #" + StringValue(sid)
	}
	return renderTerminal(">>>", Blue, chars, result, status, meta)
}
