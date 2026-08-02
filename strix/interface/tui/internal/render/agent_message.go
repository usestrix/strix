package render

import (
	"regexp"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// Markdown (agent_message_renderer.py)
// ---------------------------------------------------------------------------

var blankLineRuns = regexp.MustCompile(`\n\s*\n`)

type mdHeader struct {
	prefix string
	strip  int
	style  lipgloss.Style
}

var mdHeaders = []mdHeader{
	{"###### ", 7, Bold(Field)},
	{"##### ", 6, Bold(Green)},
	{"#### ", 5, Bold(Hdr16a)},
	{"### ", 4, Bold(Hdr158)},
	{"## ", 3, Bold(Green)},
	{"# ", 2, Bold(Field)},
}

// renderAssistantMarkdown ports AgentMessageRenderer.render_simple + helpers.
func renderAssistantMarkdown(content string) string {
	if content == "" {
		return ""
	}
	cleaned := strings.TrimSpace(blankLineRuns.ReplaceAllString(content, "\n\n"))
	if cleaned == "" {
		return ""
	}
	return applyMarkdownStyles(cleaned)
}

func applyMarkdownStyles(text string) string {
	var out strings.Builder
	lines := strings.Split(text, "\n")

	inCode := false
	var codeLines []string

	flushCode := func() {
		if len(codeLines) > 0 {
			out.WriteString(Col(Text).Render(strings.Join(codeLines, "\n")))
		}
		codeLines = nil
	}

	for i, line := range lines {
		if i > 0 && !inCode {
			out.WriteString("\n")
		}

		if strings.HasPrefix(line, "```") {
			if !inCode {
				inCode = true
				codeLines = nil
				if i > 0 {
					out.WriteString("\n")
				}
			} else {
				inCode = false
				flushCode()
			}
			continue
		}

		if inCode {
			codeLines = append(codeLines, line)
			continue
		}

		if h := tryHeader(line); h != nil {
			out.WriteString(h.style.Render(line[h.strip:]))
			continue
		}
		switch {
		case strings.HasPrefix(line, "> "):
			out.WriteString(Col(Green).Render("┃ ") + inlineFormat(line[2:]))
		case strings.HasPrefix(line, "- "), strings.HasPrefix(line, "* "):
			out.WriteString(Col(Green).Render("• ") + inlineFormat(line[2:]))
		case len(line) > 2 && line[0] >= '0' && line[0] <= '9' && (line[1:3] == ". " || line[1:3] == ") "):
			out.WriteString(Col(Green).Render(string(line[0])+". ") + inlineFormat(line[2:]))
		case line == "---" || line == "***" || line == "___":
			out.WriteString(Col(Green).Render(strings.Repeat("─", 40)))
		default:
			out.WriteString(inlineFormat(line))
		}
	}

	if inCode && len(codeLines) > 0 {
		flushCode()
	}
	return out.String()
}

func tryHeader(line string) *mdHeader {
	for i := range mdHeaders {
		if strings.HasPrefix(line, mdHeaders[i].prefix) {
			return &mdHeaders[i]
		}
	}
	return nil
}

// inlineFormat ports _process_inline_formatting.
func inlineFormat(line string) string {
	var out strings.Builder
	i, n := 0, len(line)
	for i < n {
		if i+1 < n && (line[i:i+2] == "**" || line[i:i+2] == "__") {
			marker := line[i : i+2]
			if end := strings.Index(line[i+2:], marker); end != -1 {
				end += i + 2
				out.WriteString(Bold(Field).Render(line[i+2 : end]))
				i = end + 2
				continue
			}
		}
		if i+1 < n && line[i:i+2] == "~~" {
			if end := strings.Index(line[i+2:], "~~"); end != -1 {
				end += i + 2
				out.WriteString(lipgloss.NewStyle().Strikethrough(true).Foreground(Strike).Render(line[i+2 : end]))
				i = end + 2
				continue
			}
		}
		if line[i] == '`' {
			if end := strings.Index(line[i+1:], "`"); end != -1 {
				end += i + 1
				out.WriteString(lipgloss.NewStyle().Bold(true).Foreground(Green).Background(CodeBg).Render(line[i+1 : end]))
				i = end + 1
				continue
			}
		}
		if line[i] == '*' || line[i] == '_' {
			marker := line[i]
			if i+1 < n && line[i+1] != marker {
				if end := strings.IndexByte(line[i+1:], marker); end != -1 {
					end += i + 1
					if end+1 >= n || line[end+1] != marker {
						out.WriteString(lipgloss.NewStyle().Italic(true).Foreground(Mint).Render(line[i+1 : end]))
						i = end + 1
						continue
					}
				}
			}
		}
		out.WriteByte(line[i])
		i++
	}
	return out.String()
}
