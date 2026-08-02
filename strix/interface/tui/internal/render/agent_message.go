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
	codeLang := ""
	var codeLines []string

	flushCode := func() {
		if len(codeLines) > 0 {
			out.WriteString(HighlightCode(strings.Join(codeLines, "\n"), codeLang))
		}
		codeLines = nil
		codeLang = ""
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if i > 0 && !inCode {
			out.WriteString("\n")
		}

		if !inCode {
			if rows := tableRows(lines[i:]); rows > 0 {
				out.WriteString(renderMarkdownTable(lines[i : i+rows]))
				i += rows - 1
				continue
			}
		}

		if strings.HasPrefix(line, "```") {
			if !inCode {
				inCode = true
				codeLines = nil
				codeLang = strings.TrimSpace(strings.TrimPrefix(line, "```"))
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

func isTableRow(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "|") && strings.Count(trimmed, "|") >= 2
}

var tableSeparatorCell = regexp.MustCompile(`^:?-+:?$`)

func isTableSeparator(line string) bool {
	if !isTableRow(line) {
		return false
	}
	cells := splitTableRow(line)
	if len(cells) == 0 {
		return false
	}
	for _, cell := range cells {
		if !tableSeparatorCell.MatchString(strings.TrimSpace(cell)) {
			return false
		}
	}
	return true
}

// tableRows returns how many leading lines form a markdown table (header,
// separator, then body rows), or 0 when the block is not a table.
func tableRows(lines []string) int {
	if len(lines) < 2 || !isTableRow(lines[0]) || !isTableSeparator(lines[1]) {
		return 0
	}
	rows := 2
	for rows < len(lines) && isTableRow(lines[rows]) && !isTableSeparator(lines[rows]) {
		rows++
	}
	return rows
}

func splitTableRow(line string) []string {
	trimmed := strings.TrimSpace(line)
	trimmed = strings.TrimPrefix(trimmed, "|")
	trimmed = strings.TrimSuffix(trimmed, "|")
	cells := strings.Split(trimmed, "|")
	for i := range cells {
		cells[i] = strings.TrimSpace(cells[i])
	}
	return cells
}

// renderMarkdownTable draws a column-aligned table: bold header, a rule under
// it, and inline-formatted body cells.
func renderMarkdownTable(lines []string) string {
	headerStyle := func(cell string) string { return Bold(Field).Render(cell) }
	rows := make([][]string, 0, len(lines)-1)
	styleCells := func(line string, style func(string) string) []string {
		cells := splitTableRow(line)
		for i := range cells {
			cells[i] = style(cells[i])
		}
		return cells
	}
	rows = append(rows, styleCells(lines[0], headerStyle))
	for _, line := range lines[2:] {
		rows = append(rows, styleCells(line, inlineFormat))
	}

	widths := make([]int, len(rows[0]))
	for _, cells := range rows {
		for i, cell := range cells {
			if i < len(widths) {
				widths[i] = max(widths[i], lipgloss.Width(cell))
			}
		}
	}

	formatRow := func(cells []string) string {
		parts := make([]string, len(widths))
		for i := range widths {
			cell := ""
			if i < len(cells) {
				cell = cells[i]
			}
			parts[i] = cell + strings.Repeat(" ", max(0, widths[i]-lipgloss.Width(cell)))
		}
		return strings.TrimRight(strings.Join(parts, Dim().Render(" │ ")), " ")
	}

	out := []string{formatRow(rows[0])}
	rule := make([]string, len(widths))
	for i, width := range widths {
		rule[i] = strings.Repeat("─", width)
	}
	out = append(out, Dim().Render(strings.Join(rule, "─┼─")))
	for _, cells := range rows[1:] {
		out = append(out, formatRow(cells))
	}
	return strings.Join(out, "\n")
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
