package app

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// This file ports the Python Textual/Rich renderers
// (strix/interface/tui/renderers/*.py and utils.py) as faithfully as possible
// so the Go chat/tool output matches the reference TUI glyph-for-glyph and
// color-for-color. Rich's "dim" attribute maps to lipgloss Faint; Rich named
// styles map to the exact hex the Python code emits.

// Colors used by the renderers, matching the Python hex values exactly.
var (
	cField     = lipgloss.Color("#4ade80") // FIELD_STYLE base (bold)
	cReportHdr = lipgloss.Color("#ea580c") // report title / orange
	cSevCrit   = lipgloss.Color("#dc2626")
	cSevHigh   = lipgloss.Color("#ea580c")
	cSevMed    = lipgloss.Color("#d97706")
	cSevLow    = lipgloss.Color("#65a30d")
	cSevInfo   = lipgloss.Color("#0284c7")
	cGray      = lipgloss.Color("#6b7280")
	cPurple    = lipgloss.Color("#a855f7") // thinking
	cLavender  = lipgloss.Color("#a78bfa") // todos / agent graph
	cEmerald   = lipgloss.Color("#10b981") // skills / patch ops
	cGold      = lipgloss.Color("#fbbf24") // notes
	cAmberY    = lipgloss.Color("#f59e0b") // running icon / reopened
	cLineNum   = lipgloss.Color("#facc15")
	cLabel     = lipgloss.Color("#a1a1aa")
	cSnippet   = lipgloss.Color("#e2e8f0")
	cSlate     = lipgloss.Color("#94a3b8")
	cCyan      = lipgloss.Color("#06b6d4") // proxy
	cStatus3xx = lipgloss.Color("#eab308")
	cStatus4xx = lipgloss.Color("#f97316")
	cHdr16a    = lipgloss.Color("#16a34a")
	cHdr158    = lipgloss.Color("#15803d")
	cMint      = lipgloss.Color("#86efac")
	cStrike    = lipgloss.Color("#525252")
	cCodeBg    = lipgloss.Color("#0a0a0a")
	cInfoBlue  = lipgloss.Color("#60a5fa")
)

// Style helpers. col() foreground; dimS() Rich "dim" (faint attribute).
func col(c lipgloss.Color) lipgloss.Style { return lipgloss.NewStyle().Foreground(c) }
func dimS() lipgloss.Style                { return lipgloss.NewStyle().Faint(true) }
func boldC(c lipgloss.Color) lipgloss.Style {
	return lipgloss.NewStyle().Bold(true).Foreground(c)
}

// severityColor maps a severity string to the report renderer's color.
func severityColor(sev string) lipgloss.Color {
	switch strings.ToLower(sev) {
	case "critical":
		return cSevCrit
	case "high":
		return cSevHigh
	case "medium":
		return cSevMed
	case "low":
		return cSevLow
	case "info":
		return cSevInfo
	}
	return cGray
}

func cvssColor(score float64) lipgloss.Color {
	switch {
	case score >= 9.0:
		return cSevCrit
	case score >= 7.0:
		return cSevHigh
	case score >= 4.0:
		return cSevMed
	case score >= 0.1:
		return cSevLow
	}
	return cGray
}

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
	{"###### ", 7, boldC(cField)},
	{"##### ", 6, boldC(green)},
	{"#### ", 5, boldC(cHdr16a)},
	{"### ", 4, boldC(cHdr158)},
	{"## ", 3, boldC(green)},
	{"# ", 2, boldC(cField)},
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
			out.WriteString(col(textColor).Render(strings.Join(codeLines, "\n")))
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
			out.WriteString(col(green).Render("┃ ") + inlineFormat(line[2:]))
		case strings.HasPrefix(line, "- "), strings.HasPrefix(line, "* "):
			out.WriteString(col(green).Render("• ") + inlineFormat(line[2:]))
		case len(line) > 2 && line[0] >= '0' && line[0] <= '9' && (line[1:3] == ". " || line[1:3] == ") "):
			out.WriteString(col(green).Render(string(line[0])+". ") + inlineFormat(line[2:]))
		case line == "---" || line == "***" || line == "___":
			out.WriteString(col(green).Render(strings.Repeat("─", 40)))
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
				out.WriteString(boldC(cField).Render(line[i+2 : end]))
				i = end + 2
				continue
			}
		}
		if i+1 < n && line[i:i+2] == "~~" {
			if end := strings.Index(line[i+2:], "~~"); end != -1 {
				end += i + 2
				out.WriteString(lipgloss.NewStyle().Strikethrough(true).Foreground(cStrike).Render(line[i+2 : end]))
				i = end + 2
				continue
			}
		}
		if line[i] == '`' {
			if end := strings.Index(line[i+1:], "`"); end != -1 {
				end += i + 1
				out.WriteString(lipgloss.NewStyle().Bold(true).Foreground(green).Background(cCodeBg).Render(line[i+1 : end]))
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
						out.WriteString(lipgloss.NewStyle().Italic(true).Foreground(cMint).Render(line[i+1 : end]))
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

// ---------------------------------------------------------------------------
// Chat messages
// ---------------------------------------------------------------------------

// renderUserMessage ports UserMessageRenderer._format_user_message.
func renderUserMessage(content string) string {
	bar := col(blue).Render("▍")
	var b strings.Builder
	b.WriteString(bar + " " + lipgloss.NewStyle().Bold(true).Render("You:"))
	for _, line := range strings.Split(content, "\n") {
		b.WriteString("\n" + bar + " " + line)
	}
	return b.String()
}

// renderChat renders a chat event (assistant markdown or user message).
func renderChat(data map[string]any, width int) string {
	role, _ := data["role"].(string)
	content := stripControls(stringValue(data["content"]))
	if role == "user" {
		return renderUserMessage(content)
	}
	return renderAssistantMarkdown(content)
}

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
		p := shellParsed{content: stringValue(m["content"])}
		if code, ok := numericValue(m["exit_code"]); ok {
			p.exitCode, p.hasExitCode = int(code), true
		}
		return p
	}
	s, ok := result.(string)
	if !ok {
		if result == nil {
			return shellParsed{}
		}
		return shellParsed{content: stringValue(result)}
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
			b.WriteString("  " + dimS().Render(truncateShellLine(line)))
			if i < len(lines)-1 {
				b.WriteString("\n")
			}
		}
		return b.String()
	}

	display := lines[:head]
	hidden := total - head - tail
	for _, line := range display {
		b.WriteString("  " + dimS().Render(truncateShellLine(line)) + "\n")
	}
	b.WriteString(dimS().Italic(true).Render(fmt.Sprintf("  ... %d lines truncated ...", hidden)) + "\n")
	tailLines := lines[total-tail:]
	for i, line := range tailLines {
		b.WriteString("  " + dimS().Render(truncateShellLine(line)))
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
			b.WriteString("\n" + col(red).Faint(true).Render(fmt.Sprintf("  exit %d", p.exitCode)))
		}
		return
	}
	b.WriteString("\n" + formatShellOutput(output))
	if p.hasExitCode && p.exitCode != 0 {
		b.WriteString("\n" + col(red).Faint(true).Render(fmt.Sprintf("  exit %d", p.exitCode)))
	}
}

func renderTerminal(prompt string, promptColor lipgloss.Color, command string, result any, status, meta string) string {
	var b strings.Builder
	b.WriteString(dimS().Render(">_") + " ")
	if strings.TrimSpace(command) == "" {
		b.WriteString(dimS().Render("getting logs..."))
	} else {
		b.WriteString(col(promptColor).Render(prompt) + " " + command)
	}
	if meta != "" {
		b.WriteString(dimS().Render("  " + meta))
	}
	if result != nil {
		appendShellOutput(&b, parseShellResult(result), status)
	}
	return b.String()
}

func renderExecCommand(args map[string]any, result any, status string) string {
	cmd := stringValue(args["cmd"])
	var metaParts []string
	if wd := stringValue(args["workdir"]); wd != "" {
		metaParts = append(metaParts, "cwd:"+wd)
	}
	if b, ok := args["tty"].(bool); ok && b {
		metaParts = append(metaParts, "tty")
	}
	meta := strings.Join(metaParts, ", ")
	return renderTerminal("$", green, cmd, result, status, meta)
}

func renderWriteStdin(args map[string]any, result any, status string) string {
	chars := stringValue(args["chars"])
	meta := ""
	if sid, ok := args["session_id"]; ok && sid != nil {
		meta = "session #" + stringValue(sid)
	}
	return renderTerminal(">>>", blue, chars, result, status, meta)
}

// ---------------------------------------------------------------------------
// Filesystem: apply_patch + view_image (filesystem_renderer.py)
// ---------------------------------------------------------------------------

const (
	addFilePfx    = "*** Add File: "
	deleteFilePfx = "*** Delete File: "
	updateFilePfx = "*** Update File: "
	beginPatch    = "*** Begin Patch"
	endPatch      = "*** End Patch"
)

type patchOp struct {
	kind string
	path string
	old  []string
	new  []string
}

func extractPatchText(args map[string]any) string {
	if raw, ok := args["patch"].(string); ok {
		return raw
	}
	if raw, ok := args["patch"].(map[string]any); ok {
		if inner, ok := raw["patch"].(string); ok {
			return inner
		}
	}
	if fb, ok := args["input"].(string); ok {
		return fb
	}
	return ""
}

func parsePatchOperations(patch string) []patchOp {
	var ops []patchOp
	var cur *patchOp
	flush := func() {
		if cur != nil && cur.kind != "" {
			ops = append(ops, *cur)
		}
		cur = nil
	}
	for _, line := range strings.Split(patch, "\n") {
		switch {
		case line == beginPatch || line == endPatch:
			continue
		case strings.HasPrefix(line, addFilePfx):
			flush()
			cur = &patchOp{kind: "add", path: strings.TrimSpace(line[len(addFilePfx):])}
		case strings.HasPrefix(line, updateFilePfx):
			flush()
			cur = &patchOp{kind: "update", path: strings.TrimSpace(line[len(updateFilePfx):])}
		case strings.HasPrefix(line, deleteFilePfx):
			flush()
			cur = &patchOp{kind: "delete", path: strings.TrimSpace(line[len(deleteFilePfx):])}
		case cur != nil && cur.kind == "update":
			if strings.HasPrefix(line, "@@") {
				continue
			}
			if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
				cur.old = append(cur.old, line[1:])
			} else if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
				cur.new = append(cur.new, line[1:])
			}
		case cur != nil && cur.kind == "add":
			if strings.HasPrefix(line, "+") {
				cur.new = append(cur.new, line[1:])
			} else if strings.TrimSpace(line) != "" {
				cur.new = append(cur.new, line)
			}
		}
	}
	flush()
	return ops
}

var opLabel = map[string]string{"add": "create", "update": "edit", "delete": "delete"}

func renderPatchOperation(b *strings.Builder, op patchOp) {
	label := opLabel[op.kind]
	if label == "" {
		label = "file"
	}
	b.WriteString(col(cEmerald).Render("◇ ") + dimS().Render(label))
	if op.path != "" {
		p := op.path
		if len(p) > 60 {
			p = p[len(p)-60:]
		}
		b.WriteString(" " + dimS().Render(p))
	}
	if op.kind == "update" {
		for _, line := range op.old {
			b.WriteString("\n" + col(red).Render("-") + " " + line)
		}
		for _, line := range op.new {
			b.WriteString("\n" + col(green).Render("+") + " " + line)
		}
	} else if op.kind == "add" && len(op.new) > 0 {
		b.WriteString("\n" + col(textColor).Render(strings.Join(op.new, "\n")))
	}
}

func renderApplyPatch(args map[string]any, result any, status string) string {
	ops := parsePatchOperations(extractPatchText(args))
	var b strings.Builder
	if len(ops) == 0 {
		b.WriteString(col(cEmerald).Render("◇ ") + dimS().Render("patch"))
		if s, ok := result.(string); ok && strings.TrimSpace(s) != "" {
			b.WriteString("\n  " + dimS().Render(strings.TrimSpace(s)))
		} else if result == nil {
			b.WriteString(" " + dimS().Render("Processing..."))
		}
		return b.String()
	}
	for i, op := range ops {
		if i > 0 {
			b.WriteString("\n")
		}
		renderPatchOperation(&b, op)
	}
	if status == "failed" {
		if s, ok := result.(string); ok && strings.TrimSpace(s) != "" {
			b.WriteString("\n  " + col(red).Render(strings.TrimSpace(s)))
		}
	}
	return b.String()
}

func renderViewImage(args map[string]any, result any) string {
	path := strings.TrimSpace(stringValue(args["path"]))
	var b strings.Builder
	b.WriteString(col(cEmerald).Render("◇ ") + dimS().Render("view image"))
	if path != "" {
		if len(path) > 60 {
			path = path[len(path)-60:]
		}
		b.WriteString(" " + dimS().Render(path))
	}
	if s, ok := result.(string); ok {
		low := strings.ToLower(strings.TrimSpace(s))
		if strings.HasPrefix(low, "image path ") || strings.HasPrefix(low, "unable to read image") ||
			strings.HasPrefix(low, "manifest path") || strings.HasPrefix(low, "exceeded the allowed size") ||
			strings.Contains(low, "not a supported image") {
			b.WriteString("\n  " + col(red).Render(strings.TrimSpace(s)))
			return b.String()
		}
	}
	if isImageSuccess(result) {
		b.WriteString("  " + col(green).Render("✓"))
	}
	return b.String()
}

func isImageSuccess(result any) bool {
	if m, ok := result.(map[string]any); ok {
		return stringValue(m["type"]) == "image"
	}
	if s, ok := result.(string); ok {
		return strings.HasPrefix(strings.TrimLeft(s, " \t\n"), "data:image/")
	}
	return false
}

// ---------------------------------------------------------------------------
// Reporting (reporting_renderer.py)
// ---------------------------------------------------------------------------

func renderVulnerabilityReport(args map[string]any, result any) string {
	resultMap, _ := result.(map[string]any)
	var b strings.Builder
	b.WriteString("🐞 " + boldC(cReportHdr).Render("Vulnerability Report"))

	field := func(label, value string) {
		if value != "" {
			b.WriteString("\n\n" + boldC(cField).Render(label+": ") + value)
		}
	}
	title := stringValue(args["title"])
	field("Title", title)

	if sev := stringValue(resultMap["severity"]); sev != "" {
		b.WriteString("\n\n" + boldC(cField).Render("Severity: ") +
			lipgloss.NewStyle().Bold(true).Foreground(severityColor(sev)).Render(strings.ToUpper(sev)))
	}
	if score, ok := numericValue(resultMap["cvss_score"]); ok {
		b.WriteString("\n\n" + boldC(cField).Render("CVSS Score: ") +
			lipgloss.NewStyle().Bold(true).Foreground(cvssColor(score)).Render(stringValue(resultMap["cvss_score"])))
	}
	field("Target", stringValue(args["target"]))
	field("Endpoint", stringValue(args["endpoint"]))
	field("Method", stringValue(args["method"]))
	field("CVE", stringValue(args["cve"]))
	field("CWE", stringValue(args["cwe"]))

	if bd, ok := args["cvss_breakdown"].(map[string]any); ok && len(bd) > 0 {
		parts := cvssVectorParts(bd)
		if len(parts) > 0 {
			b.WriteString("\n\n" + boldC(cField).Render("CVSS Vector: ") + dimS().Render(strings.Join(parts, "/")))
		}
	}

	section := func(label, value string) {
		if value != "" {
			b.WriteString("\n\n" + boldC(cField).Render(label) + "\n" + value)
		}
	}
	section("Description", stringValue(args["description"]))
	section("Impact", stringValue(args["impact"]))
	section("Technical Analysis", stringValue(args["technical_analysis"]))
	renderCodeLocations(&b, args["code_locations"])
	section("PoC Description", stringValue(args["poc_description"]))
	if poc := stringValue(args["poc_script_code"]); poc != "" {
		b.WriteString("\n\n" + boldC(cField).Render("PoC Code") + "\n" + col(textColor).Render(poc))
	}
	section("Remediation", stringValue(args["remediation_steps"]))

	if title == "" {
		b.WriteString("\n  " + dimS().Render("Creating report..."))
	}
	return "\n\n" + b.String() + "\n\n"
}

var cvssKeys = [][2]string{
	{"attack_vector", "AV"}, {"attack_complexity", "AC"}, {"privileges_required", "PR"},
	{"user_interaction", "UI"}, {"scope", "S"}, {"confidentiality", "C"},
	{"integrity", "I"}, {"availability", "A"},
}

func cvssVectorParts(bd map[string]any) []string {
	var parts []string
	for _, kp := range cvssKeys {
		if v := stringValue(bd[kp[0]]); v != "" {
			parts = append(parts, kp[1]+":"+v)
		}
	}
	return parts
}

func renderCodeLocations(b *strings.Builder, raw any) {
	locs, ok := raw.([]any)
	if !ok || len(locs) == 0 {
		return
	}
	b.WriteString("\n\n" + boldC(cField).Render("Code Locations"))
	for i, l := range locs {
		loc, ok := l.(map[string]any)
		if !ok {
			continue
		}
		b.WriteString("\n\n" + dimS().Render(fmt.Sprintf("  Location %d: ", i+1)))
		file := stringValue(loc["file"])
		if file == "" {
			file = "unknown"
		}
		b.WriteString(boldC(cInfoBlue).Render(file))
		if start, ok := numericValue(loc["start_line"]); ok {
			if end, ok := numericValue(loc["end_line"]); ok && end != start {
				b.WriteString(col(cLineNum).Render(fmt.Sprintf(":%d-%d", int(start), int(end))))
			} else {
				b.WriteString(col(cLineNum).Render(fmt.Sprintf(":%d", int(start))))
			}
		}
		if label := stringValue(loc["label"]); label != "" {
			b.WriteString(lipgloss.NewStyle().Italic(true).Foreground(cLabel).Render("\n  " + label))
		}
		if snip := stringValue(loc["snippet"]); snip != "" {
			b.WriteString("\n  " + col(cSnippet).Render(snip))
		}
		before, after := stringValue(loc["fix_before"]), stringValue(loc["fix_after"])
		if before != "" || after != "" {
			b.WriteString("\n  " + dimS().Render("Fix:"))
			if before != "" {
				b.WriteString("\n  " + col(red).Render("- ") + col(red).Render(before))
			}
			if after != "" {
				b.WriteString("\n  " + col(green).Render("+ ") + col(green).Render(after))
			}
		}
	}
}

func renderDependencyReport(args map[string]any, result any) string {
	resultMap, _ := result.(map[string]any)
	// Unsuccessful / not-persisted variants.
	if resultMap != nil {
		success, hasSuccess := resultMap["success"].(bool)
		warning := stringValue(resultMap["warning"])
		if (hasSuccess && !success) || warning != "" {
			return renderDependencyUnsuccessful(args, resultMap)
		}
	}
	var b strings.Builder
	b.WriteString("📦 " + boldC(cReportHdr).Render("Dependency (SCA) Report"))
	field := func(label, value string) {
		if value != "" {
			b.WriteString("\n\n" + boldC(cField).Render(label+": ") + value)
		}
	}
	title := stringValue(args["title"])
	field("Title", title)
	if sev := stringValue(resultMap["severity"]); sev != "" {
		b.WriteString("\n\n" + boldC(cField).Render("Severity: ") +
			lipgloss.NewStyle().Bold(true).Foreground(severityColor(sev)).Render(strings.ToUpper(sev)))
	}
	if score, ok := numericValue(args["advisory_cvss"]); ok {
		b.WriteString("\n\n" + boldC(cField).Render("Advisory CVSS: ") +
			lipgloss.NewStyle().Bold(true).Foreground(cvssColor(score)).Render(stringValue(args["advisory_cvss"])))
	}
	field("CVE", stringValue(args["cve"]))
	field("CWE", stringValue(args["cwe"]))
	if pkg := stringValue(args["package_name"]); pkg != "" {
		b.WriteString("\n\n" + boldC(cField).Render("Package: ") + boldC(cInfoBlue).Render(pkg))
		if eco := stringValue(args["package_ecosystem"]); eco != "" {
			b.WriteString(dimS().Render(" (" + eco + ")"))
		}
	}
	if inst := stringValue(args["installed_version"]); inst != "" {
		b.WriteString("\n\n" + boldC(cField).Render("Installed: ") + col(red).Render(inst))
		if fixed := stringValue(args["fixed_version"]); fixed != "" {
			b.WriteString(dimS().Render("  →  ") + boldC(cField).Render("Fixed: ") + col(green).Render(fixed))
		}
	}
	field("Fix Effort", stringValue(args["fix_effort"]))
	field("Target", stringValue(args["target"]))
	section := func(label, value string) {
		if value != "" {
			b.WriteString("\n\n" + boldC(cField).Render(label) + "\n" + value)
		}
	}
	section("Description", stringValue(args["description"]))
	section("Impact", stringValue(args["impact"]))
	section("Technical Analysis", stringValue(args["technical_analysis"]))
	section("Assumptions", stringValue(args["assumptions"]))
	section("Remediation", stringValue(args["remediation_steps"]))
	if title == "" {
		b.WriteString("\n  " + dimS().Render("Creating dependency report..."))
	}
	return "\n\n" + b.String() + "\n\n"
}

func renderDependencyUnsuccessful(args, result map[string]any) string {
	var b strings.Builder
	b.WriteString("📦 " + boldC(cReportHdr).Render("Dependency (SCA) Report"))
	if title := stringValue(args["title"]); title != "" {
		b.WriteString("\n\n" + boldC(cField).Render("Title: ") + title)
	}
	success, hasSuccess := result["success"].(bool)
	var label, detail string
	var style lipgloss.Style
	if hasSuccess && !success {
		detail = stringValue(result["error"])
		if errs, ok := result["errors"].([]any); ok && len(errs) > 0 {
			var parts []string
			for _, e := range errs {
				parts = append(parts, stringValue(e))
			}
			detail = strings.Join(parts, "; ")
		}
		label, style = "✗ Not created: ", boldC(cSevCrit)
		if detail == "" {
			detail = "Report was not created."
		}
	} else {
		detail = stringValue(result["warning"])
		label, style = "⚠ Not persisted: ", boldC(cSevMed)
		if detail == "" {
			detail = "Report could not be persisted."
		}
	}
	b.WriteString("\n\n" + style.Render(label) + detail)
	return "\n\n" + b.String() + "\n\n"
}

// ---------------------------------------------------------------------------
// Finish scan (finish_renderer.py)
// ---------------------------------------------------------------------------

func renderFinishScan(args map[string]any) string {
	var b strings.Builder
	b.WriteString(col(green).Render("◆ ") + boldC(green).Render("Penetration test completed"))
	section := func(label, value string) {
		if value != "" {
			b.WriteString("\n\n" + boldC(cField).Render(label) + "\n" + value)
		}
	}
	es := stringValue(args["executive_summary"])
	me := stringValue(args["methodology"])
	ta := stringValue(args["technical_analysis"])
	re := stringValue(args["recommendations"])
	section("Executive Summary", es)
	section("Methodology", me)
	section("Technical Analysis", ta)
	section("Recommendations", re)
	if es == "" && me == "" && ta == "" && re == "" {
		b.WriteString("\n  " + dimS().Render("Generating final report..."))
	}
	return "\n\n" + b.String() + "\n\n"
}

// ---------------------------------------------------------------------------
// Notes (notes_renderer.py)
// ---------------------------------------------------------------------------

func renderNote(name string, args map[string]any, result any) string {
	var b strings.Builder
	icon := col(cGold).Render("◇ ")
	switch name {
	case "create_note":
		category := stringValue(args["category"])
		if category == "" {
			category = "general"
		}
		title, content := strings.TrimSpace(stringValue(args["title"])), strings.TrimSpace(stringValue(args["content"]))
		b.WriteString(icon + dimS().Render("note") + " " + dimS().Render("("+category+")"))
		if title != "" {
			b.WriteString("\n  " + title)
		}
		if content != "" {
			b.WriteString("\n  " + dimS().Render(content))
		}
		if title == "" && content == "" {
			b.WriteString("\n  " + dimS().Render("Capturing..."))
		}
	case "delete_note":
		b.WriteString(icon + dimS().Render("note removed"))
	case "update_note":
		title, content := stringValue(args["title"]), strings.TrimSpace(stringValue(args["content"]))
		b.WriteString(icon + dimS().Render("note updated"))
		if title != "" {
			b.WriteString("\n  " + title)
		}
		if content != "" {
			b.WriteString("\n  " + dimS().Render(content))
		}
		if title == "" && content == "" {
			b.WriteString("\n  " + dimS().Render("Updating..."))
		}
	case "list_notes":
		b.WriteString(icon + dimS().Render("notes"))
		b.WriteString(noteListBody(result))
	case "get_note":
		b.WriteString(icon + dimS().Render("note read"))
		if m, ok := result.(map[string]any); ok && truthy(m["success"]) {
			note, _ := m["note"].(map[string]any)
			renderSingleNote(&b, note)
		} else {
			b.WriteString("\n  " + dimS().Render("Loading..."))
		}
	default:
		b.WriteString(icon + dimS().Render(strings.ReplaceAll(name, "_", " ")))
	}
	return b.String()
}

func noteListBody(result any) string {
	var b strings.Builder
	if s, ok := result.(string); ok && strings.TrimSpace(s) != "" {
		return "\n  " + dimS().Render(strings.TrimSpace(s))
	}
	m, ok := result.(map[string]any)
	if !ok || !truthy(m["success"]) {
		return "\n  " + dimS().Render("Loading...")
	}
	notes, _ := m["notes"].([]any)
	count, _ := numericValue(m["total_count"])
	if int(count) == 0 || len(notes) == 0 {
		return "\n  " + dimS().Render("No notes")
	}
	for _, n := range notes {
		note, _ := n.(map[string]any)
		title := strings.TrimSpace(stringValue(note["title"]))
		if title == "" {
			title = "(untitled)"
		}
		category := stringValue(note["category"])
		if category == "" {
			category = "general"
		}
		content := strings.TrimSpace(stringValue(note["content"]))
		if content == "" {
			content = strings.TrimSpace(stringValue(note["content_preview"]))
		}
		b.WriteString("\n  - " + title + dimS().Render(" ("+category+")"))
		if content != "" {
			b.WriteString("\n    " + dimS().Render(content))
		}
	}
	return b.String()
}

func renderSingleNote(b *strings.Builder, note map[string]any) {
	title := strings.TrimSpace(stringValue(note["title"]))
	if title == "" {
		title = "(untitled)"
	}
	category := stringValue(note["category"])
	if category == "" {
		category = "general"
	}
	b.WriteString("\n  " + title + dimS().Render(" ("+category+")"))
	if content := strings.TrimSpace(stringValue(note["content"])); content != "" {
		b.WriteString("\n  " + dimS().Render(content))
	}
}

// ---------------------------------------------------------------------------
// Todos (todo_renderer.py)
// ---------------------------------------------------------------------------

var todoMarkers = map[string]string{"pending": "[ ]", "in_progress": "[~]", "done": "[•]"}

var todoTitles = map[string]struct {
	title   string
	color   lipgloss.Color
	loading string
	errMsg  string
}{
	"create_todo":       {"Todo", cLavender, "Creating...", "Failed to create todo"},
	"list_todos":        {"Todos", cLavender, "Loading...", "Unable to list todos"},
	"update_todo":       {"Todo Updated", cLavender, "Updating...", "Failed to update todo"},
	"mark_todo_done":    {"Todo Completed", cLavender, "Marking done...", "Failed to mark todo done"},
	"mark_todo_pending": {"Todo Reopened", cAmberY, "Reopening...", "Failed to reopen todo"},
	"delete_todo":       {"Todo Removed", cSlate, "Removing...", "Failed to remove todo"},
}

func renderTodo(name string, result any) string {
	meta := todoTitles[name]
	var b strings.Builder
	b.WriteString("📋 " + boldC(meta.color).Render(meta.title))
	if s, ok := result.(string); ok && strings.TrimSpace(s) != "" {
		b.WriteString("\n  " + dimS().Render(strings.TrimSpace(s)))
		return b.String()
	}
	if m, ok := result.(map[string]any); ok {
		if truthy(m["success"]) {
			formatTodoLines(&b, m)
		} else {
			errMsg := stringValue(m["error"])
			if errMsg == "" {
				errMsg = meta.errMsg
			}
			b.WriteString("\n  " + col(red).Render(errMsg))
		}
	} else {
		b.WriteString("\n  " + dimS().Render(meta.loading))
	}
	return b.String()
}

func formatTodoLines(b *strings.Builder, result map[string]any) {
	todos, ok := result["todos"].([]any)
	if !ok || len(todos) == 0 {
		b.WriteString("\n  " + dimS().Render("No todos"))
		return
	}
	for _, t := range todos {
		todo, _ := t.(map[string]any)
		status := stringValue(todo["status"])
		marker := todoMarkers[status]
		if marker == "" {
			marker = todoMarkers["pending"]
		}
		title := strings.TrimSpace(stringValue(todo["title"]))
		if title == "" {
			title = "(untitled)"
		}
		b.WriteString("\n  " + marker + " ")
		switch status {
		case "done":
			b.WriteString(dimS().Strikethrough(true).Render(title))
		case "in_progress":
			b.WriteString(lipgloss.NewStyle().Italic(true).Render(title))
		default:
			b.WriteString(title)
		}
	}
}

// ---------------------------------------------------------------------------
// Agents graph (agents_graph_renderer.py)
// ---------------------------------------------------------------------------

func renderAgentGraphTool(name string, args map[string]any, result any) string {
	var b strings.Builder
	switch name {
	case "view_agent_graph":
		b.WriteString(col(cLavender).Render("◇ ") + dimS().Render("viewing agents graph"))
	case "create_agent":
		agentName := stringValue(args["name"])
		if agentName == "" {
			agentName = "Agent"
		}
		b.WriteString(col(cLavender).Render("◈ ") + dimS().Render("spawning ") + boldC(cLavender).Render(agentName))
		if task := stringValue(args["task"]); task != "" {
			b.WriteString("\n  " + dimS().Render(task))
		}
	case "send_message_to_agent":
		b.WriteString(col(cInfoBlue).Render("→ "))
		if target := stringValue(args["target_agent_id"]); target != "" {
			b.WriteString(dimS().Render("to " + target))
		} else {
			b.WriteString(dimS().Render("sending message"))
		}
		if msg := stringValue(args["message"]); msg != "" {
			b.WriteString("\n  " + dimS().Render(msg))
		}
	case "agent_finish":
		success := true
		if v, ok := args["success"].(bool); ok {
			success = v
		}
		if success {
			b.WriteString(col(green).Render("◆ ") + boldC(green).Render("Agent completed"))
		} else {
			b.WriteString(col(red).Render("◆ ") + boldC(red).Render("Agent failed"))
		}
		if summary := stringValue(args["result_summary"]); summary != "" {
			b.WriteString("\n  " + lipgloss.NewStyle().Bold(true).Render(summary))
			if findings, ok := args["findings"].([]any); ok {
				for _, f := range findings {
					b.WriteString("\n  • " + dimS().Render(stringValue(f)))
				}
			}
		} else {
			b.WriteString("\n  " + dimS().Render("Completing task..."))
		}
	case "wait_for_message":
		b.WriteString(col(cGray).Render("○ ") + dimS().Render("waiting"))
		if reason := stringValue(args["reason"]); reason != "" {
			b.WriteString("\n  " + dimS().Render(reason))
		}
	case "stop_agent":
		b.WriteString(col(red).Render("◼ ") + dimS().Render("stopping"))
		if target := stringValue(args["target_agent_id"]); target != "" {
			b.WriteString(boldC(red).Render(" " + target))
		}
		cascade := true
		if v, ok := args["cascade"].(bool); ok {
			cascade = v
		}
		if cascade {
			b.WriteString(dimS().Italic(true).Render(" + descendants"))
		}
		if reason := stringValue(args["reason"]); reason != "" {
			b.WriteString("\n  " + dimS().Render(reason))
		}
		if m, ok := result.(map[string]any); ok {
			if s, hs := m["success"].(bool); hs && !s {
				if e := stringValue(m["error"]); e != "" {
					b.WriteString("\n  " + col(red).Render(e))
				}
			}
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Proxy (proxy_renderer.py)
// ---------------------------------------------------------------------------

const proxyIcon = "<~>"

func proxyStatusStyle(code int) lipgloss.Style {
	switch {
	case code >= 200 && code < 300:
		return col(green)
	case code >= 300 && code < 400:
		return col(cStatus3xx)
	case code >= 400 && code < 500:
		return col(cStatus4xx)
	case code >= 500:
		return col(red)
	}
	return dimS()
}

func ptrunc(s string, max int) string {
	if len(s) > max {
		return s[:max-3] + "..."
	}
	return s
}

func psanitize(s string, max int) string {
	clean := strings.NewReplacer("\n", " ", "\r", "", "\t", " ").Replace(s)
	return ptrunc(clean, max)
}

func renderProxyTool(name string, args map[string]any, result any, status string) string {
	switch name {
	case "list_requests":
		return renderListRequests(args, result, status)
	case "view_request":
		return renderViewRequest(args, result, status)
	case "repeat_request":
		return renderRepeatRequest(args, result, status)
	case "list_sitemap":
		return renderListSitemap(args, result, status)
	case "view_sitemap_entry":
		return renderViewSitemapEntry(args, result, status)
	case "scope_rules":
		return renderScopeRules(args, result, status)
	}
	return ""
}

func resultMapOf(result any) (map[string]any, bool) {
	m, ok := result.(map[string]any)
	return m, ok
}

func renderListRequests(args map[string]any, result any, status string) string {
	var b strings.Builder
	b.WriteString(dimS().Render(proxyIcon) + col(cCyan).Render(" listing requests"))
	if f := stringValue(args["httpql_filter"]); f != "" {
		b.WriteString(dimS().Italic(true).Render("  where " + ptrunc(f, 150)))
	}
	var meta []string
	if s := stringValue(args["sort_by"]); s != "" && s != "timestamp" {
		meta = append(meta, "by:"+s)
	}
	if s := stringValue(args["sort_order"]); s != "" && s != "desc" {
		meta = append(meta, s)
	}
	if s := stringValue(args["scope_id"]); s != "" {
		meta = append(meta, "scope:"+truncStr(s, 8))
	}
	if len(meta) > 0 {
		b.WriteString(dimS().Render("  (" + strings.Join(meta, ", ") + ")"))
	}
	if status == "completed" {
		if m, ok := resultMapOf(result); ok {
			if e, has := m["error"]; has {
				b.WriteString(col(red).Render("  error: " + psanitize(stringValue(e), 150)))
			} else {
				entries, _ := m["entries"].([]any)
				suffix := ""
				if pi, ok := m["page_info"].(map[string]any); ok && truthy(pi["has_next_page"]) {
					suffix = "+"
				}
				b.WriteString(dimS().Render(fmt.Sprintf("  [%d%s found]", len(entries), suffix)))
				renderRequestEntries(&b, entries)
			}
		}
	}
	return b.String()
}

func renderRequestEntries(b *strings.Builder, entries []any) {
	if len(entries) == 0 {
		return
	}
	b.WriteString("\n")
	limit := len(entries)
	if limit > 20 {
		limit = 20
	}
	for i := 0; i < limit; i++ {
		entry, ok := entries[i].(map[string]any)
		if !ok {
			continue
		}
		req, _ := entry["request"].(map[string]any)
		resp, _ := entry["response"].(map[string]any)
		method := stringValue(req["method"])
		if method == "" {
			method = "?"
		}
		host := stringValue(req["host"])
		path := stringValue(req["path"])
		if path == "" {
			path = "/"
		}
		b.WriteString("  " + col(cLavender).Render(fmt.Sprintf("%-6s", method)))
		b.WriteString(dimS().Render(" " + ptrunc(host+path, 180)))
		if code, ok := numericValue(resp["status_code"]); ok && code != 0 {
			b.WriteString(proxyStatusStyle(int(code)).Render(fmt.Sprintf(" %d", int(code))))
		}
		if i < limit-1 {
			b.WriteString("\n")
		}
	}
	if len(entries) > 20 {
		b.WriteString("\n" + dimS().Italic(true).Render(fmt.Sprintf("  ... +%d more", len(entries)-20)))
	}
}

func renderViewRequest(args map[string]any, result any, status string) string {
	var b strings.Builder
	b.WriteString(dimS().Render(proxyIcon))
	part := stringValue(args["part"])
	if part == "" {
		part = "request"
	}
	action := "viewing"
	search := stringValue(args["search_pattern"])
	if search != "" {
		action = "searching"
	}
	b.WriteString(col(cCyan).Render(" " + action + " " + part))
	if rid := stringValue(args["request_id"]); rid != "" {
		b.WriteString(dimS().Render(" #" + rid))
	}
	if search != "" {
		b.WriteString(dimS().Italic(true).Render("  /" + ptrunc(search, 100) + "/"))
	}
	if status == "completed" {
		if m, ok := resultMapOf(result); ok {
			if e, has := m["error"]; has {
				b.WriteString(col(red).Render("  error: " + psanitize(stringValue(e), 150)))
			} else if hits, has := m["hits"].([]any); has {
				total := len(hits)
				if t, ok := numericValue(m["total_hits"]); ok {
					total = int(t)
				}
				b.WriteString(dimS().Render(fmt.Sprintf("  [%d matches]", total)))
				renderSearchHits(&b, hits)
			} else if content, has := m["content"]; has {
				page := 1
				if p, ok := numericValue(m["page"]); ok {
					page = int(p)
				}
				tl := 0
				if t, ok := numericValue(m["total_lines"]); ok {
					tl = int(t)
				}
				b.WriteString(dimS().Render(fmt.Sprintf("  [page %d, %d lines]", page, tl)))
				renderContentLines(&b, stringValue(content), truthy(m["has_more"]))
			}
		}
	}
	return b.String()
}

func renderSearchHits(b *strings.Builder, hits []any) {
	if len(hits) == 0 {
		return
	}
	b.WriteString("\n")
	limit := len(hits)
	if limit > 5 {
		limit = 5
	}
	for i := 0; i < limit; i++ {
		m, ok := hits[i].(map[string]any)
		if !ok {
			continue
		}
		before := lastN(strings.NewReplacer("\n", " ", "\r", "").Replace(stringValue(m["before"])), 100)
		after := firstN(strings.NewReplacer("\n", " ", "\r", "").Replace(stringValue(m["after"])), 100)
		b.WriteString("  ")
		if before != "" {
			b.WriteString(dimS().Render("..." + before))
		}
		b.WriteString(boldC(green).Render(stringValue(m["match"])))
		if after != "" {
			b.WriteString(dimS().Render(after + "..."))
		}
		if i < limit-1 {
			b.WriteString("\n")
		}
	}
	if len(hits) > 5 {
		b.WriteString("\n" + dimS().Italic(true).Render(fmt.Sprintf("  ... +%d more matches", len(hits)-5)))
	}
}

func renderContentLines(b *strings.Builder, content string, hasMore bool) {
	if content == "" {
		return
	}
	allLines := strings.Split(content, "\n")
	lines := allLines
	if len(lines) > 15 {
		lines = lines[:15]
	}
	b.WriteString("\n")
	for i, line := range lines {
		b.WriteString("  " + dimS().Render(ptrunc(line, maxLineLength)))
		if i < len(lines)-1 {
			b.WriteString("\n")
		}
	}
	if hasMore || len(allLines) > 15 {
		b.WriteString("\n" + dimS().Italic(true).Render("  ... more content available"))
	}
}

func renderRepeatRequest(args map[string]any, result any, status string) string {
	var b strings.Builder
	b.WriteString(dimS().Render(proxyIcon) + col(cCyan).Render(" repeating request"))
	if rid := stringValue(args["request_id"]); rid != "" {
		b.WriteString(dimS().Render(" #" + rid))
	}
	if mods, ok := args["modifications"].(map[string]any); ok {
		b.WriteString(dimS().Italic(true).Render("\n  modifications:"))
		arrow := col(blue).Render("  >> ")
		if url, ok := mods["url"]; ok {
			b.WriteString("\n" + arrow + dimS().Render("url: "+ptrunc(stringValue(url), 180)))
		}
		writeKV := func(key, prefix string, valMax int) {
			if kv, ok := mods[key].(map[string]any); ok {
				n := 0
				for k, v := range kv {
					if n >= 5 {
						break
					}
					b.WriteString("\n" + arrow + dimS().Render(fmt.Sprintf(prefix, k, psanitize(stringValue(v), valMax))))
					n++
				}
			}
		}
		writeKV("headers", "%s: %s", 150)
		writeKV("cookies", "cookie %s=%s", 100)
		writeKV("params", "param %s=%s", 100)
		if body, ok := mods["body"].(string); ok {
			b.WriteString("\n" + arrow)
			bodyLines := strings.Split(body, "\n")
			shown := bodyLines
			if len(shown) > 4 {
				shown = shown[:4]
			}
			for i, line := range shown {
				if i > 0 {
					b.WriteString("\n" + dimS().Render("     "))
				}
				b.WriteString(dimS().Render(ptrunc(line, maxLineLength)))
			}
			if len(bodyLines) > 4 {
				b.WriteString(dimS().Italic(true).Render(" ..."))
			}
		}
	} else if mods, ok := args["modifications"].(string); ok && mods != "" {
		b.WriteString(dimS().Italic(true).Render("\n  " + ptrunc(mods, 200)))
	}
	if status == "completed" {
		if m, ok := resultMapOf(result); ok {
			success, hasSuccess := m["success"].(bool)
			if hasSuccess && !success && stringValue(m["error"]) != "" {
				b.WriteString(col(red).Render("\n  error: " + psanitize(stringValue(m["error"]), 150)))
			} else {
				resp, _ := m["response"].(map[string]any)
				b.WriteString("\n" + col(green).Render("  << "))
				if code, ok := numericValue(resp["status_code"]); ok && code != 0 {
					b.WriteString(proxyStatusStyle(int(code)).Render(fmt.Sprintf("%d", int(code))))
				} else {
					b.WriteString(dimS().Render("(no response)"))
				}
				if ms, ok := numericValue(m["elapsed_ms"]); ok && ms != 0 {
					b.WriteString(dimS().Render(fmt.Sprintf(" (%dms)", int(ms))))
				}
				body := stringValue(resp["body"])
				if body != "" {
					allLines := strings.Split(body, "\n")
					lines := allLines
					if len(lines) > 5 {
						lines = lines[:5]
					}
					for _, line := range lines {
						b.WriteString("\n" + col(green).Render("  << ") + dimS().Render(ptrunc(line, maxLineLength-5)))
					}
					if truthy(resp["body_truncated"]) || len(allLines) > 5 {
						b.WriteString("\n" + dimS().Italic(true).Render("  ..."))
					}
				}
			}
		}
	}
	return b.String()
}

func renderListSitemap(args map[string]any, result any, status string) string {
	var b strings.Builder
	b.WriteString(dimS().Render(proxyIcon) + col(cCyan).Render(" listing sitemap"))
	if pid := stringValue(args["parent_id"]); pid != "" {
		b.WriteString(dimS().Render("  under #" + ptrunc(pid, 20)))
	}
	var meta []string
	if s := stringValue(args["scope_id"]); s != "" {
		meta = append(meta, "scope:"+truncStr(s, 8))
	}
	if d := stringValue(args["depth"]); d != "" && d != "DIRECT" {
		meta = append(meta, strings.ToLower(d))
	}
	if len(meta) > 0 {
		b.WriteString(dimS().Render("  (" + strings.Join(meta, ", ") + ")"))
	}
	if status == "completed" {
		if m, ok := resultMapOf(result); ok {
			if e, has := m["error"]; has {
				b.WriteString(col(red).Render("  error: " + psanitize(stringValue(e), 150)))
			} else {
				total := 0
				if t, ok := numericValue(m["total_count"]); ok {
					total = int(t)
				}
				entries, _ := m["entries"].([]any)
				b.WriteString(dimS().Render(fmt.Sprintf("  [%d entries]", total)))
				renderSitemapEntries(&b, entries)
			}
		}
	}
	return b.String()
}

var sitemapKindColors = map[string]lipgloss.Color{
	"DOMAIN": cAmberY, "DIRECTORY": blue, "REQUEST": green,
}

func renderSitemapEntries(b *strings.Builder, entries []any) {
	if len(entries) == 0 {
		return
	}
	b.WriteString("\n")
	limit := len(entries)
	if limit > 20 {
		limit = 20
	}
	for i := 0; i < limit; i++ {
		entry, ok := entries[i].(map[string]any)
		if !ok {
			continue
		}
		kind := stringValue(entry["kind"])
		if kind == "" {
			kind = "?"
		}
		label := stringValue(entry["label"])
		if label == "" {
			label = "?"
		}
		kindStyle, ok := sitemapKindColors[kind]
		style := dimS()
		if ok {
			style = col(kindStyle)
		}
		abbr := kind
		if len(abbr) > 3 {
			abbr = abbr[:3]
		}
		b.WriteString("  " + style.Render(fmt.Sprintf("%-3s", abbr)) + dimS().Render(" "+ptrunc(label, 150)))
		if req, ok := entry["request"].(map[string]any); ok {
			if method := stringValue(req["method"]); method != "" {
				b.WriteString(col(cLavender).Render(" " + method))
			}
			if code, ok := numericValue(req["status_code"]); ok && code != 0 {
				b.WriteString(proxyStatusStyle(int(code)).Render(fmt.Sprintf(" %d", int(code))))
			}
		}
		if truthy(entry["has_descendants"]) {
			b.WriteString(dimS().Italic(true).Render(" +"))
		}
		if i < limit-1 {
			b.WriteString("\n")
		}
	}
	if len(entries) > 20 {
		b.WriteString("\n" + dimS().Italic(true).Render(fmt.Sprintf("  ... +%d more", len(entries)-20)))
	}
}

func renderViewSitemapEntry(args map[string]any, result any, status string) string {
	var b strings.Builder
	b.WriteString(dimS().Render(proxyIcon) + col(cCyan).Render(" viewing sitemap"))
	if eid := stringValue(args["entry_id"]); eid != "" {
		b.WriteString(dimS().Render(" #" + ptrunc(eid, 20)))
	}
	if status == "completed" {
		if m, ok := resultMapOf(result); ok {
			if e, has := m["error"]; has {
				b.WriteString(col(red).Render("  error: " + psanitize(stringValue(e), 150)))
			} else if entry, ok := m["entry"].(map[string]any); ok {
				kind, label := stringValue(entry["kind"]), stringValue(entry["label"])
				related, _ := entry["related_requests"].(map[string]any)
				if kind != "" && label != "" {
					b.WriteString(dimS().Render(fmt.Sprintf("  %s: %s", kind, ptrunc(label, 120))))
				}
				total := 0
				if t, ok := numericValue(related["total_count"]); ok {
					total = int(t)
				}
				if total != 0 {
					b.WriteString(dimS().Render(fmt.Sprintf("  [%d requests]", total)))
				}
				reqs, _ := related["requests"].([]any)
				renderRelatedRequests(&b, reqs)
			}
		}
	}
	return b.String()
}

func renderRelatedRequests(b *strings.Builder, reqs []any) {
	if len(reqs) == 0 {
		return
	}
	b.WriteString("\n")
	limit := len(reqs)
	if limit > 10 {
		limit = 10
	}
	for i := 0; i < limit; i++ {
		req, ok := reqs[i].(map[string]any)
		if !ok {
			continue
		}
		method := stringValue(req["method"])
		if method == "" {
			method = "?"
		}
		path := stringValue(req["path"])
		if path == "" {
			path = "/"
		}
		b.WriteString("  " + col(cLavender).Render(fmt.Sprintf("%-6s", method)) + dimS().Render(" "+ptrunc(path, 180)))
		if code, ok := numericValue(req["status_code"]); ok && code != 0 {
			b.WriteString(proxyStatusStyle(int(code)).Render(fmt.Sprintf(" %d", int(code))))
		}
		if i < limit-1 {
			b.WriteString("\n")
		}
	}
	if len(reqs) > 10 {
		b.WriteString("\n" + dimS().Italic(true).Render(fmt.Sprintf("  ... +%d more", len(reqs)-10)))
	}
}

var scopeActionMap = map[string]string{
	"get": "getting", "list": "listing", "create": "creating", "update": "updating", "delete": "deleting",
}

func renderScopeRules(args map[string]any, result any, status string) string {
	var b strings.Builder
	b.WriteString(dimS().Render(proxyIcon))
	action := stringValue(args["action"])
	actionText, ok := scopeActionMap[action]
	if !ok {
		if action != "" {
			actionText = action + "ing"
		} else {
			actionText = "managing"
		}
	}
	b.WriteString(col(cCyan).Render(" " + actionText + " proxy scope"))
	if sn := stringValue(args["scope_name"]); sn != "" {
		b.WriteString(dimS().Italic(true).Render(" '" + ptrunc(sn, 50) + "'"))
	}
	if sid := stringValue(args["scope_id"]); sid != "" {
		b.WriteString(dimS().Render(" #" + truncStr(sid, 8)))
	}
	writeList := func(key, label string) {
		if items, ok := args[key].([]any); ok && len(items) > 0 {
			shown := items
			if len(shown) > 4 {
				shown = shown[:4]
			}
			var parts []string
			for _, it := range shown {
				parts = append(parts, ptrunc(stringValue(it), 40))
			}
			b.WriteString("\n  " + dimS().Render(label+": "+strings.Join(parts, ", ")))
			if len(items) > 4 {
				b.WriteString(dimS().Italic(true).Render(fmt.Sprintf(" +%d", len(items)-4)))
			}
		}
	}
	writeList("allowlist", "allow")
	writeList("denylist", "deny")
	if status == "completed" {
		if m, ok := resultMapOf(result); ok {
			switch {
			case m["error"] != nil:
				b.WriteString(col(red).Render("  error: " + psanitize(stringValue(m["error"]), 150)))
			case m["scopes"] != nil:
				scopes, _ := m["scopes"].([]any)
				b.WriteString(dimS().Render(fmt.Sprintf("  [%d scopes]", len(scopes))))
				renderScopeList(&b, scopes)
			case m["scope"] != nil:
				if scope, ok := m["scope"].(map[string]any); ok {
					if allow, ok := scope["allowlist"].([]any); ok && len(allow) > 0 {
						b.WriteString("\n  " + dimS().Render("allow: "+joinTrunc(allow, 40, 5)))
					}
					if deny, ok := scope["denylist"].([]any); ok && len(deny) > 0 {
						b.WriteString("\n  " + dimS().Render("deny: "+joinTrunc(deny, 40, 5)))
					}
				}
			case m["message"] != nil:
				b.WriteString(col(green).Render("  " + stringValue(m["message"])))
			}
		}
	}
	return b.String()
}

func renderScopeList(b *strings.Builder, scopes []any) {
	if len(scopes) == 0 {
		return
	}
	b.WriteString("\n")
	limit := len(scopes)
	if limit > 5 {
		limit = 5
	}
	for i := 0; i < limit; i++ {
		scope, ok := scopes[i].(map[string]any)
		if !ok {
			continue
		}
		name := stringValue(scope["name"])
		if name == "" {
			name = "?"
		}
		b.WriteString("  " + col(green).Render(ptrunc(name, 40)))
		if allow, ok := scope["allowlist"].([]any); ok && len(allow) > 0 {
			b.WriteString(dimS().Render("  " + joinTrunc(allow, 30, 3)))
			if len(allow) > 3 {
				b.WriteString(dimS().Italic(true).Render(fmt.Sprintf(" +%d", len(allow)-3)))
			}
		}
		if i < limit-1 {
			b.WriteString("\n")
		}
	}
}

// ---------------------------------------------------------------------------
// Simple tools (think, web_search, load_skill) + generic fallback
// ---------------------------------------------------------------------------

func renderThink(args map[string]any) string {
	thought := stringValue(args["thought"])
	var b strings.Builder
	b.WriteString("🧠 " + boldC(cPurple).Render("Thinking") + "\n  ")
	if thought != "" {
		b.WriteString(dimS().Italic(true).Render(thought))
	} else {
		b.WriteString(dimS().Italic(true).Render("Thinking..."))
	}
	return b.String()
}

func renderWebSearch(args map[string]any) string {
	query := stringValue(args["query"])
	var b strings.Builder
	b.WriteString("🌐 " + boldC(cInfoBlue).Render("Searching the web..."))
	if query != "" {
		b.WriteString("\n  " + dimS().Render(query))
	}
	return b.String()
}

func renderLoadSkill(args map[string]any, result any) string {
	var requested string
	if list, ok := args["skills"].([]any); ok {
		var parts []string
		for _, s := range list {
			parts = append(parts, stringValue(s))
		}
		requested = strings.Join(parts, ", ")
	} else {
		requested = stringValue(args["skills"])
	}
	var b strings.Builder
	b.WriteString(col(cEmerald).Render("◇ ") + dimS().Render("loading skill"))
	if requested != "" {
		b.WriteString(" " + col(cEmerald).Render(requested))
	} else if result == nil {
		b.WriteString("\n  " + dimS().Render("Loading..."))
	}
	return b.String()
}

// statusIcon ports BaseToolRenderer.status_icon.
func statusIcon(status string) (string, lipgloss.Style) {
	switch status {
	case "running":
		return "● In progress...", col(cAmberY)
	case "completed":
		return "✓ Done", col(green)
	case "failed":
		return "✗ Failed", col(cSevCrit)
	case "error":
		return "✗ Error", col(cSevCrit)
	}
	return "○ Unknown", dimS()
}

// renderGenericTool ports registry._render_default_tool_widget.
func renderGenericTool(name string, args map[string]any, result any, status string) string {
	var b strings.Builder
	b.WriteString(dimS().Render("→ Using tool ") + boldC(blue).Render(name) + "\n")
	for _, k := range sortedKeys(args) {
		b.WriteString("  " + dimS().Render(k) + ": " + stringValue(args[k]) + "\n")
	}
	if (status == "completed" || status == "failed" || status == "error") && result != nil {
		b.WriteString(lipgloss.NewStyle().Bold(true).Render("Result: ") + stringValue(result))
	} else {
		icon, style := statusIcon(status)
		b.WriteString(style.Render(icon))
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

func renderTool(data map[string]any, width int) string {
	name := stringValue(data["tool_name"])
	status := stringValue(data["status"])
	args, _ := data["args"].(map[string]any)
	if args == nil {
		args = map[string]any{}
	}
	result := data["result"]

	switch name {
	case "exec_command":
		return renderExecCommand(args, result, status)
	case "write_stdin":
		return renderWriteStdin(args, result, status)
	case "apply_patch":
		return renderApplyPatch(args, result, status)
	case "view_image":
		return renderViewImage(args, result)
	case "create_vulnerability_report":
		return renderVulnerabilityReport(args, result)
	case "create_dependency_report":
		return renderDependencyReport(args, result)
	case "finish_scan":
		return renderFinishScan(args)
	case "think":
		return renderThink(args)
	case "web_search":
		return renderWebSearch(args)
	case "load_skill":
		return renderLoadSkill(args, result)
	case "create_note", "delete_note", "update_note", "list_notes", "get_note":
		return renderNote(name, args, result)
	case "create_todo", "list_todos", "update_todo", "mark_todo_done", "mark_todo_pending", "delete_todo":
		return renderTodo(name, result)
	case "view_agent_graph", "create_agent", "send_message_to_agent", "agent_finish", "wait_for_message", "stop_agent":
		return renderAgentGraphTool(name, args, result)
	case "list_requests", "view_request", "repeat_request", "list_sitemap", "view_sitemap_entry", "scope_rules":
		return renderProxyTool(name, args, result, status)
	}
	return renderGenericTool(name, args, result, status)
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case nil:
		return false
	}
	return v != nil
}

func numericValue(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	}
	return 0, false
}

func truncStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func lastN(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

func firstN(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func joinTrunc(items []any, max, limit int) string {
	shown := items
	if len(shown) > limit {
		shown = shown[:limit]
	}
	var parts []string
	for _, it := range shown {
		parts = append(parts, ptrunc(stringValue(it), max))
	}
	return strings.Join(parts, ", ")
}

// stripControlsKeepTabs drops control bytes except \t and \n (shell cleaning).
func stripControlsKeepTabs(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 32 {
			return r
		}
		return -1
	}, s)
}
