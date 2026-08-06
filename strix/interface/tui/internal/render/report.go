package render

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// Reporting (reporting_renderer.py)
// ---------------------------------------------------------------------------

func renderVulnerabilityReport(args map[string]any, result any) string {
	resultMap, _ := result.(map[string]any)
	var b strings.Builder
	b.WriteString("🐞 " + Bold(ReportHdr).Render("Vulnerability Report"))

	field := func(label, value string) {
		if value != "" {
			b.WriteString("\n\n" + Bold(Field).Render(label+": ") + value)
		}
	}
	title := StringValue(args["title"])
	field("Title", title)

	if sev := StringValue(resultMap["severity"]); sev != "" {
		b.WriteString("\n\n" + Bold(Field).Render("Severity: ") +
			lipgloss.NewStyle().Bold(true).Foreground(SeverityColor(sev)).Render(strings.ToUpper(sev)))
	}
	if score, ok := NumericValue(resultMap["cvss_score"]); ok {
		b.WriteString("\n\n" + Bold(Field).Render("CVSS Score: ") +
			lipgloss.NewStyle().Bold(true).Foreground(CVSSColor(score)).Render(StringValue(resultMap["cvss_score"])))
	}
	field("Target", StringValue(args["target"]))
	field("Endpoint", StringValue(args["endpoint"]))
	field("Method", StringValue(args["method"]))
	field("CVE", StringValue(args["cve"]))
	field("CWE", StringValue(args["cwe"]))

	if bd, ok := args["cvss_breakdown"].(map[string]any); ok && len(bd) > 0 {
		parts := CVSSVectorParts(bd)
		if len(parts) > 0 {
			b.WriteString("\n\n" + Bold(Field).Render("CVSS Vector: ") + Dim().Render(strings.Join(parts, "/")))
		}
	}

	section := func(label, value string) {
		if value != "" {
			b.WriteString("\n\n" + Bold(Field).Render(label) + "\n" + value)
		}
	}
	section("Description", StringValue(args["description"]))
	section("Impact", StringValue(args["impact"]))
	section("Technical Analysis", StringValue(args["technical_analysis"]))
	renderCodeLocations(&b, args["code_locations"])
	section("PoC Description", StringValue(args["poc_description"]))
	if poc := StringValue(args["poc_script_code"]); poc != "" {
		b.WriteString("\n\n" + Bold(Field).Render("PoC Code") + "\n" + Col(Text).Render(poc))
	}
	section("Remediation", StringValue(args["remediation_steps"]))

	if title == "" {
		b.WriteString("\n  " + Dim().Render("Creating report..."))
	}
	return "\n\n" + b.String() + "\n\n"
}

var cvssKeys = [][2]string{
	{"attack_vector", "AV"}, {"attack_complexity", "AC"}, {"privileges_required", "PR"},
	{"user_interaction", "UI"}, {"scope", "S"}, {"confidentiality", "C"},
	{"integrity", "I"}, {"availability", "A"},
}

func CVSSVectorParts(bd map[string]any) []string {
	var parts []string
	for _, kp := range cvssKeys {
		if v := StringValue(bd[kp[0]]); v != "" {
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
	b.WriteString("\n\n" + Bold(Field).Render("Code Locations"))
	for i, l := range locs {
		loc, ok := l.(map[string]any)
		if !ok {
			continue
		}
		b.WriteString("\n\n" + Dim().Render(fmt.Sprintf("  Location %d: ", i+1)))
		file := StringValue(loc["file"])
		if file == "" {
			file = "unknown"
		}
		b.WriteString(Bold(InfoBlue).Render(file))
		if start, ok := NumericValue(loc["start_line"]); ok {
			if end, ok := NumericValue(loc["end_line"]); ok && end != start {
				b.WriteString(Col(LineNum).Render(fmt.Sprintf(":%d-%d", int(start), int(end))))
			} else {
				b.WriteString(Col(LineNum).Render(fmt.Sprintf(":%d", int(start))))
			}
		}
		if label := StringValue(loc["label"]); label != "" {
			b.WriteString(lipgloss.NewStyle().Italic(true).Foreground(Label).Render("\n  " + label))
		}
		if snip := StringValue(loc["snippet"]); snip != "" {
			b.WriteString("\n  " + Col(Snippet).Render(snip))
		}
		before, after := StringValue(loc["fix_before"]), StringValue(loc["fix_after"])
		if before != "" || after != "" {
			b.WriteString("\n  " + Dim().Render("Fix:"))
			if before != "" {
				b.WriteString("\n  " + Col(Red).Render("- ") + Col(Red).Render(before))
			}
			if after != "" {
				b.WriteString("\n  " + Col(Green).Render("+ ") + Col(Green).Render(after))
			}
		}
	}
}
