package render

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// Report browsing (reporting_renderer.py: ListReportsRenderer, GetReportRenderer)
// ---------------------------------------------------------------------------

// listSeverityColor mirrors reporting_renderer._severity_style, whose fallback
// is medium rather than the vulnerability report's neutral gray.
func listSeverityColor(severity string) lipgloss.Color {
	switch strings.ToLower(severity) {
	case "critical":
		return SevCrit
	case "high":
		return SevHigh
	case "medium":
		return SevMed
	case "low":
		return SevLow
	case "info":
		return SevInfo
	case "none":
		return Gray
	}
	return SevMed
}

// authorLabel ports reporting_renderer._author_label.
func authorLabel(report map[string]any) string {
	if by, ok := report["by_you"].(bool); ok && by {
		return "you"
	}
	return strings.TrimSpace(StringValue(report["agent_name"]))
}

func reportSummaryLine(b *strings.Builder, report map[string]any, prefix string) {
	id := strings.TrimSpace(StringValue(report["id"]))
	title := strings.TrimSpace(StringValue(report["title"]))
	if title == "" {
		title = "(untitled)"
	}
	severity := strings.TrimSpace(StringValue(report["severity"]))
	b.WriteString(prefix)
	if severity != "" {
		b.WriteString(Bold(listSeverityColor(severity)).Render(strings.ToUpper(severity)) + " ")
	}
	if id != "" {
		b.WriteString(Dim().Render(id + " "))
	}
	b.WriteString(title)
	if author := authorLabel(report); author != "" {
		b.WriteString(Dim().Render(" (" + author + ")"))
	}
}

func renderListReports(result any) string {
	var b strings.Builder
	b.WriteString(Col(Red).Render("◆ ") + Dim().Render("reports"))

	if text, ok := result.(string); ok && strings.TrimSpace(text) != "" {
		b.WriteString("\n  " + Dim().Render(strings.TrimSpace(text)))
		return b.String()
	}

	resultMap, _ := result.(map[string]any)
	success, _ := resultMap["success"].(bool)
	if !success {
		b.WriteString("\n  " + Dim().Render("Loading..."))
		return b.String()
	}

	if total, ok := NumericValue(resultMap["total_count"]); ok {
		b.WriteString(Dim().Render(fmt.Sprintf(" (%d)", int(total))))
	} else {
		b.WriteString(Dim().Render(" (0)"))
	}
	if counts, ok := resultMap["severity_counts"].(map[string]any); ok {
		for _, severity := range SortedKeys(counts) {
			b.WriteString("  " + Col(listSeverityColor(severity)).Render(
				severity+" "+StringValue(counts[severity])))
		}
	}

	reports, _ := resultMap["reports"].([]any)
	if len(reports) == 0 {
		b.WriteString("\n  " + Dim().Render("No reports filed yet"))
		return b.String()
	}
	for _, raw := range reports {
		report, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		reportSummaryLine(&b, report, "\n  - ")
	}
	return b.String()
}

func renderGetReport(result any) string {
	var b strings.Builder
	b.WriteString(Col(Red).Render("◆ ") + Dim().Render("report read"))

	resultMap, _ := result.(map[string]any)
	success, _ := resultMap["success"].(bool)
	report, _ := resultMap["report"].(map[string]any)
	if !success || len(report) == 0 {
		detail := ""
		if hasSuccess, ok := resultMap["success"].(bool); ok && !hasSuccess {
			detail = StringValue(resultMap["error"])
		}
		if detail == "" {
			detail = "Loading..."
		}
		b.WriteString("\n  " + Dim().Render(detail))
		return b.String()
	}

	reportSummaryLine(&b, report, "\n  ")
	if target := strings.TrimSpace(StringValue(report["target"])); target != "" {
		b.WriteString("\n  " + Dim().Render(target))
	}
	return b.String()
}
