package render

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func renderDependencyReport(args map[string]any, result any) string {
	resultMap, _ := result.(map[string]any)
	// Unsuccessful / not-persisted variants.
	if resultMap != nil {
		success, hasSuccess := resultMap["success"].(bool)
		warning := StringValue(resultMap["warning"])
		if (hasSuccess && !success) || warning != "" {
			return renderDependencyUnsuccessful(args, resultMap)
		}
	}
	var b strings.Builder
	b.WriteString("📦 " + Bold(ReportHdr).Render("Dependency (SCA) Report"))
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
	if score, ok := NumericValue(args["advisory_cvss"]); ok {
		b.WriteString("\n\n" + Bold(Field).Render("Advisory CVSS: ") +
			lipgloss.NewStyle().Bold(true).Foreground(CVSSColor(score)).Render(StringValue(args["advisory_cvss"])))
	}
	field("CVE", StringValue(args["cve"]))
	field("CWE", StringValue(args["cwe"]))
	if pkg := StringValue(args["package_name"]); pkg != "" {
		b.WriteString("\n\n" + Bold(Field).Render("Package: ") + Bold(InfoBlue).Render(pkg))
		if eco := StringValue(args["package_ecosystem"]); eco != "" {
			b.WriteString(Dim().Render(" (" + eco + ")"))
		}
	}
	if inst := StringValue(args["installed_version"]); inst != "" {
		b.WriteString("\n\n" + Bold(Field).Render("Installed: ") + Col(Red).Render(inst))
		if fixed := StringValue(args["fixed_version"]); fixed != "" {
			b.WriteString(Dim().Render("  →  ") + Bold(Field).Render("Fixed: ") + Col(Green).Render(fixed))
		}
	}
	field("Fix Effort", StringValue(args["fix_effort"]))
	field("Target", StringValue(args["target"]))
	section := func(label, value string) {
		if value != "" {
			b.WriteString("\n\n" + Bold(Field).Render(label) + "\n" + value)
		}
	}
	section("Description", StringValue(args["description"]))
	section("Impact", StringValue(args["impact"]))
	section("Technical Analysis", StringValue(args["technical_analysis"]))
	section("Assumptions", StringValue(args["assumptions"]))
	section("Remediation", StringValue(args["remediation_steps"]))
	if title == "" {
		b.WriteString("\n  " + Dim().Render("Creating dependency report..."))
	}
	return "\n\n" + b.String() + "\n\n"
}

func renderDependencyUnsuccessful(args, result map[string]any) string {
	var b strings.Builder
	b.WriteString("📦 " + Bold(ReportHdr).Render("Dependency (SCA) Report"))
	if title := StringValue(args["title"]); title != "" {
		b.WriteString("\n\n" + Bold(Field).Render("Title: ") + title)
	}
	success, hasSuccess := result["success"].(bool)
	var label, detail string
	var style lipgloss.Style
	if hasSuccess && !success {
		detail = StringValue(result["error"])
		if errs, ok := result["errors"].([]any); ok && len(errs) > 0 {
			var parts []string
			for _, e := range errs {
				parts = append(parts, StringValue(e))
			}
			detail = strings.Join(parts, "; ")
		}
		label, style = "✗ Not created: ", Bold(SevCrit)
		if detail == "" {
			detail = "Report was not created."
		}
	} else {
		detail = StringValue(result["warning"])
		label, style = "⚠ Not persisted: ", Bold(SevMed)
		if detail == "" {
			detail = "Report could not be persisted."
		}
	}
	b.WriteString("\n\n" + style.Render(label) + detail)
	return "\n\n" + b.String() + "\n\n"
}
