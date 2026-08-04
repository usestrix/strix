package app

// Markdown clipboard report for the vulnerability detail dialog, porting
// VulnerabilityDetailScreen._get_markdown_report plus the report-writer fence
// helpers (safe_fence, guess_language_name).

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/alecthomas/chroma/v2/lexers"

	"github.com/usestrix/strix/tui/internal/render"
)

var backtickRun = regexp.MustCompile("`+")

// safeFence returns a backtick fence that content cannot break out of: one
// backtick longer than the longest run inside it, never fewer than three.
func safeFence(content string) string {
	longest := 0
	for _, run := range backtickRun.FindAllString(content, -1) {
		longest = max(longest, len(run))
	}
	return strings.Repeat("`", max(3, longest+1))
}

// guessLanguageName returns a markdown fence tag for code, defaulting to
// "python" when auto-detection is inconclusive (legacy PoC scripts are Python).
func guessLanguageName(code string) string {
	lexer := lexers.Analyse(code)
	if lexer == nil {
		return "python"
	}
	config := lexer.Config()
	if config == nil || len(config.Aliases) == 0 || config.Name == "plaintext" {
		return "python"
	}
	return config.Aliases[0]
}

func titleCaseWords(text string) string {
	words := strings.Fields(text)
	for i, word := range words {
		words[i] = titleCase(word)
	}
	return strings.Join(words, " ")
}

// vulnerabilityMarkdownReport builds the Markdown vulnerability report copied
// to the clipboard, field-for-field with the old Textual screen.
func vulnerabilityMarkdownReport(v map[string]any) string {
	var lines []string

	title := render.StringValue(v["title"])
	if title == "" {
		title = "Untitled Vulnerability"
	}
	lines = append(lines, "# "+title, "")

	field := func(label, value string) {
		if value != "" {
			lines = append(lines, fmt.Sprintf("**%s:** %s", label, value))
		}
	}
	field("ID", render.StringValue(v["id"]))
	field("Severity", strings.ToUpper(render.StringValue(v["severity"])))
	field("Found", render.StringValue(v["timestamp"]))
	field("Agent", render.StringValue(v["agent_name"]))
	field("Target", render.StringValue(v["target"]))
	if dep, ok := v["dependency_metadata"].(map[string]any); ok {
		field("Package", render.StringValue(dep["package_name"]))
		field("Ecosystem", render.StringValue(dep["package_ecosystem"]))
		field("Installed Version", render.StringValue(dep["installed_version"]))
		field("Fixed Version", render.StringValue(dep["fixed_version"]))
	}
	field("Endpoint", render.StringValue(v["endpoint"]))
	field("Method", render.StringValue(v["method"]))
	field("CVE", render.StringValue(v["cve"]))
	field("CWE", render.StringValue(v["cwe"]))
	field("CVSS", render.StringValue(v["cvss"]))
	if fe := render.StringValue(v["fix_effort"]); fe != "" {
		field("Fix Effort", titleCaseWords(fe))
	}
	if bd, ok := v["cvss_breakdown"].(map[string]any); ok && len(bd) > 0 {
		if parts := render.CVSSVectorParts(bd); len(parts) > 0 {
			field("CVSS Vector", strings.Join(parts, "/"))
		}
	}

	description := render.StringValue(v["description"])
	if description == "" {
		description = "No description provided."
	}
	lines = append(lines, "", "## Description", "", description)

	section := func(label, value string) {
		if value != "" {
			lines = append(lines, "", "## "+label, "", value)
		}
	}
	section("Impact", render.StringValue(v["impact"]))
	section("Technical Analysis", render.StringValue(v["technical_analysis"]))
	section("Evidence", render.StringValue(v["evidence"]))

	pocDescription := render.StringValue(v["poc_description"])
	pocScript := render.StringValue(v["poc_script_code"])
	if pocDescription != "" || pocScript != "" {
		lines = append(lines, "", "## Proof of Concept", "")
		if pocDescription != "" {
			lines = append(lines, pocDescription, "")
		}
		if pocScript != "" {
			pocLang, pocCode := render.ParseFencedCode(pocScript)
			if pocLang == "" {
				pocLang = guessLanguageName(pocCode)
			}
			fence := safeFence(pocCode)
			lines = append(lines, fence+pocLang, pocCode, fence)
		}
	}

	if locations, ok := v["code_locations"].([]any); ok && len(locations) > 0 {
		lines = append(lines, "", "## Code Analysis", "")
		for i, item := range locations {
			loc, ok := item.(map[string]any)
			if !ok {
				continue
			}
			file := render.StringValue(loc["file"])
			if file == "" {
				file = "unknown"
			}
			lineRef := ""
			if start := render.StringValue(loc["start_line"]); start != "" {
				if end := render.StringValue(loc["end_line"]); end != "" && end != start {
					lineRef = fmt.Sprintf(" (lines %s-%s)", start, end)
				} else {
					lineRef = fmt.Sprintf(" (line %s)", start)
				}
			}
			lines = append(lines, fmt.Sprintf("**Location %d:** `%s`%s", i+1, file, lineRef))
			if label := render.StringValue(loc["label"]); label != "" {
				lines = append(lines, "  "+label)
			}
			if snippet := render.StringValue(loc["snippet"]); snippet != "" {
				fence := safeFence(snippet)
				lines = append(lines, fence+"\n"+snippet+"\n"+fence)
			}
			before := render.StringValue(loc["fix_before"])
			after := render.StringValue(loc["fix_after"])
			if before != "" || after != "" {
				lines = append(lines, "**Suggested Fix:**", "```diff")
				if before != "" {
					for _, l := range strings.Split(before, "\n") {
						lines = append(lines, "- "+l)
					}
				}
				if after != "" {
					for _, l := range strings.Split(after, "\n") {
						lines = append(lines, "+ "+l)
					}
				}
				lines = append(lines, "```")
			}
			lines = append(lines, "")
		}
	}

	section("Remediation", render.StringValue(v["remediation_steps"]))
	section("Assumptions", render.StringValue(v["assumptions"]))

	lines = append(lines, "")
	return strings.Join(lines, "\n")
}
