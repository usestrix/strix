// Package render turns chat and tool events into styled terminal output,
// with one file per tool renderer.
package render

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Colors and shared lipgloss style helpers used across the renderers.
// Rich's "dim" attribute maps to lipgloss Faint.
var (
	Green     = lipgloss.Color("#22c55e")
	Blue      = lipgloss.Color("#3b82f6")
	Red       = lipgloss.Color("#ef4444")
	Text      = lipgloss.Color("#d4d4d4")
	Field     = lipgloss.Color("#4ade80") // FIELD_STYLE base (bold)
	ReportHdr = lipgloss.Color("#ea580c") // report title / orange
	SevCrit   = lipgloss.Color("#dc2626")
	SevHigh   = lipgloss.Color("#ea580c")
	SevMed    = lipgloss.Color("#d97706")
	SevLow    = lipgloss.Color("#65a30d")
	SevInfo   = lipgloss.Color("#0284c7")
	Gray      = lipgloss.Color("#6b7280")
	Purple    = lipgloss.Color("#a855f7") // thinking
	Lavender  = lipgloss.Color("#a78bfa") // todos / agent graph
	Emerald   = lipgloss.Color("#10b981") // skills / patch ops
	Gold      = lipgloss.Color("#fbbf24") // notes
	AmberY    = lipgloss.Color("#f59e0b") // running icon / reopened
	LineNum   = lipgloss.Color("#facc15")
	Label     = lipgloss.Color("#a1a1aa")
	Snippet   = lipgloss.Color("#e2e8f0")
	Slate     = lipgloss.Color("#94a3b8")
	Cyan      = lipgloss.Color("#06b6d4") // proxy
	Status3xx = lipgloss.Color("#eab308")
	Status4xx = lipgloss.Color("#f97316")
	Hdr16a    = lipgloss.Color("#16a34a")
	Hdr158    = lipgloss.Color("#15803d")
	Mint      = lipgloss.Color("#86efac")
	Strike    = lipgloss.Color("#525252")
	CodeBg    = lipgloss.Color("#0a0a0a")
	InfoBlue  = lipgloss.Color("#60a5fa")
)

// Style helpers. Col() foreground; Dim() Rich "dim" (faint attribute).
func Col(c lipgloss.Color) lipgloss.Style { return lipgloss.NewStyle().Foreground(c) }
func Dim() lipgloss.Style                 { return lipgloss.NewStyle().Faint(true) }
func Bold(c lipgloss.Color) lipgloss.Style {
	return lipgloss.NewStyle().Bold(true).Foreground(c)
}

// severityColor maps a severity string to the report renderer's color.
func SeverityColor(sev string) lipgloss.Color {
	switch strings.ToLower(sev) {
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
	}
	return Gray
}

func CVSSColor(score float64) lipgloss.Color {
	switch {
	case score >= 9.0:
		return SevCrit
	case score >= 7.0:
		return SevHigh
	case score >= 4.0:
		return SevMed
	case score >= 0.1:
		return SevLow
	}
	return Gray
}
