package render

import (
	"strings"
)

// ---------------------------------------------------------------------------
// Finish scan (finish_renderer.py)
// ---------------------------------------------------------------------------

func renderFinishScan(args map[string]any) string {
	var b strings.Builder
	b.WriteString(Col(Green).Render("◆ ") + Bold(Green).Render("Penetration test completed"))
	section := func(label, value string) {
		if value != "" {
			b.WriteString("\n\n" + Bold(Field).Render(label) + "\n" + value)
		}
	}
	es := StringValue(args["executive_summary"])
	me := StringValue(args["methodology"])
	ta := StringValue(args["technical_analysis"])
	re := StringValue(args["recommendations"])
	section("Executive Summary", es)
	section("Methodology", me)
	section("Technical Analysis", ta)
	section("Recommendations", re)
	if es == "" && me == "" && ta == "" && re == "" {
		b.WriteString("\n  " + Dim().Render("Generating final report..."))
	}
	return "\n\n" + b.String() + "\n\n"
}
