package render

import (
	"strings"
)

func renderViewImage(args map[string]any, result any) string {
	path := strings.TrimSpace(StringValue(args["path"]))
	var b strings.Builder
	b.WriteString(Col(Emerald).Render("◇ ") + Dim().Render("view image"))
	if path != "" {
		if len(path) > 60 {
			path = path[len(path)-60:]
		}
		b.WriteString(" " + Dim().Render(path))
	}
	if s, ok := result.(string); ok {
		low := strings.ToLower(strings.TrimSpace(s))
		if strings.HasPrefix(low, "image path ") || strings.HasPrefix(low, "unable to read image") ||
			strings.HasPrefix(low, "manifest path") || strings.HasPrefix(low, "exceeded the allowed size") ||
			strings.Contains(low, "not a supported image") {
			b.WriteString("\n  " + Col(Red).Render(strings.TrimSpace(s)))
			return b.String()
		}
	}
	if isImageSuccess(result) {
		b.WriteString("  " + Col(Green).Render("✓"))
	}
	return b.String()
}

func isImageSuccess(result any) bool {
	if m, ok := result.(map[string]any); ok {
		return StringValue(m["type"]) == "image"
	}
	if s, ok := result.(string); ok {
		return strings.HasPrefix(strings.TrimLeft(s, " \t\n"), "data:image/")
	}
	return false
}
