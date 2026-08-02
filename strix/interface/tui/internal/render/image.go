package render

import (
	"regexp"
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
		if KittyGraphicsSupported() {
			if mime, payload := extractImageDataURI(result); mime != "" {
				if block := kittyImageBlock(mime, payload); block != "" {
					b.WriteString("\n" + block)
				}
			}
		}
	}
	return b.String()
}

var imageDataURIRE = regexp.MustCompile(`data:image/(png|jpe?g|gif|webp);base64,([A-Za-z0-9+/]+={0,2})`)

// extractImageDataURI pulls a base64 image payload out of a view_image tool
// result: a raw data URI or a structured map with an image_url/url field.
func extractImageDataURI(result any) (mime, payload string) {
	var s string
	switch v := result.(type) {
	case string:
		s = v
	case map[string]any:
		if u := StringValue(v["image_url"]); u != "" {
			s = u
		} else if u := StringValue(v["url"]); u != "" {
			s = u
		}
	}
	if s == "" {
		return "", ""
	}
	m := imageDataURIRE.FindStringSubmatch(s)
	if m == nil || len(m[2]) < 100 || len(m[2])%4 != 0 {
		return "", ""
	}
	return m[1], m[2]
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
