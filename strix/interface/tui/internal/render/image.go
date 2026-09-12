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

var imageMimes = []string{"png", "jpeg", "jpg", "gif", "webp"}

func isBase64Byte(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' ||
		b == '+' || b == '/' || b == '='
}

// parseImageDataURI scans a data URI without a regexp: payloads run to
// megabytes and the regexp engine is far too slow to walk them per frame.
func parseImageDataURI(s string) (mime, payload string) {
	start := strings.Index(s, "data:image/")
	if start < 0 {
		return "", ""
	}
	rest := s[start+len("data:image/"):]
	for _, candidate := range imageMimes {
		if !strings.HasPrefix(rest, candidate+";base64,") {
			continue
		}
		data := rest[len(candidate)+len(";base64,"):]
		end := len(data)
		for i := range len(data) {
			if !isBase64Byte(data[i]) {
				end = i
				break
			}
		}
		if candidate == "jpg" {
			candidate = "jpeg"
		}
		return candidate, data[:end]
	}
	return "", ""
}

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
	mime, payload = parseImageDataURI(s)
	if mime == "" || len(payload) < 100 || len(payload)%4 != 0 {
		return "", ""
	}
	return mime, payload
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
