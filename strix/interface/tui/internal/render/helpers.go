package render

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

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

func NumericValue(v any) (float64, bool) {
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
		parts = append(parts, ptrunc(StringValue(it), max))
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

func StringValue(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	raw, err := json.Marshal(value)
	if err == nil {
		return string(raw)
	}
	return fmt.Sprint(value)
}

// mcpTextResult unwraps only exact MCP text envelopes. Other data stays JSON
// so metadata, images, and structured fields are never hidden by the display.
func mcpTextResult(value any) string {
	if text, ok := exactMCPText(value); ok {
		return text
	}
	if raw, ok := value.(string); ok {
		var decoded any
		if json.Unmarshal([]byte(raw), &decoded) == nil {
			if text, ok := exactMCPText(decoded); ok {
				return text
			}
		}
	}
	return StringValue(value)
}

func exactMCPText(value any) (string, bool) {
	result, ok := value.(map[string]any)
	if !ok {
		return "", false
	}
	text, ok := result["text"].(string)
	if !ok {
		return "", false
	}
	if len(result) == 1 || (len(result) == 2 && result["type"] == "text") {
		return text, true
	}
	return "", false
}
func StripControls(value string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 32 {
			return r
		}
		return -1
	}, value)
}

func SortedKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
