package render

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/x/ansi"
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

// truncStr and firstN keep the first n display columns of s, without splitting
// a multi-byte rune. Kept as two names since callers use both spellings for the
// same "keep the start" truncation.
func truncStr(s string, n int) string {
	return ansi.Truncate(s, n, "")
}

// lastN keeps the last n display columns of s, without splitting a multi-byte rune.
func lastN(s string, n int) string {
	if w := ansi.StringWidth(s); w > n {
		return ansi.TruncateLeft(s, w-n, "")
	}
	return s
}

func firstN(s string, n int) string {
	return ansi.Truncate(s, n, "")
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
