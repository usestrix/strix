package render

import (
	"testing"
	"unicode/utf8"
)

// Regression test for https://github.com/usestrix/strix/issues/1152
func TestTruncSplitsRunes(t *testing.T) {
	cases := []struct {
		name string
		out  string
	}{
		{"firstN", firstN("中文字ABC", 4)},
		{"lastN", lastN("ABC中文字", 4)},
		{"truncStr", truncStr("中文字ABC", 4)},
		{"ptrunc", ptrunc("中文字ABCDEF", 5)},
		{"truncateShellLine", truncateShellLine(repeatStr("中", maxLineLength))},
	}
	for _, c := range cases {
		if !utf8.ValidString(c.out) {
			t.Errorf("%s produced invalid UTF-8: %q", c.name, c.out)
		}
	}
}

func TestFirstNTruncStrKeepStart(t *testing.T) {
	if got := firstN("中文字ABC", 4); got != "中文" {
		t.Errorf("firstN(%q, 4) = %q, want %q", "中文字ABC", got, "中文")
	}
	if got := truncStr("中文字ABC", 4); got != "中文" {
		t.Errorf("truncStr(%q, 4) = %q, want %q", "中文字ABC", got, "中文")
	}
	if got := firstN("hello", 3); got != "hel" {
		t.Errorf("firstN(%q, 3) = %q, want %q", "hello", got, "hel")
	}
	if got := firstN("hi", 10); got != "hi" {
		t.Errorf("firstN(%q, 10) = %q, want unchanged", "hi", got)
	}
}

func TestLastNKeepsEnd(t *testing.T) {
	// Widths: A=1 B=1 C=1 中=2 文=2 字=2. Keeping the last 4 *columns* (not
	// characters) lands on 文+字 (2+2=4), matching the issue's "count columns,
	// not bytes" requirement.
	if got := lastN("ABC中文字", 4); got != "文字" {
		t.Errorf("lastN(%q, 4) = %q, want %q", "ABC中文字", got, "文字")
	}
	if got := lastN("hello", 3); got != "llo" {
		t.Errorf("lastN(%q, 3) = %q, want %q", "hello", got, "llo")
	}
	if got := lastN("hi", 10); got != "hi" {
		t.Errorf("lastN(%q, 10) = %q, want unchanged", "hi", got)
	}
}

func TestPtruncAppendsEllipsisWithinBudget(t *testing.T) {
	got := ptrunc("abcdefgh", 5)
	if got != "ab..." {
		t.Errorf("ptrunc(%q, 5) = %q, want %q", "abcdefgh", got, "ab...")
	}
	if got := ptrunc("hi", 5); got != "hi" {
		t.Errorf("ptrunc(%q, 5) = %q, want unchanged", "hi", got)
	}
}

func repeatStr(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
