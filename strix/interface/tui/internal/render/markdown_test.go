package render

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestHighlightCodeColorsKnownLanguage(t *testing.T) {
	out := HighlightCode("def main():\n    return 1", "python")
	if !strings.Contains(out, "\x1b[") {
		t.Fatal("python code was not colorized")
	}
	if ansi.Strip(out) != "def main():\n    return 1" {
		t.Fatalf("highlighting changed the code text: %q", ansi.Strip(out))
	}
}

func TestMarkdownCodeFenceIsHighlighted(t *testing.T) {
	out := renderAssistantMarkdown("intro\n```python\nimport os\n```\ndone")
	plain := ansi.Strip(out)
	if !strings.Contains(plain, "import os") {
		t.Fatalf("code fence content missing: %q", plain)
	}
	if strings.Contains(plain, "```") {
		t.Fatalf("fence markers leaked into output: %q", plain)
	}
}

func TestParseFencedCode(t *testing.T) {
	lang, code := ParseFencedCode("```python\nprint(1)\n```")
	if lang != "python" || code != "print(1)" {
		t.Fatalf("got lang=%q code=%q", lang, code)
	}
	lang, code = ParseFencedCode("plain text")
	if lang != "" || code != "plain text" {
		t.Fatalf("unfenced text mangled: lang=%q code=%q", lang, code)
	}
}

func TestMarkdownTableIsAligned(t *testing.T) {
	out := renderAssistantMarkdown(strings.Join([]string{
		"| Name | Severity |",
		"| --- | --- |",
		"| SQLi | **high** |",
		"| XSS | low |",
	}, "\n"))
	plain := ansi.Strip(out)
	lines := strings.Split(plain, "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 table rows, got %d: %q", len(lines), plain)
	}
	if !strings.Contains(lines[0], "Name") || !strings.Contains(lines[0], "│") {
		t.Fatalf("header row not formatted: %q", lines[0])
	}
	if !strings.Contains(lines[1], "─┼─") {
		t.Fatalf("separator rule missing: %q", lines[1])
	}
	if !strings.Contains(lines[2], "high") || strings.Contains(lines[2], "**") {
		t.Fatalf("body cell not inline-formatted: %q", lines[2])
	}
	if strings.Index(lines[2], "│") != strings.Index(lines[3], "│") {
		t.Fatalf("columns misaligned:\n%q\n%q", lines[2], lines[3])
	}
}

func TestNonTablePipeLinesAreLeftAlone(t *testing.T) {
	out := renderAssistantMarkdown("a | b\nplain line")
	if !strings.Contains(ansi.Strip(out), "a | b") {
		t.Fatalf("pipe text mangled: %q", ansi.Strip(out))
	}
}

func TestMarkdownOrderedListsUseSingleSpaceAfterMarker(t *testing.T) {
	out := renderAssistantMarkdown("1. hello\n2) world")
	plain := ansi.Strip(out)
	for _, want := range []string{"1. hello", "2) world"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("ordered list item %q missing: %q", want, plain)
		}
	}
	if strings.Contains(plain, "1.  hello") || strings.Contains(plain, "2)  world") {
		t.Fatalf("double space after the list marker: %q", plain)
	}
}

func TestInlineFormatKeepsNonEmphasisMarkers(t *testing.T) {
	literal := []string{
		"ls *.py *.go",
		"snake_case_name and other_var_here",
		"a * b * c",
		"call obj.__init__ now",
		"rm -rf /tmp/* /var/*",
		"5 * 3 = 15",
	}
	for _, line := range literal {
		if got := ansi.Strip(inlineFormat(line)); got != line {
			t.Fatalf("%q was treated as emphasis: %q", line, got)
		}
	}
}

func TestInlineFormatStillStylesRealEmphasis(t *testing.T) {
	cases := map[string]string{
		"this is *italic* text": "this is italic text",
		"this is **bold** text": "this is bold text",
		"gone ~~away~~ now":     "gone away now",
		"use `code` here":       "use code here",
	}
	for line, want := range cases {
		if got := ansi.Strip(inlineFormat(line)); got != want {
			t.Fatalf("%q: got %q want %q", line, got, want)
		}
	}
}
