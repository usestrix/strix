package render

import (
	"path/filepath"
	"strings"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/formatters"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
)

// HighlightCode ports the Python renderers' pygments highlighting: colorize
// code for the terminal using the "native" style, falling back to the plain
// text when the language is unknown or the highlighter fails.
func HighlightCode(code, language string) string {
	if strings.TrimSpace(code) == "" {
		return code
	}
	var lexer chroma.Lexer
	if language != "" {
		lexer = lexers.Get(language)
	}
	if lexer == nil {
		lexer = lexers.Analyse(code)
	}
	if lexer == nil {
		return Col(Text).Render(code)
	}
	lexer = chroma.Coalesce(lexer)
	style := styles.Get("native")
	formatter := formatters.Get("terminal256")
	iterator, err := lexer.Tokenise(nil, code)
	if err != nil {
		return Col(Text).Render(code)
	}
	var out strings.Builder
	if err := formatter.Format(&out, style, iterator); err != nil {
		return Col(Text).Render(code)
	}
	return strings.TrimSuffix(out.String(), "\n")
}

// languageForPath resolves a chroma language name from a file path, returning
// "" when the extension is unknown.
func languageForPath(path string) string {
	if path == "" {
		return ""
	}
	lexer := lexers.Match(filepath.Base(path))
	if lexer == nil {
		return ""
	}
	return lexer.Config().Name
}

// ParseFencedCode ports parse_fenced_code: strip a surrounding ``` fence and
// return the declared language (if any) and the inner code.
func ParseFencedCode(raw string) (language, code string) {
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(trimmed, "```") {
		return "", raw
	}
	lines := strings.Split(trimmed, "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[len(lines)-1]) != "```" {
		return "", raw
	}
	language = strings.TrimSpace(strings.TrimPrefix(lines[0], "```"))
	return language, strings.Join(lines[1:len(lines)-1], "\n")
}
