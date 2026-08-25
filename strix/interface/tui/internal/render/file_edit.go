package render

import (
	"strings"
)

// ---------------------------------------------------------------------------
// Filesystem: apply_patch + view_image (filesystem_renderer.py)
// ---------------------------------------------------------------------------

const (
	addFilePfx    = "*** Add File: "
	deleteFilePfx = "*** Delete File: "
	updateFilePfx = "*** Update File: "
	beginPatch    = "*** Begin Patch"
	endPatch      = "*** End Patch"
)

type patchOp struct {
	kind string
	path string
	old  []string
	new  []string
}

func extractPatchText(args map[string]any) string {
	if raw, ok := args["patch"].(string); ok {
		return raw
	}
	if raw, ok := args["patch"].(map[string]any); ok {
		if inner, ok := raw["patch"].(string); ok {
			return inner
		}
	}
	if fb, ok := args["input"].(string); ok {
		return fb
	}
	return ""
}

func parsePatchOperations(patch string) []patchOp {
	var ops []patchOp
	var cur *patchOp
	flush := func() {
		if cur != nil && cur.kind != "" {
			ops = append(ops, *cur)
		}
		cur = nil
	}
	for _, line := range strings.Split(patch, "\n") {
		switch {
		case line == beginPatch || line == endPatch:
			continue
		case strings.HasPrefix(line, addFilePfx):
			flush()
			cur = &patchOp{kind: "add", path: strings.TrimSpace(line[len(addFilePfx):])}
		case strings.HasPrefix(line, updateFilePfx):
			flush()
			cur = &patchOp{kind: "update", path: strings.TrimSpace(line[len(updateFilePfx):])}
		case strings.HasPrefix(line, deleteFilePfx):
			flush()
			cur = &patchOp{kind: "delete", path: strings.TrimSpace(line[len(deleteFilePfx):])}
		case cur != nil && cur.kind == "update":
			if strings.HasPrefix(line, "@@") {
				continue
			}
			if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
				cur.old = append(cur.old, line[1:])
			} else if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
				cur.new = append(cur.new, line[1:])
			}
		case cur != nil && cur.kind == "add":
			if strings.HasPrefix(line, "+") {
				cur.new = append(cur.new, line[1:])
			} else if strings.TrimSpace(line) != "" {
				cur.new = append(cur.new, line)
			}
		}
	}
	flush()
	return ops
}

var opLabel = map[string]string{"add": "create", "update": "edit", "delete": "delete"}

func renderPatchOperation(b *strings.Builder, op patchOp) {
	label := opLabel[op.kind]
	if label == "" {
		label = "file"
	}
	b.WriteString(Col(Emerald).Render("◇ ") + Dim().Render(label))
	if op.path != "" {
		p := op.path
		if len(p) > 60 {
			p = p[len(p)-60:]
		}
		b.WriteString(" " + Dim().Render(p))
	}
	lang := languageForPath(op.path)
	if op.kind == "update" {
		for _, line := range highlightLines(op.old, lang) {
			b.WriteString("\n" + Col(Red).Render("-") + " " + line)
		}
		for _, line := range highlightLines(op.new, lang) {
			b.WriteString("\n" + Col(Green).Render("+") + " " + line)
		}
	} else if op.kind == "add" && len(op.new) > 0 {
		b.WriteString("\n" + HighlightCode(strings.Join(op.new, "\n"), lang))
	}
}

func highlightLines(lines []string, lang string) []string {
	if len(lines) == 0 || lang == "" {
		return lines
	}
	return strings.Split(HighlightCode(strings.Join(lines, "\n"), lang), "\n")
}

func renderApplyPatch(args map[string]any, result any, status string) string {
	ops := parsePatchOperations(extractPatchText(args))
	var b strings.Builder
	if len(ops) == 0 {
		b.WriteString(Col(Emerald).Render("◇ ") + Dim().Render("patch"))
		if s, ok := result.(string); ok && strings.TrimSpace(s) != "" {
			b.WriteString("\n  " + Dim().Render(strings.TrimSpace(s)))
		} else if result == nil {
			b.WriteString(" " + Dim().Render("Processing..."))
		}
		return b.String()
	}
	for i, op := range ops {
		if i > 0 {
			b.WriteString("\n")
		}
		renderPatchOperation(&b, op)
	}
	if status == "blocked" {
		b.WriteString("\n  " + safetyBlockLine(result))
	}
	if status == "failed" {
		if s, ok := result.(string); ok && strings.TrimSpace(s) != "" {
			b.WriteString("\n  " + Col(Red).Render(strings.TrimSpace(s)))
		}
	}
	return b.String()
}
