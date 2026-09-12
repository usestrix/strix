package render

import (
	"strings"
)

// ---------------------------------------------------------------------------
// Notes (notes_renderer.py)
// ---------------------------------------------------------------------------

func renderNote(name string, args map[string]any, result any) string {
	var b strings.Builder
	icon := Col(Gold).Render("◇ ")
	switch name {
	case "create_note":
		category := StringValue(args["category"])
		if category == "" {
			category = "general"
		}
		title, content := strings.TrimSpace(StringValue(args["title"])), strings.TrimSpace(StringValue(args["content"]))
		b.WriteString(icon + Dim().Render("note") + " " + Dim().Render("("+category+")"))
		if title != "" {
			b.WriteString("\n  " + title)
		}
		if content != "" {
			b.WriteString("\n  " + Dim().Render(content))
		}
		if title == "" && content == "" {
			b.WriteString("\n  " + Dim().Render("Capturing..."))
		}
	case "delete_note":
		b.WriteString(icon + Dim().Render("note removed"))
	case "update_note":
		title, content := StringValue(args["title"]), strings.TrimSpace(StringValue(args["content"]))
		b.WriteString(icon + Dim().Render("note updated"))
		if title != "" {
			b.WriteString("\n  " + title)
		}
		if content != "" {
			b.WriteString("\n  " + Dim().Render(content))
		}
		if title == "" && content == "" {
			b.WriteString("\n  " + Dim().Render("Updating..."))
		}
	case "list_notes":
		b.WriteString(icon + Dim().Render("notes"))
		b.WriteString(noteListBody(result))
	case "get_note":
		b.WriteString(icon + Dim().Render("note read"))
		if m, ok := result.(map[string]any); ok && truthy(m["success"]) {
			note, _ := m["note"].(map[string]any)
			renderSingleNote(&b, note)
		} else {
			b.WriteString("\n  " + Dim().Render("Loading..."))
		}
	default:
		b.WriteString(icon + Dim().Render(strings.ReplaceAll(name, "_", " ")))
	}
	return b.String()
}

func noteListBody(result any) string {
	var b strings.Builder
	if s, ok := result.(string); ok && strings.TrimSpace(s) != "" {
		return "\n  " + Dim().Render(strings.TrimSpace(s))
	}
	m, ok := result.(map[string]any)
	if !ok || !truthy(m["success"]) {
		return "\n  " + Dim().Render("Loading...")
	}
	notes, _ := m["notes"].([]any)
	count, _ := NumericValue(m["total_count"])
	if int(count) == 0 || len(notes) == 0 {
		return "\n  " + Dim().Render("No notes")
	}
	for _, n := range notes {
		note, _ := n.(map[string]any)
		title := strings.TrimSpace(StringValue(note["title"]))
		if title == "" {
			title = "(untitled)"
		}
		category := StringValue(note["category"])
		if category == "" {
			category = "general"
		}
		content := strings.TrimSpace(StringValue(note["content"]))
		if content == "" {
			content = strings.TrimSpace(StringValue(note["content_preview"]))
		}
		b.WriteString("\n  - " + title + Dim().Render(" ("+category+")"))
		if content != "" {
			b.WriteString("\n    " + Dim().Render(content))
		}
	}
	return b.String()
}

func renderSingleNote(b *strings.Builder, note map[string]any) {
	title := strings.TrimSpace(StringValue(note["title"]))
	if title == "" {
		title = "(untitled)"
	}
	category := StringValue(note["category"])
	if category == "" {
		category = "general"
	}
	b.WriteString("\n  " + title + Dim().Render(" ("+category+")"))
	if content := strings.TrimSpace(StringValue(note["content"])); content != "" {
		b.WriteString("\n  " + Dim().Render(content))
	}
}
