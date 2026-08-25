package render

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// Proxy (proxy_renderer.py)
// ---------------------------------------------------------------------------

const proxyIcon = "<~>"

func proxyStatusStyle(code int) lipgloss.Style {
	switch {
	case code >= 200 && code < 300:
		return Col(Green)
	case code >= 300 && code < 400:
		return Col(Status3xx)
	case code >= 400 && code < 500:
		return Col(Status4xx)
	case code >= 500:
		return Col(Red)
	}
	return Dim()
}

func ptrunc(s string, max int) string {
	if len(s) > max {
		return s[:max-3] + "..."
	}
	return s
}

func psanitize(s string, max int) string {
	clean := strings.NewReplacer("\n", " ", "\r", "", "\t", " ").Replace(s)
	return ptrunc(clean, max)
}

func renderProxyTool(name string, args map[string]any, result any, status string) string {
	switch name {
	case "list_requests":
		return renderListRequests(args, result, status)
	case "view_request":
		return renderViewRequest(args, result, status)
	case "repeat_request":
		return renderRepeatRequest(args, result, status)
	case "list_sitemap":
		return renderListSitemap(args, result, status)
	case "view_sitemap_entry":
		return renderViewSitemapEntry(args, result, status)
	case "scope_rules":
		return renderScopeRules(args, result, status)
	}
	return ""
}

func resultMapOf(result any) (map[string]any, bool) {
	m, ok := result.(map[string]any)
	return m, ok
}

func renderListRequests(args map[string]any, result any, status string) string {
	var b strings.Builder
	b.WriteString(Dim().Render(proxyIcon) + Col(Cyan).Render(" listing requests"))
	if f := StringValue(args["httpql_filter"]); f != "" {
		b.WriteString(Dim().Italic(true).Render("  where " + ptrunc(f, 150)))
	}
	var meta []string
	if s := StringValue(args["sort_by"]); s != "" && s != "timestamp" {
		meta = append(meta, "by:"+s)
	}
	if s := StringValue(args["sort_order"]); s != "" && s != "desc" {
		meta = append(meta, s)
	}
	if s := StringValue(args["scope_id"]); s != "" {
		meta = append(meta, "scope:"+truncStr(s, 8))
	}
	if len(meta) > 0 {
		b.WriteString(Dim().Render("  (" + strings.Join(meta, ", ") + ")"))
	}
	if status == "completed" {
		if m, ok := resultMapOf(result); ok {
			if e, has := m["error"]; has {
				b.WriteString(Col(Red).Render("  error: " + psanitize(StringValue(e), 150)))
			} else {
				entries, _ := m["entries"].([]any)
				suffix := ""
				if pi, ok := m["page_info"].(map[string]any); ok && truthy(pi["has_next_page"]) {
					suffix = "+"
				}
				b.WriteString(Dim().Render(fmt.Sprintf("  [%d%s found]", len(entries), suffix)))
				renderRequestEntries(&b, entries)
			}
		}
	}
	return b.String()
}

func renderRequestEntries(b *strings.Builder, entries []any) {
	if len(entries) == 0 {
		return
	}
	b.WriteString("\n")
	limit := len(entries)
	if limit > 20 {
		limit = 20
	}
	for i := 0; i < limit; i++ {
		entry, ok := entries[i].(map[string]any)
		if !ok {
			continue
		}
		req, _ := entry["request"].(map[string]any)
		resp, _ := entry["response"].(map[string]any)
		method := StringValue(req["method"])
		if method == "" {
			method = "?"
		}
		host := StringValue(req["host"])
		path := StringValue(req["path"])
		if path == "" {
			path = "/"
		}
		b.WriteString("  " + Col(Lavender).Render(fmt.Sprintf("%-6s", method)))
		b.WriteString(Dim().Render(" " + ptrunc(host+path, 180)))
		if code, ok := NumericValue(resp["status_code"]); ok && code != 0 {
			b.WriteString(proxyStatusStyle(int(code)).Render(fmt.Sprintf(" %d", int(code))))
		}
		if i < limit-1 {
			b.WriteString("\n")
		}
	}
	if len(entries) > 20 {
		b.WriteString("\n" + Dim().Italic(true).Render(fmt.Sprintf("  ... +%d more", len(entries)-20)))
	}
}

func renderViewRequest(args map[string]any, result any, status string) string {
	var b strings.Builder
	b.WriteString(Dim().Render(proxyIcon))
	part := StringValue(args["part"])
	if part == "" {
		part = "request"
	}
	action := "viewing"
	search := StringValue(args["search_pattern"])
	if search != "" {
		action = "searching"
	}
	b.WriteString(Col(Cyan).Render(" " + action + " " + part))
	if rid := StringValue(args["request_id"]); rid != "" {
		b.WriteString(Dim().Render(" #" + rid))
	}
	if search != "" {
		b.WriteString(Dim().Italic(true).Render("  /" + ptrunc(search, 100) + "/"))
	}
	if status == "completed" {
		if m, ok := resultMapOf(result); ok {
			if e, has := m["error"]; has {
				b.WriteString(Col(Red).Render("  error: " + psanitize(StringValue(e), 150)))
			} else if hits, has := m["hits"].([]any); has {
				total := len(hits)
				if t, ok := NumericValue(m["total_hits"]); ok {
					total = int(t)
				}
				b.WriteString(Dim().Render(fmt.Sprintf("  [%d matches]", total)))
				renderSearchHits(&b, hits)
			} else if content, has := m["content"]; has {
				page := 1
				if p, ok := NumericValue(m["page"]); ok {
					page = int(p)
				}
				tl := 0
				if t, ok := NumericValue(m["total_lines"]); ok {
					tl = int(t)
				}
				b.WriteString(Dim().Render(fmt.Sprintf("  [page %d, %d lines]", page, tl)))
				renderContentLines(&b, StringValue(content), truthy(m["has_more"]))
			}
		}
	}
	return b.String()
}

func renderSearchHits(b *strings.Builder, hits []any) {
	if len(hits) == 0 {
		return
	}
	b.WriteString("\n")
	limit := len(hits)
	if limit > 5 {
		limit = 5
	}
	for i := 0; i < limit; i++ {
		m, ok := hits[i].(map[string]any)
		if !ok {
			continue
		}
		before := lastN(strings.NewReplacer("\n", " ", "\r", "").Replace(StringValue(m["before"])), 100)
		after := firstN(strings.NewReplacer("\n", " ", "\r", "").Replace(StringValue(m["after"])), 100)
		b.WriteString("  ")
		if before != "" {
			b.WriteString(Dim().Render("..." + before))
		}
		b.WriteString(Bold(Green).Render(StringValue(m["match"])))
		if after != "" {
			b.WriteString(Dim().Render(after + "..."))
		}
		if i < limit-1 {
			b.WriteString("\n")
		}
	}
	if len(hits) > 5 {
		b.WriteString("\n" + Dim().Italic(true).Render(fmt.Sprintf("  ... +%d more matches", len(hits)-5)))
	}
}

func renderContentLines(b *strings.Builder, content string, hasMore bool) {
	if content == "" {
		return
	}
	allLines := strings.Split(content, "\n")
	lines := allLines
	if len(lines) > 15 {
		lines = lines[:15]
	}
	b.WriteString("\n")
	for i, line := range lines {
		b.WriteString("  " + Dim().Render(ptrunc(line, maxLineLength)))
		if i < len(lines)-1 {
			b.WriteString("\n")
		}
	}
	if hasMore || len(allLines) > 15 {
		b.WriteString("\n" + Dim().Italic(true).Render("  ... more content available"))
	}
}

func renderRepeatRequest(args map[string]any, result any, status string) string {
	var b strings.Builder
	b.WriteString(Dim().Render(proxyIcon) + Col(Cyan).Render(" repeating request"))
	if rid := StringValue(args["request_id"]); rid != "" {
		b.WriteString(Dim().Render(" #" + rid))
	}
	if mods, ok := args["modifications"].(map[string]any); ok {
		b.WriteString(Dim().Italic(true).Render("\n  modifications:"))
		arrow := Col(Blue).Render("  >> ")
		if url, ok := mods["url"]; ok {
			b.WriteString("\n" + arrow + Dim().Render("url: "+ptrunc(StringValue(url), 180)))
		}
		writeKV := func(key, prefix string, valMax int) {
			if kv, ok := mods[key].(map[string]any); ok {
				n := 0
				for k, v := range kv {
					if n >= 5 {
						break
					}
					b.WriteString("\n" + arrow + Dim().Render(fmt.Sprintf(prefix, k, psanitize(StringValue(v), valMax))))
					n++
				}
			}
		}
		writeKV("headers", "%s: %s", 150)
		writeKV("cookies", "cookie %s=%s", 100)
		writeKV("params", "param %s=%s", 100)
		if body, ok := mods["body"].(string); ok {
			b.WriteString("\n" + arrow)
			bodyLines := strings.Split(body, "\n")
			shown := bodyLines
			if len(shown) > 4 {
				shown = shown[:4]
			}
			for i, line := range shown {
				if i > 0 {
					b.WriteString("\n" + Dim().Render("     "))
				}
				b.WriteString(Dim().Render(ptrunc(line, maxLineLength)))
			}
			if len(bodyLines) > 4 {
				b.WriteString(Dim().Italic(true).Render(" ..."))
			}
		}
	} else if mods, ok := args["modifications"].(string); ok && mods != "" {
		b.WriteString(Dim().Italic(true).Render("\n  " + ptrunc(mods, 200)))
	}
	if status == "blocked" {
		b.WriteString("\n  " + safetyBlockLine(result))
		return b.String()
	}
	if status == "completed" {
		if m, ok := resultMapOf(result); ok {
			success, hasSuccess := m["success"].(bool)
			if hasSuccess && !success && StringValue(m["error"]) != "" {
				b.WriteString(Col(Red).Render("\n  error: " + psanitize(StringValue(m["error"]), 150)))
			} else {
				resp, _ := m["response"].(map[string]any)
				b.WriteString("\n" + Col(Green).Render("  << "))
				if code, ok := NumericValue(resp["status_code"]); ok && code != 0 {
					b.WriteString(proxyStatusStyle(int(code)).Render(fmt.Sprintf("%d", int(code))))
				} else {
					b.WriteString(Dim().Render("(no response)"))
				}
				if ms, ok := NumericValue(m["elapsed_ms"]); ok && ms != 0 {
					b.WriteString(Dim().Render(fmt.Sprintf(" (%dms)", int(ms))))
				}
				body := StringValue(resp["body"])
				if body != "" {
					allLines := strings.Split(body, "\n")
					lines := allLines
					if len(lines) > 5 {
						lines = lines[:5]
					}
					for _, line := range lines {
						b.WriteString("\n" + Col(Green).Render("  << ") + Dim().Render(ptrunc(line, maxLineLength-5)))
					}
					if truthy(resp["body_truncated"]) || len(allLines) > 5 {
						b.WriteString("\n" + Dim().Italic(true).Render("  ..."))
					}
				}
			}
		}
	}
	return b.String()
}

func renderListSitemap(args map[string]any, result any, status string) string {
	var b strings.Builder
	b.WriteString(Dim().Render(proxyIcon) + Col(Cyan).Render(" listing sitemap"))
	if pid := StringValue(args["parent_id"]); pid != "" {
		b.WriteString(Dim().Render("  under #" + ptrunc(pid, 20)))
	}
	var meta []string
	if s := StringValue(args["scope_id"]); s != "" {
		meta = append(meta, "scope:"+truncStr(s, 8))
	}
	if d := StringValue(args["depth"]); d != "" && d != "DIRECT" {
		meta = append(meta, strings.ToLower(d))
	}
	if len(meta) > 0 {
		b.WriteString(Dim().Render("  (" + strings.Join(meta, ", ") + ")"))
	}
	if status == "completed" {
		if m, ok := resultMapOf(result); ok {
			if e, has := m["error"]; has {
				b.WriteString(Col(Red).Render("  error: " + psanitize(StringValue(e), 150)))
			} else {
				total := 0
				if t, ok := NumericValue(m["total_count"]); ok {
					total = int(t)
				}
				entries, _ := m["entries"].([]any)
				b.WriteString(Dim().Render(fmt.Sprintf("  [%d entries]", total)))
				renderSitemapEntries(&b, entries)
			}
		}
	}
	return b.String()
}

var sitemapKindColors = map[string]lipgloss.Color{
	"DOMAIN": AmberY, "DIRECTORY": Blue, "REQUEST": Green,
}

func renderSitemapEntries(b *strings.Builder, entries []any) {
	if len(entries) == 0 {
		return
	}
	b.WriteString("\n")
	limit := len(entries)
	if limit > 20 {
		limit = 20
	}
	for i := 0; i < limit; i++ {
		entry, ok := entries[i].(map[string]any)
		if !ok {
			continue
		}
		kind := StringValue(entry["kind"])
		if kind == "" {
			kind = "?"
		}
		label := StringValue(entry["label"])
		if label == "" {
			label = "?"
		}
		kindStyle, ok := sitemapKindColors[kind]
		style := Dim()
		if ok {
			style = Col(kindStyle)
		}
		abbr := kind
		if len(abbr) > 3 {
			abbr = abbr[:3]
		}
		b.WriteString("  " + style.Render(fmt.Sprintf("%-3s", abbr)) + Dim().Render(" "+ptrunc(label, 150)))
		if req, ok := entry["request"].(map[string]any); ok {
			if method := StringValue(req["method"]); method != "" {
				b.WriteString(Col(Lavender).Render(" " + method))
			}
			if code, ok := NumericValue(req["status_code"]); ok && code != 0 {
				b.WriteString(proxyStatusStyle(int(code)).Render(fmt.Sprintf(" %d", int(code))))
			}
		}
		if truthy(entry["has_descendants"]) {
			b.WriteString(Dim().Italic(true).Render(" +"))
		}
		if i < limit-1 {
			b.WriteString("\n")
		}
	}
	if len(entries) > 20 {
		b.WriteString("\n" + Dim().Italic(true).Render(fmt.Sprintf("  ... +%d more", len(entries)-20)))
	}
}

func renderViewSitemapEntry(args map[string]any, result any, status string) string {
	var b strings.Builder
	b.WriteString(Dim().Render(proxyIcon) + Col(Cyan).Render(" viewing sitemap"))
	if eid := StringValue(args["entry_id"]); eid != "" {
		b.WriteString(Dim().Render(" #" + ptrunc(eid, 20)))
	}
	if status == "completed" {
		if m, ok := resultMapOf(result); ok {
			if e, has := m["error"]; has {
				b.WriteString(Col(Red).Render("  error: " + psanitize(StringValue(e), 150)))
			} else if entry, ok := m["entry"].(map[string]any); ok {
				kind, label := StringValue(entry["kind"]), StringValue(entry["label"])
				related, _ := entry["related_requests"].(map[string]any)
				if kind != "" && label != "" {
					b.WriteString(Dim().Render(fmt.Sprintf("  %s: %s", kind, ptrunc(label, 120))))
				}
				total := 0
				if t, ok := NumericValue(related["total_count"]); ok {
					total = int(t)
				}
				if total != 0 {
					b.WriteString(Dim().Render(fmt.Sprintf("  [%d requests]", total)))
				}
				reqs, _ := related["requests"].([]any)
				renderRelatedRequests(&b, reqs)
			}
		}
	}
	return b.String()
}

func renderRelatedRequests(b *strings.Builder, reqs []any) {
	if len(reqs) == 0 {
		return
	}
	b.WriteString("\n")
	limit := len(reqs)
	if limit > 10 {
		limit = 10
	}
	for i := 0; i < limit; i++ {
		req, ok := reqs[i].(map[string]any)
		if !ok {
			continue
		}
		method := StringValue(req["method"])
		if method == "" {
			method = "?"
		}
		path := StringValue(req["path"])
		if path == "" {
			path = "/"
		}
		b.WriteString("  " + Col(Lavender).Render(fmt.Sprintf("%-6s", method)) + Dim().Render(" "+ptrunc(path, 180)))
		if code, ok := NumericValue(req["status_code"]); ok && code != 0 {
			b.WriteString(proxyStatusStyle(int(code)).Render(fmt.Sprintf(" %d", int(code))))
		}
		if i < limit-1 {
			b.WriteString("\n")
		}
	}
	if len(reqs) > 10 {
		b.WriteString("\n" + Dim().Italic(true).Render(fmt.Sprintf("  ... +%d more", len(reqs)-10)))
	}
}

var scopeActionMap = map[string]string{
	"get": "getting", "list": "listing", "create": "creating", "update": "updating", "delete": "deleting",
}

func renderScopeRules(args map[string]any, result any, status string) string {
	var b strings.Builder
	b.WriteString(Dim().Render(proxyIcon))
	action := StringValue(args["action"])
	actionText, ok := scopeActionMap[action]
	if !ok {
		if action != "" {
			actionText = action + "ing"
		} else {
			actionText = "managing"
		}
	}
	b.WriteString(Col(Cyan).Render(" " + actionText + " proxy scope"))
	if sn := StringValue(args["scope_name"]); sn != "" {
		b.WriteString(Dim().Italic(true).Render(" '" + ptrunc(sn, 50) + "'"))
	}
	if sid := StringValue(args["scope_id"]); sid != "" {
		b.WriteString(Dim().Render(" #" + truncStr(sid, 8)))
	}
	writeList := func(key, label string) {
		if items, ok := args[key].([]any); ok && len(items) > 0 {
			shown := items
			if len(shown) > 4 {
				shown = shown[:4]
			}
			var parts []string
			for _, it := range shown {
				parts = append(parts, ptrunc(StringValue(it), 40))
			}
			b.WriteString("\n  " + Dim().Render(label+": "+strings.Join(parts, ", ")))
			if len(items) > 4 {
				b.WriteString(Dim().Italic(true).Render(fmt.Sprintf(" +%d", len(items)-4)))
			}
		}
	}
	writeList("allowlist", "allow")
	writeList("denylist", "deny")
	if status == "completed" {
		if m, ok := resultMapOf(result); ok {
			switch {
			case m["error"] != nil:
				b.WriteString(Col(Red).Render("  error: " + psanitize(StringValue(m["error"]), 150)))
			case m["scopes"] != nil:
				scopes, _ := m["scopes"].([]any)
				b.WriteString(Dim().Render(fmt.Sprintf("  [%d scopes]", len(scopes))))
				renderScopeList(&b, scopes)
			case m["scope"] != nil:
				if scope, ok := m["scope"].(map[string]any); ok {
					if allow, ok := scope["allowlist"].([]any); ok && len(allow) > 0 {
						b.WriteString("\n  " + Dim().Render("allow: "+joinTrunc(allow, 40, 5)))
					}
					if deny, ok := scope["denylist"].([]any); ok && len(deny) > 0 {
						b.WriteString("\n  " + Dim().Render("deny: "+joinTrunc(deny, 40, 5)))
					}
				}
			case m["message"] != nil:
				b.WriteString(Col(Green).Render("  " + StringValue(m["message"])))
			}
		}
	}
	return b.String()
}

func renderScopeList(b *strings.Builder, scopes []any) {
	if len(scopes) == 0 {
		return
	}
	b.WriteString("\n")
	limit := len(scopes)
	if limit > 5 {
		limit = 5
	}
	for i := 0; i < limit; i++ {
		scope, ok := scopes[i].(map[string]any)
		if !ok {
			continue
		}
		name := StringValue(scope["name"])
		if name == "" {
			name = "?"
		}
		b.WriteString("  " + Col(Green).Render(ptrunc(name, 40)))
		if allow, ok := scope["allowlist"].([]any); ok && len(allow) > 0 {
			b.WriteString(Dim().Render("  " + joinTrunc(allow, 30, 3)))
			if len(allow) > 3 {
				b.WriteString(Dim().Italic(true).Render(fmt.Sprintf(" +%d", len(allow)-3)))
			}
		}
		if i < limit-1 {
			b.WriteString("\n")
		}
	}
}
