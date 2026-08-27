package render

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestRecordCoverageRendersSurfaceAndOutcome(t *testing.T) {
	out := ansi.Strip(Tool(tool("record_coverage",
		map[string]any{
			"surface":   "POST /api/v1/invoices",
			"risk_area": "object-level authorization",
			"evidence":  "tenant B token returns 403 on tenant A invoice ids",
		},
		map[string]any{"success": true, "entry_id": "a1b2c3", "outcome": "ruled_out"},
		"completed")))
	requireContains(t, out,
		"Coverage Recorded",
		"POST /api/v1/invoices",
		"object-level authorization",
		"ruled out",
		"tenant B token returns 403",
	)
}

func TestUpdateCoverageShowsStateTransition(t *testing.T) {
	out := ansi.Strip(Tool(tool("update_coverage",
		map[string]any{"entry_id": "a1b2c3", "evidence": "reproduced with a second tenant"},
		map[string]any{
			"success":          true,
			"entry_id":         "a1b2c3",
			"previous_outcome": "needs_follow_up",
			"outcome":          "reported",
		},
		"completed")))
	requireContains(t, out, "Coverage Updated", "needs follow-up", "→", "reported")
}

func TestListCoverageRendersCountsHistoryAndAuthor(t *testing.T) {
	out := ansi.Strip(Tool(tool("list_coverage", nil,
		map[string]any{
			"success": true,
			"entries": []any{
				map[string]any{
					"entry_id":          "a1b2c3",
					"surface":           "/admin/export",
					"risk_area":         "IDOR",
					"outcome":           "no_issue_found",
					"agent_name":        "AuthzAgent",
					"previous_outcomes": []any{"needs_follow_up"},
					"evidence":          "org id is server-derived from the session",
				},
				map[string]any{
					"entry_id":  "d4e5f6",
					"surface":   "/graphql",
					"risk_area": "injection",
					"outcome":   "needs_follow_up",
					"by_you":    true,
					"evidence":  "introspection disabled; needs an authenticated schema dump",
				},
			},
			"total_count":    2,
			"outcome_counts": map[string]any{"no_issue_found": 1, "needs_follow_up": 1},
		},
		"completed")))
	requireContains(t, out,
		"/admin/export", "IDOR", "no issue found",
		"was needs follow-up", "AuthzAgent",
		"/graphql", "needs follow-up", "you",
		"no issue found: 1", "needs follow-up: 1",
	)
}

func TestListCoverageEmptyLedgerReadsAsUnrecorded(t *testing.T) {
	out := ansi.Strip(Tool(tool("list_coverage", nil,
		map[string]any{"success": true, "entries": []any{}, "total_count": 0}, "completed")))
	requireContains(t, out, "No surfaces recorded yet")

	filtered := ansi.Strip(Tool(tool("list_coverage",
		map[string]any{"outcome": "reported"},
		map[string]any{"success": true, "entries": []any{}, "total_count": 4}, "completed")))
	requireContains(t, filtered, "No surfaces match this filter")
}

func TestCoverageDuplicateRejectionSurfacesTheError(t *testing.T) {
	out := ansi.Strip(Tool(tool("record_coverage",
		map[string]any{"surface": "/login", "risk_area": "XSS"},
		map[string]any{
			"success":           false,
			"error":             "'/login' (XSS) already has coverage entry a1b2c3",
			"existing_entry_id": "a1b2c3",
		},
		"completed")))
	requireContains(t, out, "/login", "already has coverage entry a1b2c3")
}

func TestGetThreatModelRendersAmendments(t *testing.T) {
	out := ansi.Strip(Tool(tool("get_threat_model",
		map[string]any{"target": "https://app.example.com"},
		map[string]any{
			"success": true,
			"found":   true,
			"content": "# Overview\nMulti-tenant billing app.\n\n" +
				"## Trust Boundaries and Assumptions\n\n## Attack Surface\n",
			"amendments": []any{
				map[string]any{
					"agent_name": "ReconAgent",
					"content":    "staging host shares the production database",
				},
			},
		},
		"completed")))
	requireContains(t, out,
		"Threat Model", "https://app.example.com",
		"1 amendment(s)", "ReconAgent", "staging host shares the production database",
		"Multi-tenant billing app.", "Overview", "Trust Boundaries and Assumptions",
	)
}

func TestGetThreatModelMissingModelIsExplicit(t *testing.T) {
	out := ansi.Strip(Tool(tool("get_threat_model",
		map[string]any{"target": "10.0.0.5"},
		map[string]any{"success": true, "found": false}, "completed")))
	requireContains(t, out, "No model derived for this target yet")
}

func TestSaveThreatModelWarnsWhenAmendmentsAreCleared(t *testing.T) {
	out := ansi.Strip(Tool(tool("save_threat_model",
		map[string]any{"target": "app.example.com", "content": "# Overview\nA thing.\n"},
		map[string]any{
			"success":            true,
			"amendments_cleared": 2,
		},
		"completed")))
	requireContains(t, out, "Threat Model Saved", "saved", "cleared 2 amendment(s)")
}

func TestAmendThreatModelRendersAddendum(t *testing.T) {
	out := ansi.Strip(Tool(tool("amend_threat_model",
		map[string]any{
			"target":   "app.example.com",
			"addendum": "The admin role is assignable by any org member via PATCH /members.",
		},
		map[string]any{"success": true, "amendment_count": 3}, "completed")))
	requireContains(t, out, "Threat Model Amended", "amendment recorded", "(3 total)",
		"admin role is assignable")
}

func TestCoverageAndThreatModelToolsAreNotGeneric(t *testing.T) {
	// The generic fallback dumps raw arg keys; these tools must not reach it.
	for _, name := range []string{
		"record_coverage", "update_coverage", "list_coverage",
		"get_threat_model", "save_threat_model", "amend_threat_model",
	} {
		out := ansi.Strip(Tool(tool(name, map[string]any{"target": "x", "surface": "y"}, nil, "running")))
		if strings.Contains(out, "Using tool") {
			t.Fatalf("%s fell through to the generic renderer:\n%s", name, out)
		}
	}
}

func TestOutputHeavyCoverageToolsCollapse(t *testing.T) {
	for _, name := range []string{"list_coverage", "get_threat_model"} {
		if ToolPreviewLines(name) == 0 {
			t.Fatalf("%s should collapse; its output is unbounded", name)
		}
	}
	for _, name := range []string{"record_coverage", "amend_threat_model"} {
		if ToolPreviewLines(name) != 0 {
			t.Fatalf("%s should not collapse", name)
		}
	}
}

func TestVulnerabilityReportRendersCalibrationFields(t *testing.T) {
	out := ansi.Strip(Tool(tool("create_vulnerability_report",
		map[string]any{
			"title":                      "IDOR in invoice export",
			"confidence":                 "medium",
			"confidence_rationale":       "traced statically; no authenticated instance to replay against",
			"counterevidence":            "the gateway may strip the id parameter before it reaches the handler",
			"severity_change_conditions": "critical if the export includes other tenants' bank details",
			"fix_verification":           "unit tests executed; bypass review reasoned only",
			"description":                "The handler trusts a client-supplied invoice id.",
		},
		map[string]any{"success": true, "severity": "high", "cvss_score": 7.5},
		"completed")))
	requireContains(t, out,
		"Confidence", "MEDIUM", "no authenticated instance to replay against",
		"Counterevidence", "gateway may strip the id parameter",
		"Severity Would Change If", "other tenants' bank details",
		"Fix Verification", "bypass review reasoned only",
	)
}
