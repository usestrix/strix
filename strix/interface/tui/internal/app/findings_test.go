package app

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
)

func findingsModel(t *testing.T, titles ...string) Model {
	t.Helper()
	m := New(nil)
	m.width, m.height = 130, 30
	m.showSplash = false
	m.handleEnvelope(stateEnvelope(t, 1, protocol.Snapshot{ScanState: "running"}))
	items := make([]json.RawMessage, 0, len(titles))
	for i, title := range titles {
		items = append(items, rawJSON(t, map[string]any{
			"id": string(rune('a' + i)), "title": title, "severity": "high",
		}))
	}
	m.handleEnvelope(protocol.Envelope{Version: protocol.Version, Type: "collection_bootstrap",
		Payload: rawJSON(t, protocol.CollectionBootstrap{
			Collection: "vulnerabilities", Revision: 1, Cursor: 0,
			NextCursor: len(items), Done: true, Items: items,
		})})
	m.resizeViewport()
	return m
}

// Similar titles are hard to tell apart, so each finding carries its position in
// the list (#1005).
func TestFindingsAreNumbered(t *testing.T) {
	m := findingsModel(t, "Reflected XSS in search", "Reflected XSS in profile", "SQL injection")

	view := ansi.Strip(m.vulnerabilitiesView(40, 10))

	for _, want := range []string{"01 ● Reflected XSS in search", "02 ● Reflected XSS in profile", "03 ● SQL injection"} {
		if !strings.Contains(view, want) {
			t.Fatalf("missing %q in:\n%s", want, view)
		}
	}
}

// The padding widens with the count so the numbers stay aligned.
func TestFindingNumberWidthFollowsTheCount(t *testing.T) {
	for _, testCase := range []struct {
		total int
		want  int
	}{{1, 2}, {9, 2}, {99, 2}, {100, 3}, {1000, 4}} {
		if got := vulnerabilitySeqWidth(testCase.total); got != testCase.want {
			t.Fatalf("%d findings padded to %d digits, want %d", testCase.total, got, testCase.want)
		}
	}
}

// The list scrolls by row, not by finding. Stepping a whole entry at a time is
// what made a list of wrapped titles feel paginated.
func TestFindingsScrollByRow(t *testing.T) {
	long := "A deliberately long finding title that wraps across several rows in the sidebar"
	m := findingsModel(t, long, long, long)

	rows := m.vulnerabilityRows(m.vulnerabilityListWidth())
	if len(rows) <= 3 {
		t.Fatalf("titles did not wrap, so this proves nothing: %d rows", len(rows))
	}
	total, offset := m.vulnerabilityScrollRows()
	if total != len(rows) || offset != 0 {
		t.Fatalf("scroll metrics are not in rows: total=%d offset=%d rows=%d", total, offset, len(rows))
	}

	// One step of the offset moves one row, and the first visible line follows it.
	first := strings.Split(ansi.Strip(m.vulnerabilitiesView(40, 4)), "\n")[0]
	m.vulnOffset = 1
	second := strings.Split(ansi.Strip(m.vulnerabilitiesView(40, 4)), "\n")[0]
	if first == second {
		t.Fatalf("advancing one row did not move the list: %q", first)
	}
	// That row still belongs to the first finding, which an item-stepping list
	// would have skipped past entirely.
	if got := m.vulnerabilityIndexAtRow(0); got != 0 {
		t.Fatalf("one row in, the top line belongs to finding %d, want 0", got)
	}
}

// Selecting a finding scrolls the least it can, and never past its own start.
func TestSelectingAFindingBringsItIntoView(t *testing.T) {
	long := "A deliberately long finding title that wraps across several rows in the sidebar"
	m := findingsModel(t, long, long, long, long)

	m.selectedVuln = 3
	m.ensureVulnerabilityVisible()

	rows := m.vulnerabilityRows(m.vulnerabilityListWidth())
	height := m.vulnerabilityPageSize()
	end := min(len(rows), m.vulnOffset+height)
	found := false
	for _, row := range rows[m.vulnOffset:end] {
		if row.index == 3 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("the selected finding is not on screen: offset=%d height=%d", m.vulnOffset, height)
	}
	if m.vulnOffset > len(rows)-height && len(rows) > height {
		t.Fatalf("scrolled past the end: offset=%d rows=%d height=%d", m.vulnOffset, len(rows), height)
	}
}
