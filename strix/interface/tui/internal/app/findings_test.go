package app

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
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

func reportModel(t *testing.T, count int) Model {
	t.Helper()
	titles := make([]string, 0, count)
	for i := range count {
		titles = append(titles, fmt.Sprintf("Finding number %d", i+1))
	}
	m := findingsModel(t, titles...)
	m.openModal(modalVulnerability)
	return m
}

// The open report can be stepped through the list without closing it.
func TestReportStepsBetweenFindings(t *testing.T) {
	m := reportModel(t, 3)

	updated, _ := m.updateModal(tea.KeyMsg{Type: tea.KeyRight})
	m = updated.(Model)
	if m.selectedVuln != 1 {
		t.Fatalf("right moved to %d, want 1", m.selectedVuln)
	}
	if m.modal != modalVulnerability {
		t.Fatal("stepping closed the report")
	}
	updated, _ = m.updateModal(tea.KeyMsg{Type: tea.KeyLeft})
	m = updated.(Model)
	if m.selectedVuln != 0 {
		t.Fatalf("left moved to %d, want 0", m.selectedVuln)
	}
}

// The ends do not wrap: rolling from the last report to the first would hide
// that you had reached the end.
func TestReportStepsStopAtTheEnds(t *testing.T) {
	m := reportModel(t, 3)

	updated, _ := m.updateModal(tea.KeyMsg{Type: tea.KeyLeft})
	m = updated.(Model)
	if m.selectedVuln != 0 {
		t.Fatalf("left from the first report moved to %d, want 0", m.selectedVuln)
	}

	m.selectedVuln = 2
	updated, _ = m.updateModal(tea.KeyMsg{Type: tea.KeyRight})
	m = updated.(Model)
	if m.selectedVuln != 2 {
		t.Fatalf("right from the last report moved to %d, want 2", m.selectedVuln)
	}
}

// Each direction is offered only when there is a report that way, and a lone
// finding is offered neither.
func TestReportNavigationHintsFollowAvailability(t *testing.T) {
	m := reportModel(t, 3)
	for _, testCase := range []struct {
		index              int
		wantPrev, wantNext bool
		position           string
	}{
		{index: 0, wantNext: true, position: "1/3"},
		{index: 1, wantPrev: true, wantNext: true, position: "2/3"},
		{index: 2, wantPrev: true, position: "3/3"},
	} {
		m.selectedVuln = testCase.index
		view := ansi.Strip(m.modalView())
		if !strings.Contains(view, testCase.position) {
			t.Fatalf("report %d does not show %q", testCase.index, testCase.position)
		}
		if got := strings.Contains(view, "← prev"); got != testCase.wantPrev {
			t.Fatalf("report %d prev hint = %v, want %v", testCase.index, got, testCase.wantPrev)
		}
		if got := strings.Contains(view, "→ next"); got != testCase.wantNext {
			t.Fatalf("report %d next hint = %v, want %v", testCase.index, got, testCase.wantNext)
		}
	}

	lone := reportModel(t, 1)
	view := ansi.Strip(lone.modalView())
	if strings.Contains(view, "prev") || strings.Contains(view, "next") || strings.Contains(view, "1/1") {
		t.Fatalf("a lone finding offered navigation:\n%s", view)
	}
}

// A new report opens at its top, and the copy state does not carry over.
func TestSteppingResetsTheReportView(t *testing.T) {
	m := reportModel(t, 3)
	m.vulnerabilityCopied = true
	m.vulnViewport.SetYOffset(3)

	m.showVulnerability(1)

	if m.vulnViewport.YOffset != 0 {
		t.Fatalf("the next report opened scrolled to %d", m.vulnViewport.YOffset)
	}
	if m.vulnerabilityCopied {
		t.Fatal("the copy state carried over to another report")
	}
}
