package app

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
)

func triageModel(t *testing.T) Model {
	t.Helper()
	m := reportModel(t, 2)
	m.client = newClient(&recordingConn{})
	for _, finding := range m.snapshot.Vulnerabilities {
		finding["status"] = "open"
		finding["triage_revision"] = 0
		finding["finding_digest"] = strings.Repeat("a", 64)
		finding["can_triage"] = true
	}
	return m
}

func triageKey(m Model, key tea.KeyMsg) Model {
	updated, _ := m.updateModal(key)
	return updated.(Model)
}

func TestNativeTriageFormKeepsLettersAndComposerDraft(t *testing.T) {
	m := triageModel(t)
	m.input.SetValue("unfinished scan instruction")
	m = triageKey(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
	if m.modal != modalTriage {
		t.Fatal("f did not open a native form")
	}
	view := ansi.Strip(m.triageFormView())
	for _, label := range []string{"Mark as false positive", "Reason (optional)", "Note (optional)", "Close issue", "Cancel"} {
		if !strings.Contains(view, label) {
			t.Fatalf("form lacks %q", label)
		}
	}
	if strings.Contains(strings.ToLower(view), "telemetry") {
		t.Fatal("form contains telemetry copy")
	}
	m = triageKey(m, tea.KeyMsg{Type: tea.KeyTab})
	for _, letter := range "frv" {
		m = triageKey(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{letter}})
	}
	if m.triage.note.Value() != "frv" || m.triagePending != nil {
		t.Fatal("note typing triggered a command")
	}
	m = triageKey(m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.modal != modalVulnerability || m.input.Value() != "unfinished scan instruction" {
		t.Fatal("cancel lost detail or composer draft")
	}
}

func TestNativeTriageRequestUsesOriginallyReviewedDigest(t *testing.T) {
	m := triageModel(t)
	connection := &recordingConn{}
	m.client = newClient(connection)
	m.openTriageForm()
	m.triage.reason = 1
	m.triage.note.SetValue("The claim is incorrect")
	m.selectedFinding()["finding_digest"] = strings.Repeat("b", 64)
	m.triage.focus = 3
	updated, cmd := m.updateModal(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if cmd == nil {
		t.Fatal("close did not send a command")
	}
	message := cmd().(sentMsg)
	if message.err != nil || message.command != "vulnerability.triage" {
		t.Fatalf("wrong command: %#v", message)
	}
	frame, err := readEnvelopeFrame(bytes.NewReader(connection.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(frame.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["reviewed_digest"] != strings.Repeat("a", 64) || payload["finding_id"] != "a" || payload["status"] != "closed" || payload["note"] != "The claim is incorrect" {
		t.Fatalf("review request changed: %#v", payload)
	}
	if retry := m.submitTriage("closed", "unspecified", ""); retry != nil {
		t.Fatal("sent duplicate pending review")
	}
	result := protocol.CommandResult{OK: false, Command: "vulnerability.triage", Error: &protocol.CommandError{Code: "conflict", Message: "Evidence changed"}}
	m.handleEnvelope(protocol.Envelope{Version: protocol.Version, Type: "command_result", RequestID: message.requestID, Payload: rawJSON(t, result)})
	if m.modal != modalTriage || m.triage.note.Value() != "The claim is incorrect" || !strings.Contains(m.triageError, "review") {
		t.Fatal("conflict lost the editable form")
	}
	m = triageKey(m, tea.KeyMsg{Type: tea.KeyEsc})
	m.openTriageForm()
	if m.triage.note.Value() != "The claim is incorrect" || m.triage.digest != strings.Repeat("b", 64) {
		t.Fatal("fresh review lost the failed submission draft")
	}
}

func TestSavedTriagePinsDetailOffersUndoAndFiltersClosedFinding(t *testing.T) {
	m := triageModel(t)
	m.openTriageForm()
	m.submitTriage("closed", "incorrect_assumption", "note")
	closed := map[string]any{"id": "a", "status": "closed", "triage_status": "closed", "resolution_reason": "false_positive", "reason_code": "incorrect_assumption", "status_note": "note", "triage_revision": 1, "finding_digest": strings.Repeat("a", 64), "can_triage": true}
	m.handleTriageResult(protocol.CommandResult{OK: true, Command: "vulnerability.triage", Result: rawJSON(t, map[string]any{"changed": true, "finding": closed})})
	if m.modal != modalVulnerability || m.selectedFindingID() != "a" || !m.canUndoTriage() {
		t.Fatal("saved closure lost the detail or undo")
	}
	if rows := m.vulnerabilityRows(60); len(rows) != 1 || rows[0].index != 1 {
		t.Fatalf("closed finding remained active: %#v", rows)
	}
	if !strings.Contains(ansi.Strip(m.vulnerabilityDetail()), "Reopen (r)") {
		t.Fatal("native reopen is missing")
	}
	if !strings.Contains(vulnerabilityMarkdownReport(m.selectedFinding()), "Closed · False positive") {
		t.Fatal("copy lacks triage")
	}
	if cmd := m.undoTriage(); cmd == nil || m.triagePending == nil || !m.triagePending.undo {
		t.Fatal("undo unavailable")
	}
	// A saved reopen is active again and consumes the brief undo action.
	closed["status"], closed["triage_revision"] = "open", 2
	m.handleTriageResult(protocol.CommandResult{OK: true, Command: "vulnerability.triage", Result: rawJSON(t, map[string]any{"changed": true, "finding": closed})})
	if len(m.visibleFindingIndices()) != 2 || m.triageUndo != nil {
		t.Fatal("undo did not restore active finding")
	}
}

func TestNativeClosedFilterIsReachableWithoutViewer(t *testing.T) {
	m := triageModel(t)
	m.snapshot.Vulnerabilities[0]["status"] = "closed"
	m.closeModal()
	m.focus = focusVulnerabilities
	updated, cmd := m.updateMain(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'v'}})
	m = updated.(Model)
	if cmd != nil || m.findingFilterLabel() != "Closed" || m.selectedFindingID() != "a" {
		t.Fatal("v did not select the closed view locally")
	}
	updated, _ = m.updateMain(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, cmd = m.updateModal(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m = updated.(Model)
	if cmd == nil || m.triagePending == nil {
		t.Fatal("r did not submit native reopen")
	}
}

func TestCollectionRefreshPreservesReviewSelectionAndNewerAcknowledgement(t *testing.T) {
	m := triageModel(t)
	m.selectedVuln = 1
	m.openTriageForm()
	m.snapshot.Vulnerabilities[1]["triage_revision"] = 2
	m.snapshot.Vulnerabilities[1]["status"] = "closed"
	items := []json.RawMessage{rawJSON(t, map[string]any{"id": "b", "title": "Updated", "status": "open", "triage_revision": 1}), rawJSON(t, m.snapshot.Vulnerabilities[0])}
	m.handleCollectionBootstrap(rawJSON(t, protocol.CollectionBootstrap{Collection: "vulnerabilities", Revision: 2, Cursor: 0, NextCursor: 2, Done: true, Items: items}))
	if m.selectedFindingID() != "b" || m.triage.findingID != "b" || m.selectedVuln != 0 {
		t.Fatal("reorder changed the finding being reviewed")
	}
	if findingStatus(m.selectedFinding()) != "closed" || numberValue(m.selectedFinding()["triage_revision"]) != 2 {
		t.Fatal("old queued projection overwrote saved decision")
	}
}

func TestStaleClosureRemainsActiveAndCanBeReviewedAgain(t *testing.T) {
	m := triageModel(t)
	finding := m.selectedFinding()
	finding["triage_status"], finding["status"], finding["review_stale"] = "closed", "open", true
	if !m.findingVisible(0) || !strings.Contains(findingStatusLabel(finding), "Needs review") {
		t.Fatal("stale review remained suppressed")
	}
	m.openTriageForm()
	if m.modal != modalTriage {
		t.Fatal("fresh review unavailable")
	}
}

func TestNativeTriageFitsSmallTerminal(t *testing.T) {
	for _, size := range [][2]int{{130, 30}, {80, 24}, {60, 22}, {40, 18}} {
		m := triageModel(t)
		m.width, m.height = size[0], size[1]
		m.openTriageForm()
		m.triage.reason = 2
		m.triageError = "Finding evidence changed. Reload and review it again. Press Esc and review the updated finding before retrying."
		view := m.triageFormView()
		if lipgloss.Width(view) > m.width || lipgloss.Height(view) > m.height {
			t.Errorf("%dx%d form is %dx%d:\n%s", m.width, m.height, lipgloss.Width(view), lipgloss.Height(view), ansi.Strip(view))
		}
	}
}

func TestF2OpensClosedOnlyFindingsOnNarrowTerminal(t *testing.T) {
	m := triageModel(t)
	m.width, m.height = 80, 24
	for _, finding := range m.snapshot.Vulnerabilities {
		finding["status"] = "closed"
	}
	m.closeModal()
	updated, cmd := m.updateMain(tea.KeyMsg{Type: tea.KeyF2})
	m = updated.(Model)
	if cmd != nil || m.modal != modalVulnerability || m.findingFilterLabel() != "All" {
		t.Fatal("F2 did not reach closed findings without a sidebar")
	}
	if !strings.Contains(ansi.Strip(m.statusView(80)), "F2 findings") {
		t.Fatal("entry point is not discoverable")
	}
}

func TestSaveAcknowledgementCannotDismissEvidenceArrivingInFlight(t *testing.T) {
	m := triageModel(t)
	m.openTriageForm()
	m.submitTriage("closed", "unspecified", "")
	finding := m.selectedFinding()
	finding["finding_digest"] = strings.Repeat("b", 64)
	finding["evidence"] = "Changed after submission"
	finding["triage_revision"] = 1
	finding["review_stale"] = true
	m.handleTriageResult(protocol.CommandResult{OK: true, Command: "vulnerability.triage", Result: rawJSON(t, map[string]any{"changed": true, "finding": map[string]any{
		"id": "a", "status": "closed", "triage_status": "closed", "triage_revision": 1, "finding_digest": strings.Repeat("a", 64), "review_stale": false}})})
	if findingStatus(m.selectedFinding()) != "open" || !boolField(m.selectedFinding(), "review_stale") || m.selectedFinding()["finding_digest"] != strings.Repeat("b", 64) {
		t.Fatal("save hid evidence the user never reviewed")
	}
	if m.canUndoTriage() {
		t.Fatal("undo should be unavailable after evidence changed")
	}
}
