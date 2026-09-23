package app

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/usestrix/strix/tui/internal/protocol"
	"github.com/usestrix/strix/tui/internal/render"
)

var triageReasons = []struct{ code, label string }{
	{"unspecified", "Select a reason (optional)"},
	{"incorrect_assumption", "Incorrect assumption"},
	{"existing_protection", "Existing protection prevents the exploit"},
	{"not_affected", "Code or dependency is not affected"},
	{"expected_behavior", "Expected behavior, not a vulnerability"},
	{"other", "Other"},
}

var triageFields = []string{"status", "triage_status", "resolution_reason", "reason_code",
	"status_note", "status_changed_at", "status_changed_by", "triage_revision", "finding_digest", "review_stale", "can_triage"}

type triageForm struct {
	findingID string
	revision  int64
	digest    string
	reason    int
	focus     int // reason, note, cancel, submit
	note      textarea.Model
}

type triageRequest struct {
	findingID string
	previous  map[string]any
	undo      bool
}

type triageUndoState struct {
	findingID string
	previous  map[string]any
	revision  int64
	digest    string
	expires   time.Time
}

func boolField(finding map[string]any, key string) bool {
	value, _ := finding[key].(bool)
	return value
}

func findingStatus(finding map[string]any) string {
	if render.StringValue(finding["status"]) == "closed" {
		return "closed"
	}
	return "open"
}

func findingStatusLabel(finding map[string]any) string {
	if boolField(finding, "review_stale") {
		return "Needs review · evidence changed since review"
	}
	if findingStatus(finding) == "closed" {
		return "Closed · False positive"
	}
	return "Open"
}

func triageReasonLabel(code string) string {
	if code == "" || code == "unspecified" {
		return ""
	}
	for _, reason := range triageReasons {
		if reason.code == code {
			return reason.label
		}
	}
	return ""
}

func (m Model) selectedFinding() map[string]any {
	if m.selectedVuln < 0 || m.selectedVuln >= len(m.snapshot.Vulnerabilities) {
		return nil
	}
	return m.snapshot.Vulnerabilities[m.selectedVuln]
}

func (m Model) selectedFindingID() string { return collectionItemID(m.selectedFinding()) }

func (m Model) findingFilterLabel() string { return []string{"Open", "Closed", "All"}[m.findingFilter] }

func (m Model) findingVisible(index int) bool {
	if index < 0 || index >= len(m.snapshot.Vulnerabilities) {
		return false
	}
	return m.findingFilter == 2 || (findingStatus(m.snapshot.Vulnerabilities[index]) == "closed") == (m.findingFilter == 1)
}

func (m Model) visibleFindingIndices() []int {
	indices := make([]int, 0, len(m.snapshot.Vulnerabilities))
	for i := range m.snapshot.Vulnerabilities {
		if m.findingVisible(i) {
			indices = append(indices, i)
		}
	}
	return indices
}

func (m *Model) selectVisibleFinding() {
	if m.findingVisible(m.selectedVuln) {
		return
	}
	indices := m.visibleFindingIndices()
	if len(indices) > 0 {
		m.selectedVuln = indices[0]
	}
}

func (m *Model) restoreFindingSelection(id string) {
	for i, finding := range m.snapshot.Vulnerabilities {
		if collectionItemID(finding) == id {
			m.selectedVuln = i
			return
		}
	}
	// Never show a different issue under an already-open review form.
	if m.modal == modalTriage {
		m.triageError = "This finding is no longer available."
	}
	m.selectedVuln = min(m.selectedVuln, max(0, len(m.snapshot.Vulnerabilities)-1))
	if m.modal != modalTriage {
		m.selectVisibleFinding()
	}
}

func (m *Model) stepVulnerability(direction int) {
	indices := m.visibleFindingIndices()
	if direction < 0 {
		for i := len(indices) - 1; i >= 0; i-- {
			if indices[i] < m.selectedVuln {
				m.showVulnerability(indices[i])
				return
			}
		}
	} else {
		for _, index := range indices {
			if index > m.selectedVuln {
				m.showVulnerability(index)
				return
			}
		}
	}
}

func (m *Model) openTriageForm() tea.Cmd {
	finding := m.selectedFinding()
	if m.triagePending != nil || !boolField(finding, "can_triage") || findingStatus(finding) == "closed" {
		return nil
	}
	input := textarea.New()
	input.ShowLineNumbers = false
	input.CharLimit = 2000
	input.Prompt = ""
	input.Placeholder = "Optional context for your future review"
	input.SetHeight(4)
	reason := 0
	if m.triage.findingID == collectionItemID(finding) {
		input.SetValue(m.triage.note.Value())
		reason = m.triage.reason
	}
	m.triage = triageForm{findingID: collectionItemID(finding), revision: numberValue(finding["triage_revision"]),
		digest: render.StringValue(finding["finding_digest"]), note: input, reason: reason}
	m.triageError = ""
	m.triageErrorID = collectionItemID(finding)
	m.modal = modalTriage
	m.input.Blur()
	m.resizeTriageForm()
	return nil
}

func (m *Model) resizeTriageForm() {
	if m.modal != modalTriage {
		return
	}
	m.triage.note.SetWidth(max(12, min(66, m.width-12)))
	m.triage.note.SetHeight(max(2, min(4, m.height-18)))
}

func (m Model) updateTriageForm(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.triagePending != nil {
		return m, nil
	}
	switch key.String() {
	case "esc":
		m.modal = modalVulnerability
		m.triage.note.Blur()
		m.triageError = ""
		m.resizeVulnerabilityViewport()
		return m, nil
	case "tab", "shift+tab":
		delta := 1
		if key.String() == "shift+tab" {
			delta = -1
		}
		m.triage.focus = clampCycle(m.triage.focus+delta, 4)
		if m.triage.focus == 1 {
			return m, m.triage.note.Focus()
		}
		m.triage.note.Blur()
		return m, nil
	case "left", "up", "right", "down":
		if m.triage.focus == 0 {
			delta := 1
			if key.String() == "left" || key.String() == "up" {
				delta = -1
			}
			m.triage.reason = clampCycle(m.triage.reason+delta, len(triageReasons))
			return m, nil
		}
	case "enter":
		switch m.triage.focus {
		case 0:
			m.triage.focus = 1
			return m, m.triage.note.Focus()
		case 2:
			return m.updateTriageForm(tea.KeyMsg{Type: tea.KeyEsc})
		case 3:
			return m, m.submitTriage("closed", triageReasons[m.triage.reason].code, m.triage.note.Value())
		}
	}
	if m.triage.focus == 1 {
		var cmd tea.Cmd
		m.triage.note, cmd = m.triage.note.Update(key)
		return m, cmd
	}
	return m, nil
}

func (m Model) triageFormView() string {
	width := max(20, min(72, m.width-6))
	inner := width - 6
	gap, padding := "\n\n", 1
	uncertain := "Not sure? Keep open for review."
	if m.height < 26 {
		gap, padding, uncertain = "\n", 0, "Not sure? Keep open."
	}
	button := func(text string, focus int) string {
		style := lipgloss.NewStyle().Foreground(textColor)
		if m.triage.focus == focus {
			style = style.Bold(true).Background(dark).Foreground(white)
		}
		return style.Render(" " + text + " ")
	}
	content := render.Bold(white).Render("Mark as false positive") + "\n" +
		wrapBlock("Applies to this finding in this run.", inner) + gap +
		"Reason (optional)\n" + button("‹ "+triageReasons[m.triage.reason].label+" ›", 0) + gap +
		"Note (optional)\n" + m.triage.note.View() + "\n" +
		wrapBlock(uncertain, inner) + gap +
		button("Cancel", 2) + "  " + button("Close issue", 3) + "\n" +
		render.Dim().Render("Tab: next field · Esc: back")
	content = wrapBlock(content, inner)
	if m.triagePending != nil {
		content += "\nSaving…"
	} else if m.triageError != "" {
		lines := strings.Split(wrapBlock(m.triageError, inner), "\n")
		room := max(1, m.height-lipgloss.Height(content)-padding*2-3)
		if len(lines) > room {
			lines = lines[:room]
			lines[room-1] = truncate(lines[room-1], max(1, inner-1)) + "…"
		}
		content += "\n" + render.Col(red).Render(strings.Join(lines, "\n"))
	}
	return lipgloss.NewStyle().Width(width-2).Border(lipgloss.RoundedBorder()).BorderForeground(dark).Background(black).Padding(padding, 2).Render(content)
}

func (m *Model) submitTriage(status, reason, note string) tea.Cmd {
	if m.triagePending != nil || m.client == nil {
		return nil
	}
	finding := m.selectedFinding()
	if !boolField(finding, "can_triage") {
		return nil
	}
	id := collectionItemID(finding)
	revision := numberValue(finding["triage_revision"])
	digest := render.StringValue(finding["finding_digest"])
	if m.modal == modalTriage {
		id, revision, digest = m.triage.findingID, m.triage.revision, m.triage.digest
		if id != collectionItemID(finding) {
			m.triageError = "This finding changed. Review it again."
			return nil
		}
	}
	previous := make(map[string]any, len(finding))
	for key, value := range finding {
		previous[key] = value
	}
	m.triagePending = &triageRequest{findingID: id, previous: previous}
	m.triageError = ""
	m.triageErrorID = id
	return send(m.client, "vulnerability.triage", map[string]any{"finding_id": id, "status": status,
		"resolution_reason": "false_positive", "expected_revision": revision, "reviewed_digest": digest,
		"reason_code": reason, "note": note})
}

func (m Model) canUndoTriage() bool {
	return m.triageUndo != nil && time.Now().Before(m.triageUndo.expires) && m.selectedFindingID() == m.triageUndo.findingID &&
		numberValue(m.selectedFinding()["triage_revision"]) == m.triageUndo.revision &&
		render.StringValue(m.selectedFinding()["finding_digest"]) == m.triageUndo.digest
}

func (m *Model) undoTriage() tea.Cmd {
	if !m.canUndoTriage() || m.triagePending != nil {
		return nil
	}
	previous := m.triageUndo.previous
	cmd := m.submitTriage(findingStatus(previous), normalizeTriageReason(render.StringValue(previous["reason_code"])), render.StringValue(previous["status_note"]))
	if m.triagePending != nil {
		m.triagePending.undo = true
	}
	return cmd
}

func (m *Model) handleTriageResult(result protocol.CommandResult) tea.Cmd {
	pending := m.triagePending
	if pending == nil {
		return nil
	}
	m.triagePending = nil
	m.triageErrorID = pending.findingID
	if !result.OK {
		m.triageError = "Could not save this decision."
		if result.Error != nil {
			m.triageError = result.Error.Message
		}
		if result.Error != nil && result.Error.Code == "conflict" {
			m.triageError += " Press Esc and review the updated finding before retrying."
		}
		return m.collectionMismatch("vulnerabilities")
	}
	var data struct {
		Changed bool           `json:"changed"`
		Finding map[string]any `json:"finding"`
	}
	if err := json.Unmarshal(result.Result, &data); err != nil || collectionItemID(data.Finding) != pending.findingID {
		m.triageError = "Save outcome unknown. Refreshing the finding before another decision."
		return m.collectionMismatch("vulnerabilities")
	}
	for i, finding := range m.snapshot.Vulnerabilities {
		if collectionItemID(finding) == pending.findingID {
			updated := make(map[string]any, len(finding))
			for key, value := range finding {
				updated[key] = value
			}
			if numberValue(data.Finding["triage_revision"]) >= numberValue(finding["triage_revision"]) {
				for key, value := range data.Finding {
					updated[key] = value
				}
				// A command acknowledges a decision, not a new evidence snapshot.
				// Preserve evidence that arrived while the save was in flight.
				preserveCurrentEvidence(finding, updated)
			}
			m.snapshot.Vulnerabilities[i] = updated
		}
	}
	m.triageError = ""
	if m.modal == modalTriage && m.triage.findingID == pending.findingID {
		m.modal = modalVulnerability
		m.triage.note.Blur()
	}
	if m.triage.findingID == pending.findingID {
		m.triage.findingID = ""
	}
	if data.Changed && !pending.undo {
		m.triageUndo = &triageUndoState{findingID: pending.findingID, previous: pending.previous,
			revision: numberValue(data.Finding["triage_revision"]), digest: render.StringValue(data.Finding["finding_digest"]), expires: time.Now().Add(15 * time.Second)}
	} else if pending.undo {
		m.triageUndo = nil
	}
	m.resizeViewport()
	m.resizeVulnerabilityViewport()
	return nil
}

// A queued collection frame predating the save cannot roll its acknowledgement back.
func keepNewerTriage(current, incoming map[string]any) map[string]any {
	if render.StringValue(incoming["triage_error"]) != "" {
		return incoming
	}
	if numberValue(current["triage_revision"]) > numberValue(incoming["triage_revision"]) {
		evidence := map[string]any{"finding_digest": incoming["finding_digest"]}
		for _, key := range triageFields {
			incoming[key] = current[key]
		}
		preserveCurrentEvidence(evidence, incoming)
	}
	return incoming
}

func preserveCurrentEvidence(evidence, decision map[string]any) {
	digest := render.StringValue(evidence["finding_digest"])
	if digest != "" && digest != render.StringValue(decision["finding_digest"]) {
		decision["finding_digest"] = digest
		if render.StringValue(decision["triage_status"]) == "closed" {
			decision["status"], decision["review_stale"] = "open", true
		}
	}
}

func (m *Model) preserveTriageUpdates(incoming []map[string]any) {
	current := map[string]map[string]any{}
	for _, finding := range m.snapshot.Vulnerabilities {
		current[collectionItemID(finding)] = finding
	}
	for _, finding := range incoming {
		keepNewerTriage(current[collectionItemID(finding)], finding)
	}
}

func (m Model) updateTriageMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	if msg.Button != tea.MouseButtonLeft || msg.Action != tea.MouseActionPress || m.triagePending != nil {
		return m, nil
	}
	view := m.triageFormView()
	if m.centeredLabelHit(view, "Close issue", msg.X, msg.Y) {
		m.triage.focus = 3
		return m.updateTriageForm(tea.KeyMsg{Type: tea.KeyEnter})
	}
	if m.centeredLabelHit(view, "Cancel", msg.X, msg.Y) {
		return m.updateTriageForm(tea.KeyMsg{Type: tea.KeyEsc})
	}
	if m.centeredLabelHit(view, triageReasons[m.triage.reason].label, msg.X, msg.Y) {
		m.triage.focus = 0
		m.triage.reason = (m.triage.reason + 1) % len(triageReasons)
		m.triage.note.Blur()
	}
	if m.centeredLabelHit(view, "Note (optional)", msg.X, msg.Y) {
		m.triage.focus = 1
		return m, m.triage.note.Focus()
	}
	return m, nil
}

// Legacy decisions can omit the optional category.
func normalizeTriageReason(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return "unspecified"
	}
	return reason
}
