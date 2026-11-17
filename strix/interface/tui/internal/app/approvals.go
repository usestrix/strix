package app

import (
	"fmt"
	"math"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
	"github.com/usestrix/strix/tui/internal/render"
)

type approvalTickMsg time.Time

func approvalTick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return approvalTickMsg(t) })
}

func (m *Model) syncApprovalPrompt() tea.Cmd {
	if len(m.snapshot.PendingApprovals) == 0 {
		m.approvalID = ""
		m.approvalSending = false
		if m.modal == modalApproval {
			m.closeModal()
		}
		return nil
	}
	if m.modal != modalNone && m.modal != modalApproval {
		return nil
	}
	id := m.snapshot.PendingApprovals[0].ID
	if m.approvalID != id || m.modal != modalApproval {
		startTick := m.modal != modalApproval
		m.approvalID, m.approvalSending = id, false
		m.approvalNow = time.Now()
		m.showSplash = false
		m.openModal(modalApproval)
		m.modalChoice = 1
		if startTick {
			return approvalTick()
		}
	}
	return nil
}

func (m Model) approvalView() string {
	if len(m.snapshot.PendingApprovals) == 0 {
		return ""
	}
	a := m.snapshot.PendingApprovals[0]
	_, _, chatWidth, _ := m.layout()
	width := min(76, max(20, chatWidth-4))
	title := "△ Run this command?"
	switch a.Tool {
	case "repeat_request":
		title = "△ Send this request?"
	case "call_mcp":
		title = "△ Run this tool?"
	}
	if count := max(len(m.snapshot.PendingApprovals), m.snapshot.PendingApprovalCount); count > 1 {
		title += fmt.Sprintf("  1 of %d", count)
	}
	seconds := 0
	if expires, err := time.Parse(time.RFC3339Nano, a.ExpiresAt); err == nil {
		seconds = max(0, int(math.Ceil(expires.Sub(m.approvalNow).Seconds())))
	}
	category := strings.ReplaceAll(a.Category, "_", " ")
	timeoutAction := "blocks"
	if m.snapshot.ApprovalOnTimeout == "allow" {
		timeoutAction = "runs"
	}
	if len(category) > 0 {
		category = strings.ToUpper(category[:1]) + category[1:]
	}
	lines, whole := m.approvalLines(a, width)
	if !whole {
		lines = append(lines, "[too long to show in full here: it can only be blocked]")
	}
	body := truncate(ansi.Strip(a.AgentName), width-4) + "\n" + strings.Join(lines, "\n") + "\n" +
		fmt.Sprintf("%s · %s in %d:%02d", category, timeoutAction, seconds/60, seconds%60) + "\n" +
		"←/→ choose · enter confirm · esc block"
	return m.cornerPrompt(render.Bold(amber).Render(title), body, width, "Allow", "Block")
}

// approvalLines wraps the action to the prompt and reports whether all of it fits on screen.
func (m Model) approvalLines(a protocol.Approval, width int) ([]string, bool) {
	lines := strings.Split(ansi.Hardwrap(ansi.Strip(a.Summary), max(1, width-4), false), "\n")
	room := max(3, m.height-12)
	if len(lines) <= room {
		return lines, !a.Truncated
	}
	return lines[:room-1], false
}

func (m *Model) answerApproval(approved bool) tea.Cmd {
	if m.approvalSending || m.approvalID == "" {
		return nil
	}
	// A person only allows an action they were shown in full.
	if approved && len(m.snapshot.PendingApprovals) > 0 {
		_, _, chatWidth, _ := m.layout()
		if _, whole := m.approvalLines(m.snapshot.PendingApprovals[0], min(76, max(20, chatWidth-4))); !whole {
			return nil
		}
	}
	m.approvalSending = true
	return send(m.client, "approval.decide", map[string]any{
		"approval_id": m.approvalID, "approved": approved,
	})
}
