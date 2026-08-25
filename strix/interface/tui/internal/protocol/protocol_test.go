package protocol

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestProtocolVersionAndCapabilities(t *testing.T) {
	if Version != 5 {
		t.Fatalf("protocol version = %d, want 5", Version)
	}
	wantCapabilities := []string{
		"state-revisions",
		"collection-deltas",
		"structured-command-errors",
		"agents-collection",
		"safety-approvals",
	}
	if !reflect.DeepEqual(Capabilities, wantCapabilities) {
		t.Fatalf("capabilities = %#v, want %#v", Capabilities, wantCapabilities)
	}

}

func TestSnapshotDecodesPendingSafetyApprovals(t *testing.T) {
	var snapshot Snapshot
	if err := json.Unmarshal([]byte(`{
		"pending_approvals": [{
			"request_id": "approval-1",
			"agent_id": "agent-1",
			"action": "Run exploit",
			"reason": "Changes target state",
			"tool_name": "exec_command",
			"digest": "abc123",
			"risk": "medium"
		}]
	}`), &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.PendingApprovals) != 1 {
		t.Fatalf("pending approvals = %d, want 1", len(snapshot.PendingApprovals))
	}
	if got := snapshot.PendingApprovals[0]; got != (SafetyApproval{
		RequestID: "approval-1",
		AgentID:   "agent-1",
		Action:    "Run exploit",
		Reason:    "Changes target state",
		ToolName:  "exec_command",
		Digest:    "abc123",
		Risk:      "medium",
	}) {
		t.Fatalf("pending approval = %#v", got)
	}
}
