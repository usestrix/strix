package protocol

import "encoding/json"

const Version = 5

var Capabilities = []string{
	"state-revisions",
	"collection-deltas",
	"structured-command-errors",
	"agents-collection",
	"safety-approvals",
}

type Envelope struct {
	Version   int             `json:"version"`
	Type      string          `json:"type"`
	RequestID string          `json:"request_id,omitempty"`
	Payload   json.RawMessage `json:"payload"`
}

type Message struct {
	ID    string `json:"id"`
	Text  string `json:"text"`
	Level string `json:"level"`
}

type Agent struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	ParentID     *string `json:"parent_id"`
	Status       string  `json:"status"`
	ErrorMessage string  `json:"error_message"`
}

type Event struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	AgentID   string         `json:"agent_id"`
	Timestamp string         `json:"timestamp"`
	Version   int            `json:"version"`
	Data      map[string]any `json:"data"`
}

type Hello struct {
	Capabilities []string `json:"capabilities"`
}

type SafetyApproval struct {
	RequestID string `json:"request_id"`
	Action    string `json:"action"`
	Reason    string `json:"reason"`
	AgentID   string `json:"agent_id"`
	ToolName  string `json:"tool_name"`
	Digest    string `json:"digest"`
	Risk      string `json:"risk"`
}

type Snapshot struct {
	SetupMode           bool             `json:"setup_mode"`
	ScanStarted         bool             `json:"scan_started"`
	ScanState           string           `json:"scan_state"`
	Targets             []string         `json:"targets"`
	TargetCount         int              `json:"target_count"`
	WorkingDir          string           `json:"working_dir"`
	PendingMount        string           `json:"pending_mount"`
	PendingApprovals    []SafetyApproval `json:"pending_approvals"`
	SafetyDisabled      bool             `json:"safety_disabled"`
	Instruction         string           `json:"instruction"`
	ScanMode            string           `json:"scan_mode"`
	MaxBudgetUSD        *float64         `json:"max_budget_usd"`
	MaxTurns            int              `json:"max_turns"`
	ScopeMode           string           `json:"scope_mode"`
	DiffBase            string           `json:"diff_base"`
	Model               string           `json:"model"`
	ModelWarning        string           `json:"model_warning"`
	CaidoURL            string           `json:"caido_url"`
	Messages            []Message        `json:"messages"`
	Agents              []Agent          `json:"-"`
	Events              []Event          `json:"-"`
	Vulnerabilities     []map[string]any `json:"-"`
	Usage               map[string]any   `json:"usage"`
	Subscription        bool             `json:"subscription"`
	ViewerStatus        string           `json:"viewer_status"`
	ViewerURL           *string          `json:"viewer_url"`
	Error               *string          `json:"error"`
	ProjectionTruncated bool             `json:"projection_truncated"`
}

type StateUpdate struct {
	Revision int      `json:"revision"`
	State    Snapshot `json:"state"`
}

type CollectionBootstrap struct {
	Collection string            `json:"collection"`
	Revision   int               `json:"revision"`
	Cursor     int               `json:"cursor"`
	NextCursor int               `json:"next_cursor"`
	Done       bool              `json:"done"`
	Items      []json.RawMessage `json:"items"`
}

type CollectionOperation struct {
	Op   string          `json:"op"`
	ID   string          `json:"id,omitempty"`
	Item json.RawMessage `json:"item"`
}

type CollectionDelta struct {
	Collection   string                `json:"collection"`
	BaseRevision int                   `json:"base_revision"`
	Revision     int                   `json:"revision"`
	Cursor       int                   `json:"cursor"`
	NextCursor   int                   `json:"next_cursor"`
	Done         bool                  `json:"done"`
	Operations   []CollectionOperation `json:"operations"`
}

type CommandError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type CommandResult struct {
	OK      bool            `json:"ok"`
	Command string          `json:"command"`
	Result  json.RawMessage `json:"result"`
	Error   *CommandError   `json:"error"`
}
