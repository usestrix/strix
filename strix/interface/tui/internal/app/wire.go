package app

import (
	"encoding/json"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/usestrix/strix/tui/internal/protocol"
	"github.com/usestrix/strix/tui/internal/render"
)

func (m *Model) handleEnvelope(envelope protocol.Envelope) tea.Cmd {
	switch envelope.Type {
	case "state":
		var update protocol.StateUpdate
		if err := json.Unmarshal(envelope.Payload, &update); err != nil {
			m.errorText = err.Error()
			return nil
		}
		if update.Revision <= m.stateRevision {
			return nil
		}
		selectedAgentID := ""
		if m.selectedAgent >= 0 && m.selectedAgent < len(m.snapshot.Agents) {
			selectedAgentID = m.snapshot.Agents[m.selectedAgent].ID
		}
		update.State.Events = m.snapshot.Events
		update.State.Vulnerabilities = m.snapshot.Vulnerabilities
		update.State.Agents = m.snapshot.Agents
		m.consumeMessages(update.State.Messages, update.State.SetupMode)
		m.snapshot = update.State
		m.stateRevision = update.Revision
		if m.snapshot.Error != nil {
			m.errorText = *m.snapshot.Error
		}
		if m.snapshot.SetupMode {
			// The start screen is its own landing page; never sit on the
			// splash before it.
			m.showSplash = false
			m.input.Placeholder = setupPlaceholder
		} else {
			m.input.Placeholder = chatPlaceholder
		}
		m.selectedAgent = selectedAgentIndex(m.snapshot.Agents, selectedAgentID)
		m.selectedVuln = min(m.selectedVuln, max(0, len(m.snapshot.Vulnerabilities)-1))
		if m.modal == modalStop && !m.selectedAgentCanStop() {
			m.closeModal()
		}
		m.syncMountPrompt()
		m.ensureAgentVisible()
		m.ensureVulnerabilityVisible()
		m.ready = true
		// resize (not just refresh): status-row visibility changes the chat height.
		m.resizeViewport()
		m.resizeVulnerabilityViewport()
	case "collection_bootstrap":
		return m.handleCollectionBootstrap(envelope.Payload)
	case "collection_delta":
		return m.handleCollectionDelta(envelope.Payload)
	case "command_result":
		if m.client == nil {
			return nil
		}
		expectedCommand, pending := m.client.ExpectedCommand(envelope.RequestID)
		if !pending {
			return nil
		}
		var result protocol.CommandResult
		if err := json.Unmarshal(envelope.Payload, &result); err != nil {
			m.errorText = err.Error()
			return nil
		}
		if result.Command != expectedCommand || !m.client.Resolve(envelope.RequestID, result.Command) {
			return nil
		}
		if !result.OK {
			if result.Command == "collection.resync" {
				if collection := m.resyncRequests[envelope.RequestID]; collection != "" {
					m.resyncRequested[collection] = false
					delete(m.resyncRequests, envelope.RequestID)
				}
			}
			message := "Command failed"
			if result.Error != nil && strings.TrimSpace(result.Error.Message) != "" {
				message = result.Error.Message
			}
			// Setup-mode errors live in the scrollback (red), like Python; during
			// a scan they surface on the status line.
			if m.snapshot.SetupMode {
				m.setupMsg(message, render.Col(red))
			} else {
				m.errorText = message
			}
			return nil
		}
		if m.snapshot.ScanStarted && !m.snapshot.SetupMode && strings.HasPrefix(result.Command, "setup.") {
			return nil
		}
		m.errorText = ""
		switch result.Command {
		case "viewer.open":
			var data struct {
				Status string  `json:"status"`
				URL    *string `json:"url"`
			}
			_ = json.Unmarshal(result.Result, &data)
			m.snapshot.ViewerStatus = data.Status
			m.snapshot.ViewerURL = data.URL
		}
	}
	return nil
}

func (m *Model) consumeMessages(messages []protocol.Message, setupMode bool) {
	if m.seenMessages == nil {
		m.seenMessages = map[string]bool{}
	}
	for _, message := range messages {
		key := message.ID
		if key == "" {
			key = message.Level + "\x00" + message.Text
		}
		if m.seenMessages[key] {
			continue
		}
		m.seenMessages[key] = true
		if !setupMode || strings.TrimSpace(message.Text) == "" {
			continue
		}
		style := render.Dim()
		switch message.Level {
		case "error":
			style = render.Col(red)
		case "warning":
			style = render.Col(amber)
		}
		m.setupMsg(message.Text, style)
	}
}

func validCollection(name string) bool {
	return name == "agents" || name == "events" || name == "vulnerabilities"
}

func (m *Model) collectionMismatch(name string) tea.Cmd {
	delete(m.collectionAssemblies, name)
	if !validCollection(name) || m.resyncRequested[name] || m.client == nil {
		return nil
	}
	m.resyncRequested[name] = true
	return send(m.client, "collection.resync", map[string]any{"collection": name})
}

func (m *Model) clearCollectionResync(name string) {
	m.resyncRequested[name] = false
	for requestID, collection := range m.resyncRequests {
		if collection == name {
			delete(m.resyncRequests, requestID)
		}
	}
}

func (m *Model) handleCollectionBootstrap(payload json.RawMessage) tea.Cmd {
	var chunk protocol.CollectionBootstrap
	if err := json.Unmarshal(payload, &chunk); err != nil {
		m.errorText = err.Error()
		return nil
	}
	if !validCollection(chunk.Collection) {
		m.errorText = "Unknown collection: " + chunk.Collection
		return nil
	}
	if chunk.Cursor == 0 {
		m.resyncRequested[chunk.Collection] = false
	}
	if chunk.Cursor == 0 {
		if chunk.Revision <= m.collectionRevisions[chunk.Collection] {
			return nil
		}
		m.collectionAssemblies[chunk.Collection] = &collectionAssembly{
			kind: "bootstrap", revision: chunk.Revision, ids: map[string]bool{},
		}
	}
	assembly := m.collectionAssemblies[chunk.Collection]
	if assembly == nil || assembly.kind != "bootstrap" || assembly.revision != chunk.Revision || assembly.cursor != chunk.Cursor {
		return m.collectionMismatch(chunk.Collection)
	}
	if chunk.NextCursor != chunk.Cursor+len(chunk.Items) {
		return m.collectionMismatch(chunk.Collection)
	}
	for _, raw := range chunk.Items {
		if chunk.Collection == "agents" {
			var agent protocol.Agent
			if err := json.Unmarshal(raw, &agent); err != nil || agent.ID == "" {
				return m.collectionMismatch(chunk.Collection)
			}
			if assembly.ids[agent.ID] {
				return m.collectionMismatch(chunk.Collection)
			}
			assembly.ids[agent.ID] = true
			assembly.agents = append(assembly.agents, agent)
		} else if chunk.Collection == "events" {
			var event protocol.Event
			if err := json.Unmarshal(raw, &event); err != nil || event.ID == "" {
				return m.collectionMismatch(chunk.Collection)
			}
			if assembly.ids[event.ID] {
				return m.collectionMismatch(chunk.Collection)
			}
			assembly.ids[event.ID] = true
			assembly.events = append(assembly.events, event)
		} else {
			var finding map[string]any
			if err := json.Unmarshal(raw, &finding); err != nil || collectionItemID(finding) == "" {
				return m.collectionMismatch(chunk.Collection)
			}
			id := collectionItemID(finding)
			if assembly.ids[id] {
				return m.collectionMismatch(chunk.Collection)
			}
			assembly.ids[id] = true
			assembly.findings = append(assembly.findings, finding)
		}
	}
	assembly.cursor = chunk.NextCursor
	if !chunk.Done {
		return nil
	}
	if chunk.Collection == "agents" {
		selectedAgentID := m.selectedAgentID()
		m.snapshot.Agents = assembly.agents
		m.selectedAgent = selectedAgentIndex(m.snapshot.Agents, selectedAgentID)
	} else if chunk.Collection == "events" {
		m.snapshot.Events = assembly.events
	} else {
		m.snapshot.Vulnerabilities = assembly.findings
	}
	m.collectionRevisions[chunk.Collection] = chunk.Revision
	delete(m.collectionAssemblies, chunk.Collection)
	m.clearCollectionResync(chunk.Collection)
	return m.refreshAfterCollection(chunk.Collection)
}

func (m *Model) handleCollectionDelta(payload json.RawMessage) tea.Cmd {
	var chunk protocol.CollectionDelta
	if err := json.Unmarshal(payload, &chunk); err != nil {
		m.errorText = err.Error()
		return nil
	}
	if !validCollection(chunk.Collection) {
		m.errorText = "Unknown collection: " + chunk.Collection
		return nil
	}
	if chunk.Cursor == 0 {
		if chunk.BaseRevision != m.collectionRevisions[chunk.Collection] || chunk.Revision <= chunk.BaseRevision {
			return m.collectionMismatch(chunk.Collection)
		}
		m.collectionAssemblies[chunk.Collection] = &collectionAssembly{
			kind: "delta", revision: chunk.Revision, baseRevision: chunk.BaseRevision,
		}
	}
	assembly := m.collectionAssemblies[chunk.Collection]
	if assembly == nil || assembly.kind != "delta" || assembly.revision != chunk.Revision ||
		assembly.baseRevision != chunk.BaseRevision || assembly.cursor != chunk.Cursor {
		return m.collectionMismatch(chunk.Collection)
	}
	if chunk.NextCursor != chunk.Cursor+len(chunk.Operations) {
		return m.collectionMismatch(chunk.Collection)
	}
	assembly.operations = append(assembly.operations, chunk.Operations...)
	assembly.cursor = chunk.NextCursor
	if !chunk.Done {
		return nil
	}
	if !m.applyCollectionOperations(chunk.Collection, assembly.operations) {
		return m.collectionMismatch(chunk.Collection)
	}
	m.collectionRevisions[chunk.Collection] = chunk.Revision
	delete(m.collectionAssemblies, chunk.Collection)
	m.clearCollectionResync(chunk.Collection)
	return m.refreshAfterCollection(chunk.Collection)
}

func (m *Model) applyCollectionOperations(name string, operations []protocol.CollectionOperation) bool {
	seen := make(map[string]bool, len(operations))
	if name == "agents" {
		selectedAgentID := m.selectedAgentID()
		values := append([]protocol.Agent(nil), m.snapshot.Agents...)
		positions := make(map[string]int, len(values))
		for index, agent := range values {
			positions[agent.ID] = index
		}
		for _, operation := range operations {
			if operation.Op == "delete" {
				if operation.ID == "" || seen[operation.ID] {
					return false
				}
				seen[operation.ID] = true
				index, exists := positions[operation.ID]
				if !exists {
					return false
				}
				values = append(values[:index], values[index+1:]...)
				positions = make(map[string]int, len(values))
				for position, value := range values {
					positions[value.ID] = position
				}
				continue
			}
			if operation.Op != "upsert" {
				return false
			}
			var agent protocol.Agent
			if err := json.Unmarshal(operation.Item, &agent); err != nil || agent.ID == "" || seen[agent.ID] {
				return false
			}
			seen[agent.ID] = true
			if index, exists := positions[agent.ID]; exists {
				values[index] = agent
			} else {
				positions[agent.ID] = len(values)
				values = append(values, agent)
			}
		}
		m.snapshot.Agents = values
		m.selectedAgent = selectedAgentIndex(values, selectedAgentID)
		return true
	}
	if name == "events" {
		values := append([]protocol.Event(nil), m.snapshot.Events...)
		positions := make(map[string]int, len(values))
		for index, event := range values {
			positions[event.ID] = index
		}
		for _, operation := range operations {
			if operation.Op == "delete" {
				if operation.ID == "" || seen[operation.ID] {
					return false
				}
				seen[operation.ID] = true
				index, exists := positions[operation.ID]
				if !exists {
					return false
				}
				values = append(values[:index], values[index+1:]...)
				positions = make(map[string]int, len(values))
				for position, value := range values {
					positions[value.ID] = position
				}
				continue
			}
			if operation.Op != "upsert" {
				return false
			}
			var event protocol.Event
			if err := json.Unmarshal(operation.Item, &event); err != nil || event.ID == "" || event.Version < 0 || seen[event.ID] {
				return false
			}
			seen[event.ID] = true
			if index, exists := positions[event.ID]; exists {
				current := values[index]
				if event.Version <= current.Version {
					return false
				}
				values[index] = event
			} else {
				positions[event.ID] = len(values)
				values = append(values, event)
			}
		}
		m.snapshot.Events = values
		return true
	}

	values := append([]map[string]any(nil), m.snapshot.Vulnerabilities...)
	positions := make(map[string]int, len(values))
	for index, finding := range values {
		positions[collectionItemID(finding)] = index
	}
	for _, operation := range operations {
		if operation.Op == "delete" {
			if operation.ID == "" || seen[operation.ID] {
				return false
			}
			seen[operation.ID] = true
			index, exists := positions[operation.ID]
			if !exists {
				return false
			}
			values = append(values[:index], values[index+1:]...)
			positions = make(map[string]int, len(values))
			for position, value := range values {
				positions[collectionItemID(value)] = position
			}
			continue
		}
		if operation.Op != "upsert" {
			return false
		}
		var finding map[string]any
		if err := json.Unmarshal(operation.Item, &finding); err != nil {
			return false
		}
		id := collectionItemID(finding)
		if id == "" {
			return false
		}
		if seen[id] {
			return false
		}
		seen[id] = true
		if index, exists := positions[id]; exists {
			values[index] = finding
		} else {
			positions[id] = len(values)
			values = append(values, finding)
		}
	}
	m.snapshot.Vulnerabilities = values
	return true
}

func collectionItemID(item map[string]any) string {
	id, _ := item["id"].(string)
	return id
}

func (m *Model) refreshAfterCollection(name string) tea.Cmd {
	if name == "agents" {
		m.ensureAgentVisible()
		m.refreshViewport()
		return m.notifyBudgetPause()
	}
	if name == "events" {
		m.refreshViewport()
		return nil
	}
	m.selectedVuln = min(m.selectedVuln, max(0, len(m.snapshot.Vulnerabilities)-1))
	m.ensureVulnerabilityVisible()
	m.resizeVulnerabilityViewport()
	return nil
}

// notifyBudgetPause ports _notify_budget_pause: a one-shot warning toast when
// any agent hits the budget limit, re-armed once no agent is paused.
func (m *Model) notifyBudgetPause() tea.Cmd {
	paused := false
	for _, agent := range m.snapshot.Agents {
		if agent.Status == "budget_paused" {
			paused = true
			break
		}
	}
	if paused && !m.budgetPauseNotified {
		m.budgetPauseNotified = true
		return m.showToastFor(
			"Budget limit reached — agents paused. Send a message to continue "+
				"(this extends the budget), or ctrl-q to quit.",
			15*time.Second,
		)
	}
	if !paused {
		m.budgetPauseNotified = false
	}
	return nil
}
