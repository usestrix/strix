package app

import (
	"encoding/json"
	"fmt"
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
		wasSetup := m.snapshot.SetupMode
		m.snapshot = update.State
		m.stateRevision = update.Revision
		if m.snapshot.Error != nil {
			m.errorText = *m.snapshot.Error
		}
		if m.snapshot.SetupMode {
			m.input.Placeholder = "Type / to configure your scan"
		} else {
			if wasSetup && m.picker != pickerNone {
				m.closePicker()
			}
			m.input.Placeholder = "Send a message"
		}
		m.selectedAgent = selectedAgentIndex(m.snapshot.Agents, selectedAgentID)
		m.selectedVuln = min(m.selectedVuln, max(0, len(m.snapshot.Vulnerabilities)-1))
		if m.modal == modalStop && !m.selectedAgentCanStop() {
			m.closeModal()
		}
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
			if result.Command == "models.list" {
				m.modelListing = nil
			}
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
		if m.snapshot.ScanStarted && !m.snapshot.SetupMode && (strings.HasPrefix(result.Command, "setup.") || result.Command == "providers.list" || result.Command == "models.list") {
			return nil
		}
		m.errorText = ""
		switch result.Command {
		case "providers.list":
			var data protocol.ProvidersResult
			_ = json.Unmarshal(result.Result, &data)
			m.options = m.options[:0]
			m.providerConfigured = map[string]bool{}
			m.providerLabels = map[string]string{}
			m.providerStates = map[string]string{}
			m.providerDetails = map[string]string{}
			m.providerDisconnectable = map[string]bool{}
			for _, p := range data.Providers {
				m.options = append(m.options, p.Name)
				m.providerConfigured[p.Name] = p.Configured
				m.providerLabels[p.Name] = p.Label
				m.providerStates[p.Name] = p.State
				m.providerDetails[p.Name] = p.Detail
				m.providerDisconnectable[p.Name] = p.Disconnectable
			}
			m.openPicker(pickerProvider)
		case "models.list":
			var data protocol.ModelsResult
			if err := json.Unmarshal(result.Result, &data); err != nil {
				m.setupMsg(err.Error(), render.Col(red))
				m.modelListing = nil
				return nil
			}
			return m.handleModelListingPage(data)
		case "setup.select_provider":
			var data protocol.Provider
			_ = json.Unmarshal(result.Result, &data)
			m.applyProviderRecord(data)
			if data.Configured {
				m.setupMsg("✓ "+m.providerStatusText(m.configProvider, m.configProviderLabel, m.configProviderDetail)+" Use /model to pick a model.", render.Col(green))
			} else if data.KeyEnv != nil {
				m.keyEnv = *data.KeyEnv
				m.openPicker(pickerAPIKey)
			} else {
				m.setupMsg(m.providerStatusText(m.configProvider, m.configProviderLabel, m.configProviderDetail), render.Col(red))
			}
		case "setup.save_api_key":
			var data protocol.Provider
			_ = json.Unmarshal(result.Result, &data)
			m.applyProviderRecord(data)
			if m.picker == pickerAPIKey {
				m.closePicker()
			}
			if data.Configured {
				m.setupMsg("✓ Saved credentials. "+m.providerStatusText(m.configProvider, m.configProviderLabel, m.configProviderDetail)+" Use /model to pick a model.", render.Col(green))
			} else {
				m.setupMsg("Saved the API key, but more configuration is required. "+m.providerStatusText(m.configProvider, m.configProviderLabel, m.configProviderDetail), render.Col(amber))
			}
		case "setup.disconnect_provider":
			var data protocol.Provider
			_ = json.Unmarshal(result.Result, &data)
			m.providerConfigured[data.Name] = data.Configured
			m.providerStates[data.Name] = data.State
			m.providerDetails[data.Name] = data.Detail
			m.providerDisconnectable[data.Name] = data.Disconnectable
			m.setupMsg("Disconnected "+data.Label+".", render.Col(amber))
		case "setup.add_custom_provider":
			var data protocol.Provider
			_ = json.Unmarshal(result.Result, &data)
			if m.picker == pickerCustomAPIKey {
				m.closePicker()
			}
			m.customKind, m.customName, m.customURL = "", "", ""
			m.applyProviderRecord(data)
			m.setupMsg("✓ Added custom provider. "+m.providerStatusText(data.Name, data.Label, data.Detail)+" Use /model to pick a model.", render.Col(green))
		case "setup.select_model":
			var data struct {
				Model string `json:"model"`
			}
			_ = json.Unmarshal(result.Result, &data)
			if m.picker == pickerModel || m.picker == pickerManualModel {
				m.closePicker()
			}
			if data.Model != "" {
				m.setupMsg("✓ Model set to "+data.Model+" (saved to your config).", render.Col(green))
			}
		case "setup.set_mode":
			var data struct {
				Mode string `json:"mode"`
			}
			_ = json.Unmarshal(result.Result, &data)
			if data.Mode != "" {
				m.closePicker()
				m.snapshot.ScanMode = data.Mode
				m.setupMsg("✓ Scan mode set to "+data.Mode+".", render.Col(green))
			}
		case "setup.add_mount":
			var data struct {
				Mount string `json:"mount"`
			}
			_ = json.Unmarshal(result.Result, &data)
			if data.Mount != "" {
				m.setupMsg("✓ Added read-only mount: "+data.Mount, render.Col(green))
			}
		case "setup.load_target_list":
			var data struct {
				Path  string `json:"path"`
				Added int    `json:"added"`
				Total int    `json:"total"`
			}
			_ = json.Unmarshal(result.Result, &data)
			m.setupMsg(fmt.Sprintf("✓ Added %d target(s) from %s (%d total).", data.Added, data.Path, data.Total), render.Col(green))
		case "setup.load_instruction_file":
			var data struct {
				Path       string `json:"path"`
				Characters int    `json:"characters"`
			}
			_ = json.Unmarshal(result.Result, &data)
			m.setupMsg(fmt.Sprintf("✓ Loaded %d instruction characters from %s.", data.Characters, data.Path), render.Col(green))
		case "setup.set_budget":
			var data struct {
				Budget *float64 `json:"budget"`
			}
			_ = json.Unmarshal(result.Result, &data)
			m.snapshot.MaxBudgetUSD = data.Budget
			if data.Budget == nil {
				m.setupMsg("Budget limit disabled.", render.Dim())
			} else {
				m.setupMsg(fmt.Sprintf("✓ Budget set to $%.2f.", *data.Budget), render.Col(green))
			}
		case "setup.set_max_turns":
			var data struct {
				Turns int `json:"turns"`
			}
			_ = json.Unmarshal(result.Result, &data)
			m.snapshot.MaxTurns = data.Turns
			m.setupMsg(fmt.Sprintf("✓ Maximum turns set to %d per agent.", data.Turns), render.Col(green))
		case "setup.set_scope":
			var data struct {
				Mode string  `json:"mode"`
				Base *string `json:"base"`
			}
			_ = json.Unmarshal(result.Result, &data)
			m.snapshot.ScopeMode = data.Mode
			m.snapshot.DiffBase = ""
			if data.Base != nil {
				m.snapshot.DiffBase = *data.Base
			}
			message := "✓ Scope mode set to " + data.Mode
			if m.snapshot.DiffBase != "" {
				message += " against " + m.snapshot.DiffBase
			}
			m.setupMsg(message+".", render.Col(green))
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

func (m *Model) handleModelListingPage(data protocol.ModelsResult) tea.Cmd {
	if data.ListingID == "" || data.Cursor < 0 || data.NextCursor != data.Cursor+1 {
		m.modelListing = nil
		m.setupMsg("Invalid paged model listing received from backend.", render.Col(red))
		return nil
	}
	if data.Cursor == 0 {
		m.modelListing = &modelListingAssembly{
			listingID: data.ListingID, groupIndexes: map[string]int{}, providerNames: map[string]bool{},
		}
	}
	listing := m.modelListing
	if listing == nil || listing.listingID != data.ListingID || listing.cursor != data.Cursor {
		m.modelListing = nil
		m.setupMsg("Model listing page mismatch; run /model again.", render.Col(red))
		return nil
	}
	for _, group := range data.Groups {
		if index, exists := listing.groupIndexes[group.Provider]; exists {
			listing.groups[index].Models = append(listing.groups[index].Models, group.Models...)
			listing.groups[index].AllowManual = listing.groups[index].AllowManual || group.AllowManual
			if listing.groups[index].Error == "" {
				listing.groups[index].Error = group.Error
			}
			continue
		}
		listing.groupIndexes[group.Provider] = len(listing.groups)
		listing.groups = append(listing.groups, group)
	}
	for _, provider := range data.Providers {
		if listing.providerNames[provider.Name] {
			continue
		}
		listing.providerNames[provider.Name] = true
		listing.providers = append(listing.providers, provider)
	}
	listing.cursor = data.NextCursor
	if !data.Done {
		return send(m.client, "models.list", map[string]any{
			"listing_id": listing.listingID,
			"cursor":     listing.cursor,
		})
	}
	groups, providers := listing.groups, listing.providers
	m.modelListing = nil
	m.installModelListing(groups, providers)
	return nil
}

func (m *Model) installModelListing(groups []protocol.ModelGroup, providers []protocol.Provider) {
	m.options = m.options[:0]
	m.modelOptions = map[string]modelPickerOption{}
	if len(groups) == 0 && len(providers) > 0 {
		m.providerConfigured = map[string]bool{}
		m.providerLabels = map[string]string{}
		m.providerStates = map[string]string{}
		m.providerDetails = map[string]string{}
		m.providerDisconnectable = map[string]bool{}
		for _, provider := range providers {
			m.options = append(m.options, provider.Name)
			m.providerConfigured[provider.Name] = provider.Configured
			m.providerLabels[provider.Name] = provider.Label
			m.providerStates[provider.Name] = provider.State
			m.providerDetails[provider.Name] = provider.Detail
			m.providerDisconnectable[provider.Name] = provider.Disconnectable
		}
		m.openPicker(pickerProvider)
		return
	}
	for groupIndex, group := range groups {
		label := group.Label
		if label == "" {
			label = group.Provider
		}
		if strings.TrimSpace(group.Error) != "" {
			m.setupMsg(label+": "+strings.TrimSpace(group.Error), render.Col(amber))
		}
		for modelIndex, model := range group.Models {
			token := fmt.Sprintf("model:%d:%d", groupIndex, modelIndex)
			m.options = append(m.options, token)
			m.modelOptions[token] = modelPickerOption{provider: group.Provider, label: label, model: model}
		}
		if group.AllowManual {
			token := fmt.Sprintf("manual:%d", groupIndex)
			m.options = append(m.options, token)
			m.modelOptions[token] = modelPickerOption{provider: group.Provider, label: label, manual: true}
		}
	}
	if len(m.options) == 0 {
		m.setupMsg("No configured providers or models are available. Run /provider to connect one.", render.Dim())
		return
	}
	m.openPicker(pickerModel)
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
