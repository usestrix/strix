package app

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/usestrix/strix/tui/internal/protocol"
)

func dialogTestModel(t *testing.T, snapshot protocol.Snapshot) (Model, *recordingConn) {
	t.Helper()
	model, connection := newCommandTestModel(t)
	model.width, model.height = 120, 40
	model.showSplash = false
	snapshot.SetupMode = true
	snapshot.ScanState = "setup"
	model.handleEnvelope(stateEnvelope(t, 1, snapshot))
	return model, connection
}

func press(t *testing.T, model Model, keys ...tea.KeyMsg) (Model, tea.Cmd) {
	t.Helper()
	var cmd tea.Cmd
	for _, key := range keys {
		updated, next := model.Update(key)
		model, cmd = updated.(Model), next
	}
	return model, cmd
}

func lastCommand(t *testing.T, cmd tea.Cmd, connection *recordingConn) protocol.Envelope {
	t.Helper()
	envelopes := drainCommands(t, cmd, connection)
	if len(envelopes) == 0 {
		t.Fatal("no command was sent")
	}
	return envelopes[len(envelopes)-1]
}

func typed(text string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(text)} }

var pickerFixture = map[string]any{
	"current":  map[string]string{"provider": "anthropic", "model": "anthropic/claude-sonnet-5-5"},
	"recent":   []map[string]string{{"provider": "anthropic", "model": "anthropic/claude-sonnet-5-5"}},
	"favorite": []map[string]string{},
	"providers": []map[string]any{
		{"id": "anthropic", "name": "Anthropic", "prefix": "anthropic", "models": []string{"anthropic/claude-sonnet-5-5", "anthropic/claude-opus-5-5"}},
		{"id": "openrouter", "name": "OpenRouter", "prefix": "openrouter", "models": []string{"openrouter/z-ai/glm-5.3"}},
	},
}

var directoryFixture = map[string]any{
	"popular": []map[string]any{
		{"id": "anthropic", "name": "Anthropic", "connected": true, "methods": []map[string]string{{"id": "api_key", "label": "API key"}}},
		{"id": "openai", "name": "OpenAI", "methods": []map[string]string{{"id": "chatgpt", "label": "Sign in with ChatGPT"}, {"id": "api_key", "label": "API key"}}},
	},
	"providers": []map[string]any{{"id": "groq", "name": "Groq", "methods": []map[string]string{{"id": "api_key", "label": "API key"}}}},
	"local": []map[string]any{
		{"id": "ollama", "name": "Ollama", "needs_base": true, "default_base": "http://localhost:11434", "key_optional": true, "methods": []map[string]string{{"id": "api_key", "label": "API key"}}},
	},
	"search": []map[string]any{{"id": "exa_search", "name": "Exa"}},
}

func TestPaletteOpensModelPickerAndSelectsModel(t *testing.T) {
	model, connection := dialogTestModel(t, protocol.Snapshot{Model: "anthropic/claude-sonnet-5-5"})
	model, _ = press(t, model, tea.KeyMsg{Type: tea.KeyCtrlP})
	if view := ansi.Strip(model.View()); !strings.Contains(view, "Search commands") || !strings.Contains(view, "Switch model") {
		t.Fatalf("palette missing: %s", view)
	}
	model, cmd := press(t, model, tea.KeyMsg{Type: tea.KeyEnter})
	if types := commandTypes(drainCommands(t, cmd, connection)); !contains(types, "models.list") {
		t.Fatalf("switch model did not request the list: %v", types)
	}
	handleCommandResult(t, &model, "models.list", pickerFixture)
	view := ansi.Strip(model.View())
	for _, want := range []string{"Search models", "Recent", "▪ claude-sonnet-5-5 Anthropic", "OpenRouter", "z-ai/glm-5.3", "connect provider ctrl+a", "favorite ctrl+f"} {
		if !strings.Contains(view, want) {
			t.Fatalf("model picker missing %q: %s", want, view)
		}
	}
	model, _ = press(t, model, typed("glm"))
	model, cmd = press(t, model, tea.KeyMsg{Type: tea.KeyEnter})
	sent := lastCommand(t, cmd, connection)
	if sent.Type != "models.select" || !strings.Contains(string(sent.Payload), `"openrouter/z-ai/glm-5.3"`) {
		t.Fatalf("selection sent %s", sent.Payload)
	}
	if model.modal != modalNone {
		t.Fatal("picker stayed open after selecting")
	}
}

func TestModelPickerOffersTypedModelWhenNothingMatches(t *testing.T) {
	model, connection := dialogTestModel(t, protocol.Snapshot{})
	cmd := model.openModels("openrouter")
	drainCommands(t, cmd, connection)
	handleCommandResult(t, &model, "models.list", pickerFixture)
	model, _ = press(t, model, typed("acme/new-model"))
	if view := ansi.Strip(model.View()); !strings.Contains(view, "Use openrouter/acme/new-model") {
		t.Fatalf("typed model not offered: %s", view)
	}
	_, cmd = press(t, model, tea.KeyMsg{Type: tea.KeyEnter})
	sent := lastCommand(t, cmd, connection)
	if !strings.Contains(string(sent.Payload), `"openrouter/acme/new-model"`) {
		t.Fatalf("typed model sent %s", sent.Payload)
	}
}

func TestSubmitWithoutModelOpensConnectFlow(t *testing.T) {
	model, connection := dialogTestModel(t, protocol.Snapshot{})
	model.input.SetValue("scan example.com")
	model, cmd := press(t, model, tea.KeyMsg{Type: tea.KeyEnter})
	if sent := lastCommand(t, cmd, connection); sent.Type != "models.list" {
		t.Fatalf("submit without a model sent %v", sent.Type)
	}
	if model.input.Value() != "scan example.com" {
		t.Fatalf("prompt was lost: %q", model.input.Value())
	}
	cmd = handleCommandResult(t, &model, "models.list", map[string]any{"providers": []any{}})
	if types := commandTypes(drainCommands(t, cmd, connection)); !contains(types, "providers.list") {
		t.Fatalf("no connected provider did not open connect: %v", types)
	}
}

func TestConnectProviderWithAPIKeyThenShowsItsModels(t *testing.T) {
	model, connection := dialogTestModel(t, protocol.Snapshot{})
	drainCommands(t, model.openProviders(), connection)
	handleCommandResult(t, &model, "providers.list", directoryFixture)
	view := ansi.Strip(model.View())
	for _, want := range []string{"Connect a provider", "Popular", "Anthropic", "connected", "Local", "Web search"} {
		if !strings.Contains(view, want) {
			t.Fatalf("provider list missing %q: %s", want, view)
		}
	}
	model, _ = press(t, model, typed("groq"), tea.KeyMsg{Type: tea.KeyEnter})
	if model.dialog.kind != dialogKeyInput {
		t.Fatalf("groq did not open the key prompt: %v", model.dialog.kind)
	}
	model, _ = press(t, model, typed("gsk-secret"))
	if view := ansi.Strip(model.View()); strings.Contains(view, "gsk-secret") || !strings.Contains(view, "Connect Groq") {
		t.Fatalf("key prompt shows the key or lacks a title: %s", view)
	}
	model, cmd := press(t, model, tea.KeyMsg{Type: tea.KeyEnter})
	sent := lastCommand(t, cmd, connection)
	if sent.Type != "providers.connect" || !strings.Contains(string(sent.Payload), `"gsk-secret"`) {
		t.Fatalf("connect sent %s", sent.Payload)
	}
	cmd = handleCommandResult(t, &model, "providers.connect", map[string]any{"provider": "groq", "name": "Groq"})
	if model.dialog.kind != dialogModels || model.dialog.filterProvider != "groq" || model.toast != "Connected Groq" {
		t.Fatalf("after connect: kind=%v filter=%q toast=%q", model.dialog.kind, model.dialog.filterProvider, model.toast)
	}
	_ = cmd
}

func TestConnectFlowsForMethodsAndLocalProviders(t *testing.T) {
	model, connection := dialogTestModel(t, protocol.Snapshot{})
	drainCommands(t, model.openProviders(), connection)
	handleCommandResult(t, &model, "providers.list", directoryFixture)
	model, _ = press(t, model, typed("openai"), tea.KeyMsg{Type: tea.KeyEnter})
	if view := ansi.Strip(model.View()); !strings.Contains(view, "Sign in with ChatGPT") || !strings.Contains(view, "API key") {
		t.Fatalf("openai methods missing: %s", view)
	}
	model, cmd := press(t, model, tea.KeyMsg{Type: tea.KeyEnter})
	if types := commandTypes(drainCommands(t, cmd, connection)); !contains(types, "providers.login") {
		t.Fatalf("sign-in did not start: %v", types)
	}
	handleCommandResult(t, &model, "providers.login", map[string]any{"url": "https://auth.example/authorize"})
	if view := ansi.Strip(model.View()); !strings.Contains(view, "https://auth.example/authorize") {
		t.Fatalf("sign-in url missing: %s", view)
	}
	cmd = model.handleEnvelope(stateEnvelope(t, 2, protocol.Snapshot{SetupMode: true, LoginState: "done"}))
	if model.dialog.kind != dialogModels || model.dialog.filterProvider != "chatgpt" {
		t.Fatalf("finished sign-in did not open ChatGPT models: %v", model.dialog.kind)
	}
	drainCommands(t, cmd, connection)

	drainCommands(t, model.openProviders(), connection)
	handleCommandResult(t, &model, "providers.list", directoryFixture)
	model, _ = press(t, model, typed("ollama"), tea.KeyMsg{Type: tea.KeyEnter})
	if model.dialog.kind != dialogBaseInput || model.dialog.query != "http://localhost:11434" {
		t.Fatalf("ollama did not ask for a base URL: %v %q", model.dialog.kind, model.dialog.query)
	}
	model, _ = press(t, model, tea.KeyMsg{Type: tea.KeyEnter})
	_, cmd = press(t, model, tea.KeyMsg{Type: tea.KeyEnter})
	sent := lastCommand(t, cmd, connection)
	if !strings.Contains(string(sent.Payload), `"api_base":"http://localhost:11434"`) {
		t.Fatalf("ollama connect sent %s", sent.Payload)
	}
}

func TestDialogShowsBackendErrorsInline(t *testing.T) {
	model, connection := dialogTestModel(t, protocol.Snapshot{})
	drainCommands(t, model.openProviders(), connection)
	handleCommandResult(t, &model, "providers.list", directoryFixture)
	model, _ = press(t, model, typed("groq"), tea.KeyMsg{Type: tea.KeyEnter}, tea.KeyMsg{Type: tea.KeyEnter})
	if view := ansi.Strip(model.View()); !strings.Contains(view, "API key is required") {
		t.Fatalf("empty key not rejected inline: %s", view)
	}
}

func TestEffortAndSettingsDialogs(t *testing.T) {
	model, connection := dialogTestModel(t, protocol.Snapshot{Model: "openai/gpt-5.4", Effort: "high", ScanMode: "deep", ScopeMode: "auto"})
	model.openEffort()
	if view := ansi.Strip(model.View()); !strings.Contains(view, "Select effort") || !strings.Contains(view, "▪ high") {
		t.Fatalf("effort dialog: %s", view)
	}
	model, cmd := press(t, model, tea.KeyMsg{Type: tea.KeyUp}, tea.KeyMsg{Type: tea.KeyEnter})
	sent := lastCommand(t, cmd, connection)
	if !strings.Contains(string(sent.Payload), `"value":"medium"`) {
		t.Fatalf("effort sent %s", sent.Payload)
	}
	model, connection = dialogTestModel(t, protocol.Snapshot{Model: "openai/gpt-5.4", Effort: "high", ScanMode: "deep", ScopeMode: "auto"})
	model.openSettings()
	view := ansi.Strip(model.View())
	for _, want := range []string{"Search settings", "Mode", "deep", "Scope", "auto", "Budget", "none", "openai/gpt-5.4"} {
		if !strings.Contains(view, want) {
			t.Fatalf("settings missing %q: %s", want, view)
		}
	}
	model, _ = press(t, model, tea.KeyMsg{Type: tea.KeyDown}, tea.KeyMsg{Type: tea.KeyDown}, tea.KeyMsg{Type: tea.KeyDown})
	_, cmd = press(t, model, tea.KeyMsg{Type: tea.KeyEnter})
	sent = lastCommand(t, cmd, connection)
	if !strings.Contains(string(sent.Payload), `"value":"quick"`) {
		t.Fatalf("mode toggle sent %s", sent.Payload)
	}
}

func TestStartScreenPointsAtCommandsWhenNoModel(t *testing.T) {
	model, _ := dialogTestModel(t, protocol.Snapshot{})
	view := ansi.Strip(model.View())
	for _, want := range []string{"no model", "ctrl+p to connect a provider", "ctrl+p commands"} {
		if !strings.Contains(view, want) {
			t.Fatalf("start screen missing %q: %s", want, view)
		}
	}
	if strings.Contains(view, "STRIX_LLM") {
		t.Fatalf("start screen still names the env var: %s", view)
	}
}
