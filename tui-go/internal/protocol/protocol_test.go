package protocol

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestProtocolVersionAndProviderStatusFields(t *testing.T) {
	if Version != 3 {
		t.Fatalf("protocol version = %d, want 3", Version)
	}
	wantCapabilities := []string{
		"state-revisions",
		"collection-deltas",
		"structured-command-errors",
		"paged-models",
		"agents-collection",
	}
	if !reflect.DeepEqual(Capabilities, wantCapabilities) {
		t.Fatalf("capabilities = %#v, want %#v", Capabilities, wantCapabilities)
	}

	raw := []byte(`{"name":"openai","label":"OpenAI","configured":true,"key_env":"OPENAI_API_KEY","custom":false,"state":"external","detail":"authenticated by environment"}`)
	var provider Provider
	if err := json.Unmarshal(raw, &provider); err != nil {
		t.Fatal(err)
	}
	if provider.State != "external" || provider.Detail != "authenticated by environment" {
		t.Fatalf("provider status fields = %q, %q", provider.State, provider.Detail)
	}
}

func TestModelsResultDecodesAggregateGroups(t *testing.T) {
	raw := []byte(`{"listing_id":"listing-1","cursor":0,"next_cursor":1,"done":true,"groups":[{"provider":"openai","label":"OpenAI","models":["openai/gpt-5"],"allow_manual":false,"error":""},{"provider":"custom-local","label":"Local GPU","models":[],"allow_manual":true,"error":"offline"}],"providers":[]}`)
	var result ModelsResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.ListingID != "listing-1" || !result.Done || result.NextCursor != 1 || len(result.Groups) != 2 || result.Groups[0].Models[0] != "openai/gpt-5" || !result.Groups[1].AllowManual || result.Groups[1].Error != "offline" {
		t.Fatalf("decoded models result = %#v", result)
	}
}
