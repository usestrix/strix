package protocol

import (
	"reflect"
	"testing"
)

func TestProtocolVersionAndCapabilities(t *testing.T) {
	if Version != 3 {
		t.Fatalf("protocol version = %d, want 3", Version)
	}
	wantCapabilities := []string{
		"state-revisions",
		"collection-deltas",
		"structured-command-errors",
		"agents-collection",
	}
	if !reflect.DeepEqual(Capabilities, wantCapabilities) {
		t.Fatalf("capabilities = %#v, want %#v", Capabilities, wantCapabilities)
	}

}
