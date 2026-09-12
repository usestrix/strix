package app

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"testing"

	"github.com/usestrix/strix/tui/internal/protocol"
	"github.com/usestrix/strix/tui/internal/render"
)

func benchImageDataURI(b *testing.B, w, h int) string {
	b.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.Set(x, y, color.RGBA{R: uint8(x), G: uint8(y), B: 0x40, A: 0xff})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		b.Fatal(err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

// BenchmarkChatContentWithImages measures a frame render for a trace holding
// many inline images, the case that made the TUI unresponsive.
func BenchmarkChatContentWithImages(b *testing.B) {
	supported := render.KittyGraphicsSupported
	render.KittyGraphicsSupported = func() bool { return true }
	b.Cleanup(func() { render.KittyGraphicsSupported = supported })

	model := New(nil)
	model.width, model.height = 130, 40
	model.showSplash = false
	model.ready = true
	events := make([]protocol.Event, 0, 20)
	for i := range 20 {
		events = append(events, protocol.Event{
			ID: fmt.Sprintf("%d", i), AgentID: "one", Type: "tool",
			Data: map[string]any{
				"tool_name": "view_image",
				"args":      map[string]any{"path": fmt.Sprintf("/tmp/shot-%d.png", i)},
				"result":    benchImageDataURI(b, 2000+i, 1400),
				"status":    "completed",
			},
		})
	}
	model.snapshot = protocol.Snapshot{
		Agents: []protocol.Agent{{ID: "one", Name: "Agent", Status: "running"}},
		Events: events,
	}
	model.resizeViewport()

	b.ResetTimer()
	for b.Loop() {
		_ = model.View()
	}
}

func BenchmarkFrameWithImagesAfterUpdate(b *testing.B) {
	supported := render.KittyGraphicsSupported
	render.KittyGraphicsSupported = func() bool { return true }
	b.Cleanup(func() { render.KittyGraphicsSupported = supported })

	model := New(nil)
	model.width, model.height = 130, 40
	model.showSplash = false
	model.ready = true
	events := make([]protocol.Event, 0, 20)
	for i := range 20 {
		events = append(events, protocol.Event{
			ID: fmt.Sprintf("%d", i), AgentID: "one", Type: "tool",
			Data: map[string]any{
				"tool_name": "view_image",
				"args":      map[string]any{"path": fmt.Sprintf("/tmp/shot-%d.png", i)},
				"result":    benchImageDataURI(b, 2000+i, 1400),
				"status":    "completed",
			},
		})
	}
	model.snapshot = protocol.Snapshot{
		Agents: []protocol.Agent{{ID: "one", Name: "Agent", Status: "running"}},
		Events: events,
	}
	model.resizeViewport()

	b.ResetTimer()
	for b.Loop() {
		model.refreshViewport()
		_ = model.View()
	}
}
