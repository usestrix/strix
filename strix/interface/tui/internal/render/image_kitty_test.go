package render

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
)

func testImageDataURI(t *testing.T, w, h int) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.Set(x, y, color.RGBA{R: uint8(255 * x / w), G: uint8(255 * y / h), B: 128, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

func withKittySupport(t *testing.T, supported bool) {
	t.Helper()
	previous := KittyGraphicsSupported
	KittyGraphicsSupported = func() bool { return supported }
	t.Cleanup(func() { KittyGraphicsSupported = previous })
}

func TestViewImageRendersKittyPlaceholders(t *testing.T) {
	withKittySupport(t, true)
	uri := testImageDataURI(t, 120, 80)
	out := Tool(tool("view_image", map[string]any{"path": "/tmp/shot.png"}, uri, "completed"))
	if !strings.ContainsRune(out, 0x10eeee) {
		t.Fatalf("expected kitty placeholder cells in render:\n%s", out)
	}

	transmissions := DrainImageTransmissions()
	if len(transmissions) != 1 {
		t.Fatalf("expected one queued transmission, got %d", len(transmissions))
	}
	seq := transmissions[0]
	if !strings.Contains(seq, "\x1b_Ga=t,q=2,f=100,") {
		t.Fatalf("missing transmit sequence: %.80s", seq)
	}
	if !strings.Contains(seq, "a=p,q=2,U=1,") {
		t.Fatalf("missing virtual placement: %.80s", seq)
	}

	// Re-rendering the same image must not queue a second transmission.
	Tool(tool("view_image", map[string]any{"path": "/tmp/shot.png"}, uri, "completed"))
	if again := DrainImageTransmissions(); len(again) != 0 {
		t.Fatalf("image retransmitted: %d", len(again))
	}
}

func TestViewImageWithoutKittySupportShowsNoPreview(t *testing.T) {
	withKittySupport(t, false)
	uri := testImageDataURI(t, 60, 40)
	out := Tool(tool("view_image", map[string]any{"path": "/tmp/shot.png"}, uri, "completed"))
	if !strings.Contains(out, "✓") {
		t.Fatalf("expected success check:\n%s", out)
	}
	if strings.ContainsRune(out, 0x10eeee) {
		t.Fatal("placeholder cells must not render without kitty graphics support")
	}
	if len(DrainImageTransmissions()) != 0 {
		t.Fatal("no transmissions expected without kitty graphics support")
	}
}

func TestExtractImageDataURI(t *testing.T) {
	uri := testImageDataURI(t, 8, 8)
	if mime, payload := extractImageDataURI(uri); mime != "png" || payload == "" {
		t.Fatal("raw data URI should extract")
	}
	if mime, _ := extractImageDataURI(map[string]any{"image_url": uri}); mime != "png" {
		t.Fatal("structured result should extract")
	}
	if mime, _ := extractImageDataURI("data:image/png;base64,short"); mime != "" {
		t.Fatal("tiny payload must be rejected")
	}
}

func TestKittyPlaceholderGrid(t *testing.T) {
	p := kittyPlacement{id: 3, cols: 4, rows: 2}
	out := kittyPlaceholder(p)
	lines := strings.Split(out, "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(lines))
	}
	if got := strings.Count(out, string(rune(0x10eeee))); got != 8 {
		t.Fatalf("expected 8 placeholder cells, got %d", got)
	}
	if !strings.Contains(out, "\x1b[38;2;0;0;3m") {
		t.Fatalf("placeholder must carry the image id in the foreground color:\n%q", out)
	}
}
