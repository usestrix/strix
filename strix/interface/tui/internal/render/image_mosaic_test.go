package render

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
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

func TestViewImageRendersMosaic(t *testing.T) {
	uri := testImageDataURI(t, 120, 80)
	out := Tool(tool("view_image", map[string]any{"path": "/tmp/shot.png"}, uri, "completed"))
	if !strings.Contains(out, "▀") {
		t.Fatalf("expected half-block mosaic in render:\n%s", out)
	}
	lines := strings.Split(out, "\n")
	mosaic := 0
	for _, line := range lines {
		if strings.Contains(line, "▀") {
			mosaic++
			if w := ansi.StringWidth(line); w > mosaicCols {
				t.Fatalf("mosaic row too wide: %d", w)
			}
		}
	}
	if mosaic < 2 || mosaic > mosaicMaxRows {
		t.Fatalf("unexpected mosaic row count: %d", mosaic)
	}
}

func TestExtractImageDataURI(t *testing.T) {
	uri := testImageDataURI(t, 8, 8)
	if mime, payload := extractImageDataURI(uri); mime != "png" || payload == "" {
		t.Fatal("raw data URI should extract")
	}
	if mime, _ := extractImageDataURI("type='image' image_url='" + uri + "'"); mime != "png" {
		t.Fatal("repr-style result should extract")
	}
	if mime, _ := extractImageDataURI(map[string]any{"image_url": uri}); mime != "png" {
		t.Fatal("structured result should extract")
	}
	if mime, _ := extractImageDataURI("data:image/png;base64,short"); mime != "" {
		t.Fatal("tiny payload must be rejected")
	}
}
