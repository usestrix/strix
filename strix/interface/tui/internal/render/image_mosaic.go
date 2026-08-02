package render

import (
	"bytes"
	"encoding/base64"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"regexp"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Half-block image preview: each terminal cell shows two vertically stacked
// pixels using "▀" with truecolor foreground (top) and background (bottom),
// mirroring what the web app's ViewImageRenderer shows inline.

const (
	mosaicMaxCols = 60
	mosaicMaxRows = 20 // cell rows; two pixel rows per cell
)

var imageDataURIRE = regexp.MustCompile(`data:image/(png|jpe?g|gif|webp);base64,([A-Za-z0-9+/]+={0,2})`)

// extractImageDataURI pulls a base64 image payload out of a view_image tool
// result: a raw data URI, an `image_url='data:...'` repr, or a structured
// map with an image_url/url field.
func extractImageDataURI(result any) (mime, payload string) {
	var s string
	switch v := result.(type) {
	case string:
		s = v
	case map[string]any:
		if u := StringValue(v["image_url"]); u != "" {
			s = u
		} else if u := StringValue(v["url"]); u != "" {
			s = u
		}
	}
	if s == "" {
		return "", ""
	}
	m := imageDataURIRE.FindStringSubmatch(s)
	if m == nil || len(m[2]) < 100 || len(m[2])%4 != 0 {
		return "", ""
	}
	return m[1], m[2]
}

// renderImageMosaic decodes the base64 payload and renders it as half-block
// truecolor rows; returns "" when the image cannot be decoded.
func renderImageMosaic(payload string) string {
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return ""
	}
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return ""
	}
	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()
	if w <= 0 || h <= 0 {
		return ""
	}
	cols := min(mosaicMaxCols, w)
	// One cell is roughly 1x2 pixels; preserve aspect in cell space.
	rows := (h*cols + w - 1) / (w * 2)
	rows = min(max(1, rows), mosaicMaxRows)

	var b strings.Builder
	for row := range rows {
		if row > 0 {
			b.WriteString("\n")
		}
		for col := range cols {
			top := averageColor(img, bounds, col, row*2, cols, rows*2)
			bottom := averageColor(img, bounds, col, row*2+1, cols, rows*2)
			style := lipgloss.NewStyle().
				Foreground(lipgloss.Color(top)).
				Background(lipgloss.Color(bottom))
			b.WriteString(style.Render("▀"))
		}
	}
	return b.String()
}

// averageColor box-samples the source region mapped to grid cell (cx, cy) of
// a gridW x gridH pixel grid, returning a hex color.
func averageColor(img image.Image, bounds image.Rectangle, cx, cy, gridW, gridH int) string {
	w, h := bounds.Dx(), bounds.Dy()
	x0 := bounds.Min.X + cx*w/gridW
	x1 := bounds.Min.X + (cx+1)*w/gridW
	y0 := bounds.Min.Y + cy*h/gridH
	y1 := bounds.Min.Y + (cy+1)*h/gridH
	if x1 <= x0 {
		x1 = x0 + 1
	}
	if y1 <= y0 {
		y1 = y0 + 1
	}
	var r, g, bl, n uint64
	for y := y0; y < y1; y++ {
		for x := x0; x < x1; x++ {
			pr, pg, pb, _ := img.At(x, y).RGBA()
			r += uint64(pr >> 8)
			g += uint64(pg >> 8)
			bl += uint64(pb >> 8)
			n++
		}
	}
	if n == 0 {
		return "#000000"
	}
	return hexColor(byte(r/n), byte(g/n), byte(bl/n))
}

const hexDigits = "0123456789abcdef"

func hexColor(r, g, b byte) string {
	out := [7]byte{'#'}
	for i, v := range [3]byte{r, g, b} {
		out[1+i*2] = hexDigits[v>>4]
		out[2+i*2] = hexDigits[v&0x0f]
	}
	return string(out[:])
}
