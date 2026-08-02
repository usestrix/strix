package render

import (
	"bytes"
	"encoding/base64"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"math"
	"regexp"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Quadrant-block image preview: each terminal cell shows a 2x2 pixel block
// using the Unicode quadrant characters with truecolor foreground/background,
// picked per cell to minimize color error (the chafa/viu approach). This is
// the densest rendering available in terminals without a graphics protocol.

const (
	mosaicMinCols     = 20
	mosaicMaxCols     = 100
	mosaicDefaultCols = 72
	mosaicMaxRows     = 28 // cell rows; two pixel rows per cell
)

var mosaicCols = mosaicDefaultCols

// SetImageWidth sizes image mosaics to the chat content width in cells.
func SetImageWidth(cells int) {
	mosaicCols = min(max(cells, mosaicMinCols), mosaicMaxCols)
}

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

// renderImageMosaic decodes the base64 payload and renders it as truecolor
// quadrant-block rows; returns "" when the image cannot be decoded.
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
	cols := min(mosaicCols, w)
	// A cell holds a 2x2 pixel quadrant; terminal cells are ~1:2, so this
	// stretches pixels slightly but doubles horizontal detail.
	rows := (h*cols + w - 1) / (w * 2)
	rows = min(max(1, rows), mosaicMaxRows)

	var b strings.Builder
	for row := range rows {
		if row > 0 {
			b.WriteString("\n")
		}
		for col := range cols {
			b.WriteString(renderQuadrantCell(img, bounds, col, row, cols, rows))
		}
	}
	return b.String()
}

// Quadrant characters indexed by a bitmask of lit sub-pixels:
// bit 0 = top-left, bit 1 = top-right, bit 2 = bottom-left, bit 3 = bottom-right.
var quadrantChars = [16]string{
	" ", "▘", "▝", "▀", "▖", "▌", "▞", "▛",
	"▗", "▚", "▐", "▜", "▄", "▙", "▟", "█",
}

func renderQuadrantCell(img image.Image, bounds image.Rectangle, col, row, gridW, gridH int) string {
	var px [4][3]float64
	px[0] = averageLinear(img, bounds, col*2, row*2, gridW*2, gridH*2)
	px[1] = averageLinear(img, bounds, col*2+1, row*2, gridW*2, gridH*2)
	px[2] = averageLinear(img, bounds, col*2, row*2+1, gridW*2, gridH*2)
	px[3] = averageLinear(img, bounds, col*2+1, row*2+1, gridW*2, gridH*2)

	// Try every fg/bg split of the four sub-pixels and keep the one that
	// minimizes squared color error against the group averages.
	bestMask, bestErr := 0, -1.0
	var bestFg, bestBg [3]float64
	for mask := range 16 {
		fg, bg, count := [3]float64{}, [3]float64{}, 0
		for i := range 4 {
			if mask&(1<<i) != 0 {
				count++
				for c := range 3 {
					fg[c] += px[i][c]
				}
			} else {
				for c := range 3 {
					bg[c] += px[i][c]
				}
			}
		}
		for c := range 3 {
			if count > 0 {
				fg[c] /= float64(count)
			}
			if count < 4 {
				bg[c] /= float64(4 - count)
			}
		}
		errSum := 0.0
		for i := range 4 {
			target := bg
			if mask&(1<<i) != 0 {
				target = fg
			}
			for c := range 3 {
				d := px[i][c] - target[c]
				errSum += d * d
			}
		}
		if bestErr < 0 || errSum < bestErr {
			bestErr, bestMask, bestFg, bestBg = errSum, mask, fg, bg
		}
	}

	style := lipgloss.NewStyle().Background(lipgloss.Color(linearToHex(bestBg)))
	if bestMask != 0 {
		style = style.Foreground(lipgloss.Color(linearToHex(bestFg)))
	}
	return style.Render(quadrantChars[bestMask])
}

// averageLinear box-samples the source region mapped to grid cell (cx, cy) of
// a gridW x gridH pixel grid, averaging in linear light for correct
// downsampling of fine detail like text.
func averageLinear(img image.Image, bounds image.Rectangle, cx, cy, gridW, gridH int) [3]float64 {
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
	var sum [3]float64
	n := 0
	for y := y0; y < y1; y++ {
		for x := x0; x < x1; x++ {
			pr, pg, pb, _ := img.At(x, y).RGBA()
			sum[0] += srgbToLinear(float64(pr>>8) / 255)
			sum[1] += srgbToLinear(float64(pg>>8) / 255)
			sum[2] += srgbToLinear(float64(pb>>8) / 255)
			n++
		}
	}
	if n == 0 {
		return [3]float64{}
	}
	for c := range 3 {
		sum[c] /= float64(n)
	}
	return sum
}

func srgbToLinear(v float64) float64 {
	if v <= 0.04045 {
		return v / 12.92
	}
	return math.Pow((v+0.055)/1.055, 2.4)
}

func linearToSrgb(v float64) float64 {
	if v <= 0.0031308 {
		return v * 12.92
	}
	return 1.055*math.Pow(v, 1/2.4) - 0.055
}

func linearToHex(c [3]float64) string {
	var out [3]byte
	for i := range 3 {
		out[i] = byte(min(max(linearToSrgb(c[i])*255+0.5, 0), 255))
	}
	return hexColor(out[0], out[1], out[2])
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
