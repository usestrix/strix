package render

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	"strings"
	"sync"
)

// Native inline images via the kitty graphics protocol with Unicode
// placeholders (https://sw.kovidgoyal.net/kitty/graphics-protocol/): the image
// is transmitted once out of band with a virtual placement, and the chat trace
// renders placeholder cells that the terminal replaces with real pixels. The
// placeholder rows are plain styled text, so they scroll and diff like any
// other Bubble Tea content. Terminals without the protocol show no preview.

const (
	imageMinCols     = 20
	imageMaxCols     = 100
	imageDefaultCols = 72
	imageMaxRows     = 28
	kittyChunkSize   = 4096
)

var imageCols = imageDefaultCols

// SetImageWidth sizes inline image placements to the chat content width in cells.
func SetImageWidth(cells int) {
	imageCols = min(max(cells, imageMinCols), imageMaxCols)
}

// KittyGraphicsSupported reports whether the terminal supports the kitty
// graphics protocol; set at startup by DetectKittyGraphics via a live
// terminal query.
var KittyGraphicsSupported = func() bool { return false }

type kittyPlacement struct {
	id          uint32
	cols        int
	rows        int
	placeholder string
}

var (
	kittyMu     sync.Mutex
	kittyByHash = map[string]kittyPlacement{}
	kittyQueue  []string
	kittyNextID uint32 = 1
)

// DrainImageTransmissions returns queued kitty transmit/placement sequences,
// to be written directly to the terminal exactly once per image.
func DrainImageTransmissions() []string {
	kittyMu.Lock()
	defer kittyMu.Unlock()
	out := kittyQueue
	kittyQueue = nil
	return out
}

// payloadKey identifies an image payload without hashing megabytes of base64
// on every frame: its length plus both ends are enough to tell distinct
// images apart.
func payloadKey(payload string) string {
	const edge = 64
	if len(payload) <= 2*edge {
		return payload
	}
	return fmt.Sprintf("%d:%s:%s", len(payload), payload[:edge], payload[len(payload)-edge:])
}

// kittyImageBlock registers the image payload (queueing its transmission on
// first sight) and returns the styled placeholder block for the chat trace.
func kittyImageBlock(mime, payload string) string {
	kittyMu.Lock()
	defer kittyMu.Unlock()
	key := payloadKey(payload)
	placement, ok := kittyByHash[key]
	if !ok {
		pngData, w, h := payloadToPNG(mime, payload)
		if pngData == nil {
			return ""
		}
		cols := min(imageCols, w)
		rows := (h*cols + w - 1) / (w * 2)
		rows = min(max(1, rows), imageMaxRows)
		placement = kittyPlacement{id: kittyNextID, cols: cols, rows: rows}
		placement.placeholder = kittyPlaceholder(placement)
		kittyNextID++
		kittyByHash[key] = placement
		kittyQueue = append(kittyQueue, kittyTransmit(placement, pngData))
	}
	return placement.placeholder
}

func payloadToPNG(mime, payload string) (data []byte, w, h int) {
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, 0, 0
	}
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, 0, 0
	}
	bounds := img.Bounds()
	if bounds.Dx() <= 0 || bounds.Dy() <= 0 {
		return nil, 0, 0
	}
	if mime == "png" {
		return raw, bounds.Dx(), bounds.Dy()
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, 0, 0
	}
	return buf.Bytes(), bounds.Dx(), bounds.Dy()
}

// kittyTransmit builds the chunked APC sequences transmitting the PNG and
// creating a virtual (U=1) placement for Unicode placeholders.
func kittyTransmit(p kittyPlacement, pngData []byte) string {
	encoded := base64.StdEncoding.EncodeToString(pngData)
	var b strings.Builder
	first := true
	for len(encoded) > 0 {
		chunk := encoded
		if len(chunk) > kittyChunkSize {
			chunk = chunk[:kittyChunkSize]
		}
		encoded = encoded[len(chunk):]
		more := 0
		if len(encoded) > 0 {
			more = 1
		}
		if first {
			fmt.Fprintf(&b, "\x1b_Ga=t,q=2,f=100,i=%d,m=%d;%s\x1b\\", p.id, more, chunk)
			first = false
		} else {
			fmt.Fprintf(&b, "\x1b_Gm=%d;%s\x1b\\", more, chunk)
		}
	}
	fmt.Fprintf(&b, "\x1b_Ga=p,q=2,U=1,i=%d,c=%d,r=%d\x1b\\", p.id, p.cols, p.rows)
	return b.String()
}

// kittyPlaceholder renders the rows x cols grid of U+10EEEE placeholder cells
// carrying the image id in the foreground color and the cell position in
// row/column diacritics. The id must reach the terminal as an exact truecolor
// value, so the SGR sequence is emitted directly rather than through lipgloss
// (whose profile detection may downsample it).
func kittyPlaceholder(p kittyPlacement) string {
	id := p.id & 0xffffff
	var b strings.Builder
	for row := range p.rows {
		if row > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "\x1b[38;2;%d;%d;%dm", id>>16&0xff, id>>8&0xff, id&0xff)
		for col := range p.cols {
			b.WriteRune(0x10eeee)
			b.WriteRune(rowColumnDiacritics[row])
			b.WriteRune(rowColumnDiacritics[col])
		}
		b.WriteString("\x1b[39m")
	}
	return b.String()
}

// rowColumnDiacritics is kitty's canonical placeholder diacritic table
// (gen/rowcolumn-diacritics.txt); index n encodes row/column number n.
var rowColumnDiacritics = []rune{
	0x0305, 0x030D, 0x030E, 0x0310, 0x0312, 0x033D, 0x033E, 0x033F, 0x0346, 0x034A, 0x034B, 0x034C,
	0x0350, 0x0351, 0x0352, 0x0357, 0x035B, 0x0363, 0x0364, 0x0365, 0x0366, 0x0367, 0x0368, 0x0369,
	0x036A, 0x036B, 0x036C, 0x036D, 0x036E, 0x036F, 0x0483, 0x0484, 0x0485, 0x0486, 0x0487, 0x0592,
	0x0593, 0x0594, 0x0595, 0x0597, 0x0598, 0x0599, 0x059C, 0x059D, 0x059E, 0x059F, 0x05A0, 0x05A1,
	0x05A8, 0x05A9, 0x05AB, 0x05AC, 0x05AF, 0x05C4, 0x0610, 0x0611, 0x0612, 0x0613, 0x0614, 0x0615,
	0x0616, 0x0617, 0x0657, 0x0658, 0x0659, 0x065A, 0x065B, 0x065D, 0x065E, 0x06D6, 0x06D7, 0x06D8,
	0x06D9, 0x06DA, 0x06DB, 0x06DC, 0x06DF, 0x06E0, 0x06E1, 0x06E2, 0x06E4, 0x06E7, 0x06E8, 0x06EB,
	0x06EC, 0x0730, 0x0732, 0x0733, 0x0735, 0x0736, 0x073A, 0x073D, 0x073F, 0x0740, 0x0741, 0x0743,
	0x0745, 0x0747, 0x0749, 0x074A, 0x07EB, 0x07EC, 0x07ED, 0x07EE, 0x07EF, 0x07F0, 0x07F1, 0x07F3,
	0x0816, 0x0817, 0x0818, 0x0819, 0x081B, 0x081C, 0x081D, 0x081E, 0x081F, 0x0820, 0x0821, 0x0822,
	0x0823, 0x0825, 0x0826, 0x0827, 0x0829, 0x082A, 0x082B, 0x082C, 0x082D, 0x0951, 0x0953, 0x0954,
	0x0F82, 0x0F83, 0x0F86, 0x0F87, 0x135D, 0x135E, 0x135F, 0x17DD, 0x193A, 0x1A17, 0x1A75, 0x1A76,
	0x1A77, 0x1A78, 0x1A79, 0x1A7A, 0x1A7B, 0x1A7C, 0x1B6B, 0x1B6D, 0x1B6E, 0x1B6F, 0x1B70, 0x1B71,
	0x1B72, 0x1B73, 0x1CD0, 0x1CD1, 0x1CD2, 0x1CDA, 0x1CDB, 0x1CE0, 0x1DC0, 0x1DC1, 0x1DC3, 0x1DC4,
	0x1DC5, 0x1DC6, 0x1DC7, 0x1DC8, 0x1DC9, 0x1DCB, 0x1DCC, 0x1DD1, 0x1DD2, 0x1DD3, 0x1DD4, 0x1DD5,
	0x1DD6, 0x1DD7, 0x1DD8, 0x1DD9, 0x1DDA, 0x1DDB, 0x1DDC, 0x1DDD, 0x1DDE, 0x1DDF, 0x1DE0, 0x1DE1,
	0x1DE2, 0x1DE3, 0x1DE4, 0x1DE5, 0x1DE6, 0x1DFE, 0x20D0, 0x20D1, 0x20D4, 0x20D5, 0x20D6, 0x20D7,
	0x20DB, 0x20DC, 0x20E1, 0x20E7, 0x20E9, 0x20F0, 0x2CEF, 0x2CF0, 0x2CF1, 0x2DE0, 0x2DE1, 0x2DE2,
	0x2DE3, 0x2DE4, 0x2DE5, 0x2DE6, 0x2DE7, 0x2DE8, 0x2DE9, 0x2DEA, 0x2DEB, 0x2DEC, 0x2DED, 0x2DEE,
	0x2DEF, 0x2DF0, 0x2DF1, 0x2DF2, 0x2DF3, 0x2DF4, 0x2DF5, 0x2DF6, 0x2DF7, 0x2DF8, 0x2DF9, 0x2DFA,
	0x2DFB, 0x2DFC, 0x2DFD, 0x2DFE, 0x2DFF, 0xA66F, 0xA67C, 0xA67D, 0xA6F0, 0xA6F1, 0xA8E0, 0xA8E1,
	0xA8E2, 0xA8E3, 0xA8E4, 0xA8E5, 0xA8E6, 0xA8E7, 0xA8E8, 0xA8E9, 0xA8EA, 0xA8EB, 0xA8EC, 0xA8ED,
	0xA8EE, 0xA8EF, 0xA8F0, 0xA8F1, 0xAAB0, 0xAAB2, 0xAAB3, 0xAAB7, 0xAAB8, 0xAABE, 0xAABF, 0xAAC1,
	0xFE20, 0xFE21, 0xFE22, 0xFE23, 0xFE24, 0xFE25, 0xFE26, 0x10A0F, 0x10A38, 0x1D185, 0x1D186,
	0x1D187, 0x1D188, 0x1D189, 0x1D1AA, 0x1D1AB, 0x1D1AC, 0x1D1AD, 0x1D242, 0x1D243, 0x1D244,
}
