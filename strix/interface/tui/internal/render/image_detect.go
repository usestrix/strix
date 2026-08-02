package render

import (
	"bytes"
	"os"
	"time"

	"github.com/charmbracelet/x/term"
)

// DetectKittyGraphics asks the terminal whether it supports the kitty
// graphics protocol, the way kitty's own tooling does: send a 1x1 query
// (a=q) followed by a Primary Device Attributes request, then read until the
// DA1 response arrives. A graphics-capable terminal answers the query with an
// APC "OK" response before the DA1; anything else ignores it. Must run before
// Bubble Tea takes over stdin.
func DetectKittyGraphics() {
	supported := queryKittyGraphics(os.Stdin, os.Stdout)
	KittyGraphicsSupported = func() bool { return supported }
}

func queryKittyGraphics(in, out *os.File) bool {
	fd := int(in.Fd())
	if !term.IsTerminal(uintptr(fd)) {
		return false
	}
	oldState, err := term.MakeRaw(uintptr(fd))
	if err != nil {
		return false
	}
	defer term.Restore(uintptr(fd), oldState) //nolint:errcheck

	// The same 1x1 RGB query used by viuer and yazi; DA1 (CSI c) is answered
	// by every terminal and bounds the read.
	if _, err := out.WriteString("\x1b_Gi=31,s=1,v=1,a=q,t=d,f=24;AAAA\x1b\\\x1b[c"); err != nil {
		return false
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	var buf bytes.Buffer
	chunk := make([]byte, 256)
	for time.Now().Before(deadline) {
		_ = in.SetReadDeadline(deadline)
		n, err := in.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			if apc := bytes.Index(buf.Bytes(), []byte("\x1b_G")); apc >= 0 &&
				bytes.Contains(buf.Bytes()[apc:], []byte(";OK")) {
				return true
			}
			// DA1 response: ESC [ ? ... c
			if idx := bytes.Index(buf.Bytes(), []byte("\x1b[?")); idx >= 0 &&
				bytes.IndexByte(buf.Bytes()[idx:], 'c') >= 0 {
				return false
			}
		}
		if err != nil {
			break
		}
	}
	return false
}
