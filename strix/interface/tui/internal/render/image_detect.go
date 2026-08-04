package render

import (
	"bytes"
	"os"
	"time"

	"github.com/charmbracelet/x/term"
)

// queryBudget bounds the whole capability exchange. A terminal answers in
// microseconds; anything this slow is not going to answer at all.
const queryBudget = 500 * time.Millisecond

// drainBudget is the grace period spent collecting whatever else the terminal
// sent after the answer we were looking for.
const drainBudget = 50 * time.Millisecond

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
	// Everything the terminal sends must be consumed before the terminal echoes
	// it: once cooked mode is back, a reply still in flight is printed to the
	// screen as mojibake like "^[[?62;52;c".
	defer term.Restore(uintptr(fd), oldState) //nolint:errcheck

	// The same 1x1 RGB query used by viuer and yazi; DA1 (CSI c) is answered
	// by every terminal and bounds the read.
	if _, err := out.WriteString("\x1b_Gi=31,s=1,v=1,a=q,t=d,f=24;AAAA\x1b\\\x1b[c"); err != nil {
		return false
	}

	supported, answered := readCapabilityReply(in, queryBudget)
	if answered {
		// The kitty answer arrives before the DA1, so the DA1 is still on its
		// way. Take it now rather than leaving it for the shell to echo.
		drainInput(in, drainBudget)
	}
	return supported
}

// readCapabilityReply reads until the kitty answer or the DA1 that follows it,
// whichever comes first. It reports whether kitty graphics are supported, and
// whether the terminal answered at all within the budget.
func readCapabilityReply(in *os.File, budget time.Duration) (supported, answered bool) {
	deadline := time.Now().Add(budget)
	var buf bytes.Buffer
	chunk := make([]byte, 256)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false, false
		}
		// The read itself has to be bounded. os.File deadlines do not work on a
		// terminal - the fd is blocking, so it is never registered with the
		// runtime poller and SetReadDeadline fails with "file type does not
		// support deadline" - which would leave this read hanging until the
		// terminal happened to send something.
		ready, err := waitReadable(in, remaining)
		if err != nil || !ready {
			return false, false
		}
		n, err := in.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			if apc := bytes.Index(buf.Bytes(), []byte("\x1b_G")); apc >= 0 &&
				bytes.Contains(buf.Bytes()[apc:], []byte(";OK")) {
				return true, true
			}
			// DA1 response: ESC [ ? ... c
			if idx := bytes.Index(buf.Bytes(), []byte("\x1b[?")); idx >= 0 &&
				bytes.IndexByte(buf.Bytes()[idx:], 'c') >= 0 {
				return false, true
			}
		}
		if err != nil {
			return false, false
		}
	}
}

// drainInput consumes whatever is already readable, so no part of the terminal's
// answer survives into cooked mode.
func drainInput(in *os.File, budget time.Duration) {
	deadline := time.Now().Add(budget)
	chunk := make([]byte, 256)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return
		}
		ready, err := waitReadable(in, remaining)
		if err != nil || !ready {
			return
		}
		if _, err := in.Read(chunk); err != nil {
			return
		}
	}
}
