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

// etx is what ctrl-c delivers while ISIG is cleared.
const etx = 0x03

// DetectKittyGraphics asks the terminal whether it supports the kitty
// graphics protocol, the way kitty's own tooling does: send a 1x1 query
// (a=q) followed by a Primary Device Attributes request, then read until the
// DA1 response arrives. A graphics-capable terminal answers the query with an
// APC "OK" response before the DA1; anything else ignores it. Must run before
// Bubble Tea takes over stdin.
func DetectKittyGraphics() {
	supported, interrupted := queryKittyGraphics(os.Stdin, os.Stdout)
	KittyGraphicsSupported = func() bool { return supported }
	if interrupted {
		// The query runs with ISIG cleared, so ctrl-c arrives as a byte instead
		// of a signal. Raise it now that the terminal is restored, so a ctrl-c
		// during startup quits rather than being swallowed.
		interruptSelf()
	}
}

func queryKittyGraphics(in, out *os.File) (supported, interrupted bool) {
	fd := int(in.Fd())
	if !term.IsTerminal(uintptr(fd)) {
		return false, false
	}
	oldState, err := term.MakeRaw(uintptr(fd))
	if err != nil {
		return false, false
	}
	// Everything the terminal sends must be consumed before the terminal echoes
	// it: once cooked mode is back, a reply still in flight is printed to the
	// screen as mojibake like "^[[?62;52;c".
	defer term.Restore(uintptr(fd), oldState) //nolint:errcheck

	// The same 1x1 RGB query used by viuer and yazi; DA1 (CSI c) is answered
	// by every terminal and bounds the read.
	if _, err := out.WriteString("\x1b_Gi=31,s=1,v=1,a=q,t=d,f=24;AAAA\x1b\\\x1b[c"); err != nil {
		return false, false
	}

	reply := readCapabilityReply(in, queryBudget)
	if reply.answered {
		// The kitty answer arrives before the DA1, so the DA1 is still on its
		// way. Take it now rather than leaving it for the shell to echo.
		drainInput(in, drainBudget)
	}
	return reply.supported, reply.interrupted
}

// capabilityReply is what the terminal told us: whether it supports the
// protocol, whether it answered at all, and whether the user pressed ctrl-c
// while we were waiting.
type capabilityReply struct {
	supported   bool
	answered    bool
	interrupted bool
}

// readCapabilityReply reads until the kitty answer or the DA1 that follows it,
// whichever comes first.
func readCapabilityReply(in *os.File, budget time.Duration) capabilityReply {
	deadline := time.Now().Add(budget)
	var buf bytes.Buffer
	chunk := make([]byte, 256)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return capabilityReply{}
		}
		// The read itself has to be bounded. os.File deadlines do not work on a
		// terminal - the fd is blocking, so it is never registered with the
		// runtime poller and SetReadDeadline fails with "file type does not
		// support deadline" - which would leave this read hanging until the
		// terminal happened to send something.
		ready, err := waitReadable(in, remaining)
		if err != nil || !ready {
			return capabilityReply{}
		}
		n, err := in.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			// ctrl-c is ETX here rather than a signal. Stop waiting on the
			// terminal the moment the user asks to leave.
			if bytes.IndexByte(buf.Bytes(), etx) >= 0 {
				return capabilityReply{interrupted: true}
			}
			if apc := bytes.Index(buf.Bytes(), []byte("\x1b_G")); apc >= 0 &&
				bytes.Contains(buf.Bytes()[apc:], []byte(";OK")) {
				return capabilityReply{supported: true, answered: true}
			}
			// DA1 response: ESC [ ? ... c
			if idx := bytes.Index(buf.Bytes(), []byte("\x1b[?")); idx >= 0 &&
				bytes.IndexByte(buf.Bytes()[idx:], 'c') >= 0 {
				return capabilityReply{answered: true}
			}
		}
		if err != nil {
			return capabilityReply{}
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
