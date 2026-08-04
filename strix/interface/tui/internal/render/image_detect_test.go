//go:build !windows

package render

import (
	"os"
	"testing"
	"time"
)

// A terminal that ignores the query must not stall startup. This is the bound
// that os.File read deadlines could not provide: a tty descriptor is blocking,
// so it is never registered with the runtime poller and SetReadDeadline fails
// with "file type does not support deadline", leaving the read to hang until the
// terminal happened to send something.
func TestCapabilityReadGivesUpOnASilentTerminal(t *testing.T) {
	reader, writer := pipePair(t)
	defer writer.Close()

	start := time.Now()
	reply := readCapabilityReply(reader, 150*time.Millisecond)

	if reply.supported || reply.answered {
		t.Fatalf("silence reported an answer: %+v", reply)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("the read was not bounded: %s", elapsed)
	}
}

func TestCapabilityReadClassifiesTheReply(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		reply string
		want  bool
	}{
		{"DA1 alone means no kitty support", "\x1b[?62;52;c", false},
		{"a kitty answer means support", "\x1b_Gi=31;OK\x1b\\\x1b[?62;52;c", true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			reader, writer := pipePair(t)
			defer writer.Close()
			if _, err := writer.WriteString(testCase.reply); err != nil {
				t.Fatalf("write reply: %v", err)
			}

			reply := readCapabilityReply(reader, time.Second)

			if !reply.answered {
				t.Fatal("a reply was sent but not seen")
			}
			if reply.supported != testCase.want {
				t.Fatalf("support = %v, want %v", reply.supported, testCase.want)
			}
		})
	}
}

// The DA1 trails a kitty answer, so it is still arriving when the answer is
// recognized. Anything left unread is echoed to the screen once cooked mode
// returns, which is where "^[[?62;52;c" came from.
func TestDrainClearsWhatFollowsTheAnswer(t *testing.T) {
	reader, writer := pipePair(t)
	defer writer.Close()
	if _, err := writer.WriteString("\x1b_Gi=31;OK\x1b\\\x1b[?62;52;c"); err != nil {
		t.Fatalf("write reply: %v", err)
	}

	reply := readCapabilityReply(reader, time.Second)
	if !reply.supported || !reply.answered {
		t.Fatalf("kitty answer not recognized: %+v", reply)
	}
	drainInput(reader, drainBudget)

	leftover, err := waitReadable(reader, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("leftover check failed: %v", err)
	}
	if leftover {
		t.Fatal("part of the reply survived the drain and would be echoed")
	}
}

// The query clears ISIG, so ctrl-c arrives as ETX rather than a signal. It has to
// end the wait instead of being swallowed as terminal noise, which is what left a
// hung startup unresponsive to ctrl-c.
func TestCtrlCEndsTheWait(t *testing.T) {
	reader, writer := pipePair(t)
	defer writer.Close()
	if _, err := writer.Write([]byte{etx}); err != nil {
		t.Fatalf("write ctrl-c: %v", err)
	}

	start := time.Now()
	reply := readCapabilityReply(reader, 10*time.Second)

	if !reply.interrupted {
		t.Fatalf("ctrl-c was not recognized: %+v", reply)
	}
	if reply.answered || reply.supported {
		t.Fatalf("ctrl-c must not be read as a terminal answer: %+v", reply)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("ctrl-c did not end the wait promptly: %s", elapsed)
	}
}

// waitReadable must report readiness without waiting out the whole timeout.
func TestWaitReadableSeesAvailableInput(t *testing.T) {
	reader, writer := pipePair(t)
	defer writer.Close()
	if _, err := writer.WriteString("x"); err != nil {
		t.Fatalf("write: %v", err)
	}

	ready, err := waitReadable(reader, time.Second)
	if err != nil {
		t.Fatalf("waitReadable failed: %v", err)
	}
	if !ready {
		t.Fatal("input was available but waitReadable reported none")
	}
}

func pipePair(t *testing.T) (reader, writer *os.File) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { reader.Close() })
	return reader, writer
}
