//go:build !windows

package render

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// waitReadable reports whether the descriptor has input available within the
// timeout. poll(2) works on a blocking terminal descriptor, which is what a tty
// is and why os.File read deadlines cannot be used here.
func waitReadable(in *os.File, timeout time.Duration) (bool, error) {
	fds := []unix.PollFd{{Fd: int32(in.Fd()), Events: unix.POLLIN}}
	milliseconds := int(timeout.Milliseconds())
	if milliseconds <= 0 {
		milliseconds = 1
	}
	for {
		n, err := unix.Poll(fds, milliseconds)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return false, err
		}
		return n > 0, nil
	}
}

// interruptSelf raises the interrupt the terminal could not deliver while the
// capability query held the terminal with signals disabled.
func interruptSelf() {
	_ = unix.Kill(os.Getpid(), unix.SIGINT)
}
