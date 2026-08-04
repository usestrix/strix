//go:build windows

package render

import (
	"os"
	"time"
)

// waitReadable has no console equivalent worth carrying: no Windows terminal
// implements the kitty graphics protocol, so detection reports no support rather
// than blocking on a reply that never comes.
func waitReadable(_ *os.File, _ time.Duration) (bool, error) {
	return false, nil
}

// interruptSelf has nothing to do: detection never reads on this platform, so
// ctrl-c is never withheld from the console.
func interruptSelf() {}
