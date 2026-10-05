package render

import "strings"

// SpinnerMarker is a one-cell placeholder for a spinner. Rendered blocks are
// cached, so the chat pane swaps in the current frame (AnimateSpinners) or a
// still circle once the wait is over (StopSpinners).
const SpinnerMarker = "\uE000"

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func StopSpinners(s string) string {
	return strings.ReplaceAll(s, SpinnerMarker, "○")
}

func AnimateSpinners(s string, tick int) string {
	return strings.ReplaceAll(s, SpinnerMarker, spinnerFrames[tick%len(spinnerFrames)])
}
