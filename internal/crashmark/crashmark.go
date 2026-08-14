// Package crashmark detects unclean exits: a marker file exists while the
// daemon runs and is removed on graceful shutdown. Finding it at startup
// means the previous run died — the "it crashed and nobody noticed" signal
// that fires the crash-restart alert.
package crashmark

import (
	"os"
	"path/filepath"
)

// Arm writes the marker and reports whether the previous run exited
// uncleanly. Call Disarm on graceful shutdown.
func Arm(dataDir string) (wasUnclean bool, disarm func(), err error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return false, nil, err
	}
	marker := filepath.Join(dataDir, ".running")
	_, statErr := os.Stat(marker)
	wasUnclean = statErr == nil
	if err := os.WriteFile(marker, []byte(""), 0o644); err != nil {
		return wasUnclean, nil, err
	}
	return wasUnclean, func() { _ = os.Remove(marker) }, nil
}
