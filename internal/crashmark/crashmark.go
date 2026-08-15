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
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return false, nil, err
	}
	if err := os.Chmod(dataDir, 0o700); err != nil {
		return false, nil, err
	}
	marker := filepath.Join(dataDir, ".running")
	if info, statErr := os.Lstat(marker); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return false, nil, &os.PathError{Op: "arm crash marker", Path: marker, Err: os.ErrInvalid}
		}
		wasUnclean = true
	} else if !os.IsNotExist(statErr) {
		return false, nil, statErr
	}
	f, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return wasUnclean, nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return wasUnclean, nil, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return wasUnclean, nil, err
	}
	if err := f.Close(); err != nil {
		return wasUnclean, nil, err
	}
	return wasUnclean, func() { _ = os.Remove(marker) }, nil
}
