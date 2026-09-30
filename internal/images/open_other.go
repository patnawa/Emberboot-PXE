//go:build !windows

package images

import "os"

func openImageFile(path string) (*os.File, error) { return os.Open(path) }
