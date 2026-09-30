//go:build !windows

package images

import "os"

func replacePublishedISO(source, destination string) error { return os.Rename(source, destination) }
