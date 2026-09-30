package images

import (
	"bytes"
	"testing"

	"github.com/kdomanski/iso9660"
)

func FuzzISODirectoryRecords(f *testing.F) {
	var seed []byte
	for _, name := range []string{"\x00", "\x01", "A.BIN;1"} {
		record := iso9660.DirectoryEntry{Identifier: name, VolumeSequenceNumber: 1}
		if len(name) == 1 {
			record.FileFlags = 2
			record.ExtentLength = 2048
		}
		raw, err := record.MarshalBinary()
		if err != nil {
			f.Fatal(err)
		}
		seed = append(seed, raw...)
	}
	seed = append(seed, make([]byte, 2048-len(seed))...)
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 || len(data) > 32*2048 {
			return
		}
		root := &isoEntry{dir: true, size: int64(len(data)), extents: []isoExtent{{size: int64(len(data))}}}
		reader := isoTreeReader{ra: bytes.NewReader(data), size: int64(len(data)), visited: make(map[int64]bool)}
		// Malformed metadata may be rejected, but must not panic or loop.
		_ = reader.readDirectory(root, 0)
	})
}
