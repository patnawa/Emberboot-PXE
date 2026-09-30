package images

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

var errValidationCanceled = fmt.Errorf("image validation canceled")

// The immutable directory index and os.File.ReadAt can be shared by concurrent
// HTTP readers. Each response gets its own seek position across all sections.
type isoHandle struct {
	f         *os.File
	root      *isoEntry
	size      int64
	indexOnce sync.Once
	indexErr  error
}

func openISO(path string) (*isoHandle, error) {
	f, err := openImageFile(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	root, err := readISORoot(f, info.Size())
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("not a readable ISO 9660 image: %w", err)
	}
	return &isoHandle{f: f, root: root, size: info.Size()}, nil
}

func (h *isoHandle) Close() {
	if h.f != nil {
		h.f.Close()
	}
}

func (h *isoHandle) index(stop <-chan struct{}) error {
	h.indexOnce.Do(func() {
		r := isoTreeReader{ra: h.f, size: h.size, stop: stop, visited: make(map[int64]bool)}
		h.indexErr = r.readDirectory(h.root, 0)
	})
	return h.indexErr
}

// Validate all file sections and directories, then checksum the entire backing
// file. A truncated final section must never be published as a Ready image.
func (h *isoHandle) validateContents(size int64, stop <-chan struct{}) (string, error) {
	if size <= 0 || size != h.size {
		return "", fmt.Errorf("invalid ISO size")
	}
	if err := h.index(stop); err != nil {
		return "", err
	}
	digest := sha256.New()
	reader := io.NewSectionReader(h.f, 0, size)
	buf := make([]byte, 1<<20)
	var total int64
	for total < size {
		select {
		case <-stop:
			return "", errValidationCanceled
		default:
		}
		n, readErr := reader.Read(buf)
		if n > 0 {
			_, _ = digest.Write(buf[:n])
			total += int64(n)
		}
		if readErr != nil {
			if readErr == io.EOF && total == size {
				break
			}
			return "", fmt.Errorf("checksum ISO: %w", readErr)
		}
		if n == 0 {
			return "", fmt.Errorf("checksum ISO: read stalled after %d of %d bytes", total, size)
		}
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func (h *isoHandle) resolve(pathInISO string) (*isoEntry, error) {
	if err := h.index(nil); err != nil {
		return nil, err
	}
	cur := h.root
	for _, part := range strings.Split(strings.Trim(pathInISO, "/"), "/") {
		if part == "" {
			continue
		}
		if !cur.IsDir() {
			return nil, fmt.Errorf("%s: not a directory", cur.Name())
		}
		var next *isoEntry
		for _, child := range cur.children {
			if strings.EqualFold(child.Name(), part) {
				next = child
				break
			}
		}
		if next == nil {
			return nil, fmt.Errorf("%s: no such file in ISO", pathInISO)
		}
		cur = next
	}
	return cur, nil
}

func (h *isoHandle) exists(pathInISO string) bool {
	f, err := h.resolve(pathInISO)
	return err == nil && !f.IsDir()
}

func (h *isoHandle) sizeOf(pathInISO string) int64 {
	f, err := h.resolve(pathInISO)
	if err != nil || f.IsDir() {
		return 0
	}
	return f.Size()
}

func (h *isoHandle) firstExisting(candidates ...string) (string, bool) {
	for _, p := range candidates {
		if h.exists(p) {
			return p, true
		}
	}
	return "", false
}

func (h *isoHandle) open(pathInISO string) (io.ReadSeeker, int64, error) {
	f, err := h.resolve(pathInISO)
	if err != nil {
		return nil, 0, err
	}
	if f.IsDir() {
		return nil, 0, fmt.Errorf("%s: is a directory", pathInISO)
	}
	if len(f.extents) == 1 {
		return io.NewSectionReader(h.f, f.extents[0].offset, f.size), f.size, nil
	}
	return io.NewSectionReader(isoFileReader{ra: h.f, file: f}, 0, f.size), f.size, nil
}
