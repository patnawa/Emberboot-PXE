package images

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kdomanski/iso9660"
)

// isoHandle is an open ISO with helpers to resolve and read files inside it.
// The underlying os.File is safe for concurrent ReadAt, so one handle serves
// many HTTP requests.
type isoHandle struct {
	f   *os.File
	img *iso9660.Image
}

func openISO(path string) (*isoHandle, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	img, err := iso9660.OpenImage(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("not a readable ISO 9660 image: %w", err)
	}
	return &isoHandle{f: f, img: img}, nil
}

func (h *isoHandle) Close() {
	if h.f != nil {
		h.f.Close()
	}
}

// resolve walks the directory tree case-insensitively (ISO9660 names are
// uppercase-ish and Windows ISOs vary between boot/ and Boot/). Returns the
// file entry or an error naming the missing component.
func (h *isoHandle) resolve(pathInISO string) (*iso9660.File, error) {
	cur, err := h.img.RootDir()
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.Trim(pathInISO, "/"), "/")
	for _, part := range parts {
		if part == "" {
			continue
		}
		if !cur.IsDir() {
			return nil, fmt.Errorf("%s: not a directory", cur.Name())
		}
		children, err := cur.GetChildren()
		if err != nil {
			return nil, err
		}
		var next *iso9660.File
		for _, c := range children {
			if strings.EqualFold(c.Name(), part) {
				next = c
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

// exists reports whether a path resolves to a regular file, returning its
// canonical resolved path for later serving.
func (h *isoHandle) exists(pathInISO string) bool {
	f, err := h.resolve(pathInISO)
	return err == nil && !f.IsDir()
}

// firstExisting returns the first candidate path that resolves to a file.
func (h *isoHandle) firstExisting(candidates ...string) (string, bool) {
	for _, p := range candidates {
		if h.exists(p) {
			return p, true
		}
	}
	return "", false
}

// open returns a ReadSeeker over a file inside the ISO plus its size.
// Files in ISO 9660 are contiguous extents, so this is a zero-copy view.
func (h *isoHandle) open(pathInISO string) (io.ReadSeeker, int64, error) {
	f, err := h.resolve(pathInISO)
	if err != nil {
		return nil, 0, err
	}
	if f.IsDir() {
		return nil, 0, fmt.Errorf("%s: is a directory", pathInISO)
	}
	r := f.Reader()
	rs, ok := r.(io.ReadSeeker)
	if !ok {
		// Never expected (Reader returns *io.SectionReader today); guard so
		// an upstream change degrades loudly rather than corrupting serves.
		return nil, 0, fmt.Errorf("%s: ISO reader is not seekable", pathInISO)
	}
	return rs, f.Size(), nil
}

// list returns the entries of a directory inside the ISO.
func (h *isoHandle) list(dirInISO string) ([]*iso9660.File, error) {
	d, err := h.resolve(dirInISO)
	if err != nil {
		return nil, err
	}
	if !d.IsDir() {
		return nil, fmt.Errorf("%s: not a directory", dirInISO)
	}
	return d.GetChildren()
}
