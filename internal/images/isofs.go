package images

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kdomanski/iso9660"
)

var errValidationCanceled = fmt.Errorf("image validation canceled")

// isoHandle is an open ISO with helpers to resolve and read files inside it.
// The underlying os.File is safe for concurrent ReadAt, so one handle serves
// many HTTP requests.
type isoHandle struct {
	f   *os.File
	img *iso9660.Image
}

func openISO(path string) (h *isoHandle, err error) {
	var f *os.File
	defer func() {
		if recovered := recover(); recovered != nil {
			if f != nil {
				f.Close()
			}
			h = nil
			err = fmt.Errorf("malformed ISO metadata: %v", recovered)
		}
	}()
	f, err = os.Open(path)
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

// validateContents walks every directory and probes the final byte of every
// file extent. ISO parsers can successfully read the primary volume
// descriptor of a truncated image; this full tree walk catches extents which
// point beyond the actual copy. The checksum also reads the complete backing
// file so validation fails on an unreadable/sparse remote copy rather than at
// client boot time.
func (h *isoHandle) validateContents(size int64, stop <-chan struct{}) (checksum string, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			checksum = ""
			err = fmt.Errorf("malformed ISO metadata: %v", recovered)
		}
	}()
	if size <= 0 {
		return "", fmt.Errorf("empty ISO")
	}
	root, err := h.img.RootDir()
	if err != nil {
		return "", fmt.Errorf("read root directory: %w", err)
	}
	stack := []*iso9660.File{root}
	entries := 0
	const maxEntries = 1_000_000
	for len(stack) > 0 {
		select {
		case <-stop:
			return "", errValidationCanceled
		default:
		}
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		entries++
		if entries > maxEntries {
			return "", fmt.Errorf("ISO contains more than %d entries", maxEntries)
		}
		if f.IsDir() {
			const maxDirectoryBytes = 256 << 20
			if f.Size() < 0 || f.Size() > size || f.Size() > maxDirectoryBytes {
				return "", fmt.Errorf("directory %q has implausible extent size %d", f.Name(), f.Size())
			}
			children, err := f.GetChildren()
			if err != nil {
				return "", fmt.Errorf("read directory %q: %w", f.Name(), err)
			}
			stack = append(stack, children...)
			continue
		}
		if f.Size() == 0 {
			continue
		}
		if f.Size() < 0 || f.Size() > size {
			return "", fmt.Errorf("file %q has implausible extent size %d", f.Name(), f.Size())
		}
		r, ok := f.Reader().(io.ReaderAt)
		if !ok {
			return "", fmt.Errorf("file %q extent is not random-access", f.Name())
		}
		var last [1]byte
		if n, err := r.ReadAt(last[:], f.Size()-1); n != 1 || err != nil {
			return "", fmt.Errorf("file %q has an incomplete extent: read %d bytes: %w", f.Name(), n, err)
		}
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

// sizeOf returns a file's size in bytes, 0 if it does not resolve.
func (h *isoHandle) sizeOf(pathInISO string) int64 {
	f, err := h.resolve(pathInISO)
	if err != nil || f.IsDir() {
		return 0
	}
	return f.Size()
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
