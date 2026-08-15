package images

import (
	"io"
	"os"
	"sync"
)

// isoGeneration keeps a validated ISO handle alive until every HTTP reader
// which acquired it has finished. A replacement or removal retires the
// generation immediately (so it cannot accept new readers), but does not
// close the file out from under in-flight responses.
type isoGeneration struct {
	mu      sync.Mutex
	h       *isoHandle
	info    os.FileInfo
	refs    int
	retired bool
	closed  bool
}

func newISOGeneration(h *isoHandle, info os.FileInfo) *isoGeneration {
	return &isoGeneration{h: h, info: info}
}

func (g *isoGeneration) acquire() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.retired || g.closed {
		return false
	}
	g.refs++
	return true
}

func (g *isoGeneration) release() {
	g.mu.Lock()
	if g.refs > 0 {
		g.refs--
	}
	if g.retired && g.refs == 0 {
		g.closeLocked()
	}
	g.mu.Unlock()
}

func (g *isoGeneration) retire() {
	g.mu.Lock()
	g.retired = true
	if g.refs == 0 {
		g.closeLocked()
	}
	g.mu.Unlock()
}

func (g *isoGeneration) closeLocked() {
	if g.closed {
		return
	}
	g.closed = true
	g.h.Close()
}

// leasedReadSeeker makes the generation lifetime explicit at the HTTP call
// site. Close is idempotent so error paths can safely defer it.
type leasedReadSeeker struct {
	io.ReadSeeker
	once    sync.Once
	release func()
}

func (r *leasedReadSeeker) Close() error {
	r.once.Do(r.release)
	return nil
}

// leasedFile retains os.File's optimized ReaderFrom/seek behavior for raw
// ISO HTTP responses while tying the descriptor to one validated generation.
type leasedFile struct {
	*os.File
	once    sync.Once
	release func()
}

func (f *leasedFile) Close() error {
	err := f.File.Close()
	f.once.Do(f.release)
	return err
}
