package logging

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Record is one captured log line for the dashboard's live log view.
type Record struct {
	Time  time.Time `json:"time"`
	Level string    `json:"level"`
	Msg   string    `json:"msg"`
	Attrs string    `json:"attrs,omitempty"`
}

const ringSize = 1000

// ringCore is the shared buffer: every derived handler (WithAttrs/WithGroup)
// writes into the same ring so the dashboard sees one unified stream.
type ringCore struct {
	mu   sync.Mutex
	buf  [ringSize]Record
	next int
	full bool
}

// Ring is a slog.Handler that keeps the last N records in memory while
// forwarding everything to an inner handler. Purely diagnostic: losing it
// loses nothing durable.
type Ring struct {
	core  *ringCore
	inner slog.Handler
	attrs []slog.Attr
}

// NewRing wraps inner with a capture buffer.
func NewRing(inner slog.Handler) *Ring {
	return &Ring{core: &ringCore{}, inner: inner}
}

func (r *Ring) Enabled(ctx context.Context, level slog.Level) bool {
	return r.inner.Enabled(ctx, level)
}

func (r *Ring) Handle(ctx context.Context, rec slog.Record) error {
	var b strings.Builder
	for _, a := range r.attrs {
		appendAttr(&b, a)
	}
	rec.Attrs(func(a slog.Attr) bool { appendAttr(&b, a); return true })
	c := r.core
	c.mu.Lock()
	c.buf[c.next] = Record{Time: rec.Time, Level: rec.Level.String(), Msg: rec.Message, Attrs: strings.TrimSpace(b.String())}
	c.next = (c.next + 1) % ringSize
	if c.next == 0 {
		c.full = true
	}
	c.mu.Unlock()
	return r.inner.Handle(ctx, rec)
}

func appendAttr(b *strings.Builder, a slog.Attr) {
	b.WriteString(a.Key)
	b.WriteString("=")
	b.WriteString(a.Value.String())
	b.WriteString(" ")
}

func (r *Ring) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &Ring{core: r.core, inner: r.inner.WithAttrs(attrs),
		attrs: append(append([]slog.Attr{}, r.attrs...), attrs...)}
}

func (r *Ring) WithGroup(name string) slog.Handler {
	return &Ring{core: r.core, inner: r.inner.WithGroup(name), attrs: r.attrs}
}

// Records returns up to limit newest records at or above minLevel, oldest
// first.
func (r *Ring) Records(minLevel slog.Level, limit int) []Record {
	c := r.core
	c.mu.Lock()
	defer c.mu.Unlock()
	n, start := c.next, 0
	if c.full {
		n, start = ringSize, c.next
	}
	out := make([]Record, 0, min(n, limit))
	for i := 0; i < n; i++ {
		rec := c.buf[(start+i)%ringSize]
		if rec.Time.IsZero() || levelOf(rec.Level) < minLevel {
			continue
		}
		out = append(out, rec)
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

func levelOf(s string) slog.Level {
	switch s {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
