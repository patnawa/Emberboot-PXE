// Package logging sets up Emberboot's structured JSON logging.
package logging

import (
	"io"
	"log/slog"
	"os"
)

// New returns a JSON slog.Logger at the given level, tagged with the site
// name so multi-site log aggregation can tell instances apart.
func New(w io.Writer, level slog.Level, site string) *slog.Logger {
	if w == nil {
		w = os.Stdout
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	l := slog.New(h)
	if site != "" {
		l = l.With("site", site)
	}
	return l
}

// ParseLevel maps a config string to a slog.Level, defaulting to info.
func ParseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
