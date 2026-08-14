package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/goccy/go-yaml"
)

// Parse decodes YAML strictly (unknown fields are errors, with line/column
// positions in the message), applies defaults, and validates.
func Parse(data []byte) (*Config, error) {
	var c Config
	if err := yaml.UnmarshalWithOptions(data, &c, yaml.DisallowUnknownField()); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// LoadFile reads and parses a config file.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return Parse(data)
}

// Status describes the manager's view of the config file for the dashboard.
type Status struct {
	Path       string    `json:"path"`
	LoadedAt   time.Time `json:"loaded_at"`
	// Rejected holds the error text of the most recent rejected reload, empty
	// if the file on disk is the one being served.
	Rejected   string    `json:"rejected,omitempty"`
	RejectedAt time.Time `json:"rejected_at,omitzero"`
}

// Manager owns the running configuration with Last-Known-Good semantics
// (ADR-0002): Reload only replaces the active config when the new file is
// valid; otherwise the old config keeps serving and the rejection is reported.
type Manager struct {
	path string
	log  *slog.Logger

	// writeMu serializes file writes from the management API (ADR-0004).
	writeMu sync.Mutex

	mu       sync.RWMutex
	current  *Config
	status   Status
	onChange []func(*Config)
	onReject []func(error)
}

// NewManager loads path or fails — at startup there is no known-good config
// to fall back to, so a broken file is fatal (supervision restarts us; better
// to die loudly than serve nothing silently).
func NewManager(path string, log *slog.Logger) (*Manager, error) {
	c, err := LoadFile(path)
	if err != nil {
		return nil, err
	}
	return &Manager{
		path:    path,
		log:     log,
		current: c,
		status:  Status{Path: path, LoadedAt: time.Now()},
	}, nil
}

// Current returns the active config. Never nil; callers must not mutate it.
func (m *Manager) Current() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// Status returns the config file state for the dashboard.
func (m *Manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

// OnChange registers a callback invoked with the new config after a
// successful reload. Callbacks must be fast and must not block.
func (m *Manager) OnChange(f func(*Config)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onChange = append(m.onChange, f)
}

// OnReject registers a callback invoked when a reload is rejected (used to
// fire the config-rejected alert).
func (m *Manager) OnReject(f func(error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onReject = append(m.onReject, f)
}

// Reload re-reads the file. Invalid content is rejected: the previous config
// keeps serving. Returns the rejection error, nil on success.
func (m *Manager) Reload() error {
	c, err := LoadFile(m.path)
	m.mu.Lock()
	if err != nil {
		m.status.Rejected = err.Error()
		m.status.RejectedAt = time.Now()
		rejecters := append([]func(error){}, m.onReject...)
		m.mu.Unlock()
		m.log.Error("config reload rejected; keeping last known good",
			"path", m.path, "error", err)
		for _, f := range rejecters {
			f(err)
		}
		return err
	}
	m.current = c
	m.status = Status{Path: m.path, LoadedAt: time.Now()}
	changers := append([]func(*Config){}, m.onChange...)
	m.mu.Unlock()
	m.log.Info("config reloaded", "path", m.path)
	for _, f := range changers {
		f(c)
	}
	return nil
}

// Watch hot-reloads on file changes until stop is closed. Editors write files
// in bursts (truncate+write, or write-temp+rename), so events are debounced.
func (m *Manager) Watch(stop <-chan struct{}) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("config watcher: %w", err)
	}
	// Watch the directory, not the file: rename-over-file (the usual atomic
	// save) removes the watched inode and silently ends a file watch.
	dir := filepath.Dir(m.path)
	if err := w.Add(dir); err != nil {
		w.Close()
		return fmt.Errorf("watch %s: %w", dir, err)
	}
	go func() {
		defer w.Close()
		var timer *time.Timer
		debounced := make(chan struct{}, 1)
		base := filepath.Base(m.path)
		for {
			select {
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				if filepath.Base(ev.Name) != base {
					continue
				}
				if timer != nil {
					timer.Stop()
				}
				timer = time.AfterFunc(500*time.Millisecond, func() {
					select {
					case debounced <- struct{}{}:
					default:
					}
				})
			case <-debounced:
				// Errors are already logged and reported via OnReject;
				// watching continues either way.
				_ = m.Reload()
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				m.log.Warn("config watcher error", "error", err)
			case <-stop:
				return
			}
		}
	}()
	return nil
}
