// Package images manages the Image folder: watching for ISOs, validating
// them (an Image is only Ready once fully copied and structurally sound —
// CONTEXT.md), detecting each Image's Boot Strategy, and serving file
// content out of ISOs for the HTTP layer.
package images

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"emberboot/internal/alerts"
	"emberboot/internal/config"
	"emberboot/internal/metrics"
)

// State of an Image in the registry.
type State string

const (
	StateValidating State = "validating"
	StateReady      State = "ready"
	StateInvalid    State = "invalid"
)

// Image is one ISO in the folder plus everything validation learned about it.
type Image struct {
	FileName    string    `json:"file_name"`
	DisplayName string    `json:"display_name"`
	SizeBytes   int64     `json:"size_bytes"`
	ModTime     time.Time `json:"mod_time"`
	State       State     `json:"state"`
	// Reason explains the state and strategy choice, dashboard-visible.
	Reason   string   `json:"reason"`
	Strategy Strategy `json:"strategy,omitempty"`
	Plan     BootPlan `json:"plan"`
	// Disabled mirrors config images.attach[..].disabled.
	Disabled bool `json:"disabled"`
	// AnswerFile from config images.attach[..].answer_file ("" = none).
	AnswerFile string `json:"answer_file,omitempty"`
	// ExtraKernelArgs from config images.attach[..].kernel_args.
	ExtraKernelArgs string `json:"extra_kernel_args,omitempty"`
}

// quiesce is how long a file must stop changing before validation is tried —
// the "is the admin's copy finished yet" debounce.
const quiesce = 3 * time.Second

// validateRetries covers Windows sharing violations while a copy tool still
// holds the file: retry with backoff before declaring the ISO invalid.
const validateRetries = 5

// Manager owns the Image registry.
type Manager struct {
	log     *slog.Logger
	cfg     func() *config.Config
	metrics *metrics.M
	alerts  *alerts.Notifier

	mu      sync.Mutex
	byName  map[string]*Image
	handles map[string]*isoHandle
	timers  map[string]*time.Timer
}

// NewManager creates the manager and runs the initial folder scan.
func NewManager(log *slog.Logger, cfg func() *config.Config, m *metrics.M, a *alerts.Notifier) *Manager {
	mgr := &Manager{
		log:     log,
		cfg:     cfg,
		metrics: m,
		alerts:  a,
		byName:  map[string]*Image{},
		handles: map[string]*isoHandle{},
		timers:  map[string]*time.Timer{},
	}
	return mgr
}

// Start scans the folder, then watches it until ctx ends. The folder is
// created if missing (a fresh install must come up green).
func (m *Manager) Start(ctx context.Context) error {
	dir := m.cfg().Images.Dir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("images dir: %w", err)
	}
	if err := os.MkdirAll(m.cfg().Images.AnswersDir, 0o755); err != nil {
		return fmt.Errorf("answers dir: %w", err)
	}
	m.scan(dir)

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("images watcher: %w", err)
	}
	if err := w.Add(dir); err != nil {
		w.Close()
		return fmt.Errorf("watch %s: %w", dir, err)
	}
	go m.watchLoop(ctx, w, dir)
	go m.diskJanitor(ctx, dir)
	return nil
}

// scan enqueues validation for every ISO already present.
func (m *Manager) scan(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		m.log.Error("images scan failed", "dir", dir, "error", err)
		return
	}
	for _, e := range entries {
		if e.IsDir() || !isISOName(e.Name()) {
			continue
		}
		m.scheduleValidate(dir, e.Name(), 0)
	}
}

func (m *Manager) watchLoop(ctx context.Context, w *fsnotify.Watcher, dir string) {
	defer w.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			name := filepath.Base(ev.Name)
			if !isISOName(name) {
				continue
			}
			switch {
			case ev.Op&(fsnotify.Remove|fsnotify.Rename) != 0:
				m.drop(name)
			case ev.Op&(fsnotify.Create|fsnotify.Write) != 0:
				m.scheduleValidate(dir, name, quiesce)
			}
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			m.log.Warn("images watcher error", "error", err)
		}
	}
}

// scheduleValidate (re)arms the per-file quiescence timer.
func (m *Manager) scheduleValidate(dir, name string, delay time.Duration) {
	m.mu.Lock()
	if t, ok := m.timers[name]; ok {
		t.Stop()
	}
	m.timers[name] = time.AfterFunc(delay, func() { m.validate(dir, name, 0) })
	m.mu.Unlock()
}

// validate checks size stability, then opens and inspects the ISO. attempt
// counts sharing-violation retries.
func (m *Manager) validate(dir, name string, attempt int) {
	path := filepath.Join(dir, name)
	fi, err := os.Stat(path)
	if err != nil {
		m.drop(name) // vanished between event and validation
		return
	}

	m.setValidating(name, fi)

	// Size stability: two samples 2s apart must agree, or the copy is still
	// running and we start over.
	size1 := fi.Size()
	time.Sleep(2 * time.Second)
	fi2, err := os.Stat(path)
	if err != nil {
		m.drop(name)
		return
	}
	if fi2.Size() != size1 {
		m.log.Debug("image still growing, rescheduling", "file", name)
		m.scheduleValidate(dir, name, quiesce)
		return
	}

	h, err := openISO(path)
	if err != nil {
		if attempt < validateRetries {
			// Likely a sharing violation or a not-yet-flushed copy.
			m.log.Debug("image not openable yet, retrying", "file", name, "attempt", attempt, "error", err)
			m.mu.Lock()
			m.timers[name] = time.AfterFunc(time.Duration(attempt+1)*2*time.Second, func() {
				m.validate(dir, name, attempt+1)
			})
			m.mu.Unlock()
			return
		}
		m.setInvalid(name, fi2, fmt.Sprintf("failed to open as ISO 9660: %v", err))
		return
	}

	strategy, plan, reason, err := detect(h, fi2.Size())
	if err != nil {
		h.Close()
		m.setInvalid(name, fi2, err.Error())
		return
	}

	// Forced strategy from config wins over detection.
	if forced := m.settings(name).Strategy; forced != "" && Strategy(forced) != strategy {
		reason = fmt.Sprintf("strategy forced to %s by config (detector said %s: %s)", forced, strategy, reason)
		strategy = Strategy(forced)
	}

	m.mu.Lock()
	if old := m.handles[name]; old != nil {
		old.Close()
	}
	m.handles[name] = h
	img := m.applySettings(&Image{
		FileName:  name,
		SizeBytes: fi2.Size(),
		ModTime:   fi2.ModTime(),
		State:     StateReady,
		Reason:    reason,
		Strategy:  strategy,
		Plan:      plan,
	})
	m.byName[name] = img
	m.mu.Unlock()
	m.refreshGauges()
	m.log.Info("image ready", "file", name, "strategy", strategy, "family", plan.Family, "size", fi2.Size())
}

func (m *Manager) setValidating(name string, fi os.FileInfo) {
	m.mu.Lock()
	m.byName[name] = m.applySettings(&Image{
		FileName:  name,
		SizeBytes: fi.Size(),
		ModTime:   fi.ModTime(),
		State:     StateValidating,
		Reason:    "checking copy completeness and ISO structure",
	})
	m.mu.Unlock()
	m.refreshGauges()
}

func (m *Manager) setInvalid(name string, fi os.FileInfo, reason string) {
	m.mu.Lock()
	m.byName[name] = m.applySettings(&Image{
		FileName:  name,
		SizeBytes: fi.Size(),
		ModTime:   fi.ModTime(),
		State:     StateInvalid,
		Reason:    reason,
	})
	m.mu.Unlock()
	m.refreshGauges()
	m.log.Warn("image invalid", "file", name, "reason", reason)
	m.alerts.Fire(alerts.ImageInvalid, name, "Image failed validation: "+name,
		map[string]string{"file": name, "reason": reason})
}

func (m *Manager) drop(name string) {
	m.mu.Lock()
	if h := m.handles[name]; h != nil {
		h.Close()
		delete(m.handles, name)
	}
	if t := m.timers[name]; t != nil {
		t.Stop()
		delete(m.timers, name)
	}
	_, existed := m.byName[name]
	delete(m.byName, name)
	m.mu.Unlock()
	if existed {
		m.refreshGauges()
		m.log.Info("image removed", "file", name)
	}
}

// settings returns per-image config (zero value if none).
func (m *Manager) settings(name string) config.ImageSettings {
	return m.cfg().Images.Attach[name]
}

// applySettings folds config attach settings into an Image. Caller holds mu
// or owns img exclusively.
func (m *Manager) applySettings(img *Image) *Image {
	s := m.settings(img.FileName)
	img.DisplayName = s.DisplayName
	if img.DisplayName == "" {
		img.DisplayName = friendlyName(img.FileName)
	}
	img.Disabled = s.Disabled
	img.AnswerFile = s.AnswerFile
	img.ExtraKernelArgs = s.KernelArgs
	return img
}

// OnConfigChange re-applies attach settings (display names, disabled flags,
// forced strategies need revalidation only if strategy changed — keep it
// simple: reapply cheap settings in place).
func (m *Manager) OnConfigChange() {
	m.mu.Lock()
	for _, img := range m.byName {
		m.applySettings(img)
	}
	m.mu.Unlock()
	m.refreshGauges()
}

// List returns Images sorted by file name (snapshot copies).
func (m *Manager) List() []Image {
	m.mu.Lock()
	out := make([]Image, 0, len(m.byName))
	for _, img := range m.byName {
		out = append(out, *img)
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].FileName < out[j].FileName })
	return out
}

// Get returns a Ready-or-not Image by file name.
func (m *Manager) Get(name string) (Image, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	img, ok := m.byName[name]
	if !ok {
		return Image{}, false
	}
	return *img, true
}

// OpenRaw opens the ISO file itself for HTTP serving (one handle per
// request; http.ServeContent needs a ReadSeeker and closes via caller).
func (m *Manager) OpenRaw(name string) (*os.File, error) {
	if !isISOName(name) {
		return nil, fmt.Errorf("not an image name")
	}
	return os.Open(filepath.Join(m.cfg().Images.Dir, filepath.Base(name)))
}

// OpenInside returns a ReadSeeker over one file inside a Ready ISO.
func (m *Manager) OpenInside(name, pathInISO string) (io.ReadSeeker, int64, time.Time, error) {
	m.mu.Lock()
	img, okImg := m.byName[name]
	h, okH := m.handles[name]
	m.mu.Unlock()
	if !okImg || !okH || img.State != StateReady {
		return nil, 0, time.Time{}, fmt.Errorf("image %s is not Ready", name)
	}
	rs, size, err := h.open(pathInISO)
	if err != nil {
		return nil, 0, time.Time{}, err
	}
	return rs, size, img.ModTime, nil
}

// refreshGauges recomputes the ready/invalid gauges.
func (m *Manager) refreshGauges() {
	var ready, invalid float64
	m.mu.Lock()
	for _, img := range m.byName {
		switch img.State {
		case StateReady:
			ready++
		case StateInvalid:
			invalid++
		}
	}
	m.mu.Unlock()
	m.metrics.ImagesReady.Set(ready)
	m.metrics.ImagesInvalid.Set(invalid)
}

// diskJanitor checks free space on the image volume every 5 minutes.
func (m *Manager) diskJanitor(ctx context.Context, dir string) {
	tick := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			freeGB, err := diskFreeGB(dir)
			if err != nil {
				m.log.Warn("disk space check failed", "error", err)
				continue
			}
			if min := m.cfg().Images.MinFreeGB; freeGB < float64(min) {
				m.alerts.Fire(alerts.DiskLow, dir,
					fmt.Sprintf("image volume has %.1f GB free (threshold %d GB)", freeGB, min),
					map[string]string{"dir": dir})
			}
		}
	}
}

func isISOName(name string) bool {
	return strings.EqualFold(filepath.Ext(name), ".iso")
}

// DiskFreeGB reports free space on the volume holding dir (diagnostics).
func DiskFreeGB(dir string) (float64, error) { return diskFreeGB(dir) }
