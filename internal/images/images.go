// Package images manages the Image folder: watching for ISOs, validating
// them (an Image is only Ready once fully copied and structurally sound —
// CONTEXT.md), detecting each Image's Boot Strategy, and serving file
// content out of ISOs for the HTTP layer.
package images

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"emberboot/internal/alerts"
	"emberboot/internal/config"
	"emberboot/internal/iscsisrv"
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
	// ISCSITarget is this image's virtual-CD IQN — every Ready image is
	// also reachable over the embedded iSCSI target, whatever its strategy.
	ISCSITarget string `json:"iscsi_target,omitempty"`
	// ExtraKernelArgs from config images.attach[..].kernel_args.
	ExtraKernelArgs string `json:"extra_kernel_args,omitempty"`
	// SHA256 is calculated only after the complete ISO has been read and its
	// directory/file extents have passed validation.
	SHA256 string `json:"sha256,omitempty"`

	// Detection is retained separately from the effective Strategy so a
	// hot-reloaded force can be applied or removed without reparsing the ISO.
	detectedStrategy Strategy
	detectedReason   string
	fileInfo         os.FileInfo
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

	mu                 sync.Mutex
	byName             map[string]*Image
	handles            map[string]*isoGeneration
	retained           map[string]*retainedImage
	pending            map[string]os.FileInfo
	pins               map[string]time.Time
	retainedBytes      int64
	timers             map[string]*validationTimer
	epochs             map[string]uint64
	activeDir          string
	runtimeISCSIActive bool
	warnedDir          string
	stopped            bool
	// Full-file validation is intentionally serialized. Hashing several large
	// ISOs at once only creates disk contention and can starve active boots.
	validateSlot chan struct{}
	metricsMu    sync.Mutex
	stopCh       chan struct{}
	validatorWG  sync.WaitGroup
	shutdownOnce sync.Once
	shutdownDone chan struct{}
}

type validationTimer struct {
	timer *time.Timer
	once  sync.Once
	wg    *sync.WaitGroup
}

func newValidationTimer(wg *sync.WaitGroup, delay time.Duration, fn func()) *validationTimer {
	v := &validationTimer{wg: wg}
	wg.Add(1)
	v.timer = time.AfterFunc(delay, func() {
		defer v.finish()
		fn()
	})
	return v
}

func (v *validationTimer) finish() { v.once.Do(v.wg.Done) }

func (v *validationTimer) stop() {
	if v != nil && v.timer.Stop() {
		v.finish()
	}
}

type retainedImage struct {
	image   Image
	gen     *isoGeneration
	expires time.Time
}

const (
	retainedGenerationTTL        = 25 * time.Hour
	maxRetainedGenerations       = 32
	maxRetainedBytes       int64 = 256 << 30
)

// NewManager creates the manager and runs the initial folder scan.
func NewManager(log *slog.Logger, cfg func() *config.Config, m *metrics.M, a *alerts.Notifier) *Manager {
	mgr := &Manager{
		log:                log,
		cfg:                cfg,
		metrics:            m,
		alerts:             a,
		byName:             map[string]*Image{},
		handles:            map[string]*isoGeneration{},
		retained:           map[string]*retainedImage{},
		pending:            map[string]os.FileInfo{},
		pins:               map[string]time.Time{},
		timers:             map[string]*validationTimer{},
		epochs:             map[string]uint64{},
		validateSlot:       make(chan struct{}, 1),
		stopCh:             make(chan struct{}),
		shutdownDone:       make(chan struct{}),
		runtimeISCSIActive: cfg().ISCSIActive(),
	}
	return mgr
}

// Start scans the folder, then watches it until ctx ends. The folder is
// created if missing (a fresh install must come up green).
func (m *Manager) Start(ctx context.Context) error {
	dir, err := canonicalDir(m.cfg().Images.Dir)
	if err != nil {
		return fmt.Errorf("images dir: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("images dir: %w", err)
	}
	if err := os.MkdirAll(m.cfg().Images.AnswersDir, 0o700); err != nil {
		return fmt.Errorf("answers dir: %w", err)
	}
	if err := os.Chmod(m.cfg().Images.AnswersDir, 0o700); err != nil {
		return fmt.Errorf("secure answers dir: %w", err)
	}
	m.mu.Lock()
	m.activeDir = dir
	m.stopped = false
	m.mu.Unlock()
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("images watcher: %w", err)
	}
	if err := w.Add(dir); err != nil {
		w.Close()
		return fmt.Errorf("watch %s: %w", dir, err)
	}
	// Add the watch before scanning so an ISO published during startup cannot
	// land in the scan/watch gap and remain invisible indefinitely.
	m.scan(dir)
	go m.watchLoop(ctx, w, dir)
	go m.diskJanitor(ctx, dir)
	go func() {
		<-ctx.Done()
		m.shutdown()
	}()
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
	reconcile := time.NewTicker(30 * time.Second)
	defer reconcile.Stop()
	events, watcherErrors := w.Events, w.Errors
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				events = nil
				m.log.Warn("images watcher event stream closed; periodic reconciliation remains active")
				continue
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
		case err, ok := <-watcherErrors:
			if !ok {
				watcherErrors = nil
				m.log.Warn("images watcher error stream closed; periodic reconciliation remains active")
				continue
			}
			m.log.Warn("images watcher error", "error", err)
			m.reconcile(dir)
		case <-reconcile.C:
			m.reconcile(dir)
		}
	}
}

// reconcile repairs missed/coalesced filesystem notifications without
// rehashing unchanged media. It is intentionally cheap enough to run
// periodically on large image libraries.
func (m *Manager) reconcile(dir string) {
	m.pruneRetained(time.Now())
	entries, err := os.ReadDir(dir)
	if err != nil {
		m.log.Warn("images reconciliation failed", "dir", dir, "error", err)
		return
	}
	present := make(map[string]os.FileInfo, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !isISOName(entry.Name()) {
			continue
		}
		fi, err := entry.Info()
		if err == nil {
			present[entry.Name()] = fi
		}
	}
	m.mu.Lock()
	known := make(map[string]os.FileInfo, len(m.byName))
	for name, img := range m.byName {
		known[name] = img.fileInfo
		if candidate := m.pending[name]; candidate != nil {
			known[name] = candidate
		}
	}
	m.mu.Unlock()
	for name, fi := range present {
		knownInfo, ok := known[name]
		if !ok || knownInfo == nil || !os.SameFile(knownInfo, fi) ||
			knownInfo.Size() != fi.Size() || !knownInfo.ModTime().Equal(fi.ModTime()) {
			m.scheduleValidate(dir, name, quiesce)
		}
	}
	for name := range known {
		if _, ok := present[name]; !ok {
			m.drop(name)
		}
	}
}

// scheduleValidate (re)arms the per-file quiescence timer.
func (m *Manager) scheduleValidate(dir, name string, delay time.Duration) {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return
	}
	if t, ok := m.timers[name]; ok {
		t.stop()
	}
	m.epochs[name]++
	epoch := m.epochs[name]
	m.timers[name] = newValidationTimer(&m.validatorWG, delay, func() { m.validate(dir, name, 0, epoch) })
	m.mu.Unlock()
	if fi, err := os.Stat(filepath.Join(dir, name)); err == nil {
		m.setValidating(name, fi, epoch)
	}
}

// scheduleRetry keeps the same epoch: a new filesystem event supersedes this
// retry and makes it a no-op, preventing stale validators from publishing.
func (m *Manager) scheduleRetry(dir, name string, attempt int, epoch uint64) {
	m.mu.Lock()
	if m.stopped || m.epochs[name] != epoch {
		m.mu.Unlock()
		return
	}
	if t := m.timers[name]; t != nil {
		t.stop()
	}
	m.timers[name] = newValidationTimer(&m.validatorWG, time.Duration(attempt)*2*time.Second, func() {
		m.validate(dir, name, attempt, epoch)
	})
	m.mu.Unlock()
}

func (m *Manager) current(epoch uint64, name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.stopped && m.epochs[name] == epoch
}

// validate checks size stability, then opens and inspects the ISO. attempt
// counts sharing-violation retries.
func (m *Manager) validate(dir, name string, attempt int, epoch uint64) {
	if !m.current(epoch, name) {
		return
	}
	path := filepath.Join(dir, name)
	fi, err := os.Lstat(path)
	if err != nil {
		m.dropIfCurrent(name, epoch) // vanished between event and validation
		return
	}
	if !fi.Mode().IsRegular() {
		m.setInvalid(name, fi, "image must be a regular file (symlinks and devices are refused)", epoch)
		return
	}

	if !m.setValidating(name, fi, epoch) {
		return
	}

	// Size stability: two samples 2s apart must agree, or the copy is still
	// running and we start over.
	size1 := fi.Size()
	settle := time.NewTimer(2 * time.Second)
	select {
	case <-settle.C:
	case <-m.stopCh:
		if !settle.Stop() {
			select {
			case <-settle.C:
			default:
			}
		}
		return
	}
	fi2, err := os.Stat(path)
	if err != nil {
		m.dropIfCurrent(name, epoch)
		return
	}
	age := time.Since(fi2.ModTime())
	if !sameFileStamp(fi, fi2) || fi2.Size() != size1 || age >= 0 && age < quiesce {
		m.log.Debug("image still growing, rescheduling", "file", name)
		m.scheduleValidate(dir, name, quiesce)
		return
	}
	select {
	case m.validateSlot <- struct{}{}:
	case <-m.stopCh:
		return
	}
	defer func() { <-m.validateSlot }()
	if !m.current(epoch, name) {
		return
	}

	h, err := openISO(path)
	if err != nil {
		if attempt < validateRetries {
			// Likely a sharing violation or a not-yet-flushed copy.
			m.log.Debug("image not openable yet, retrying", "file", name, "attempt", attempt, "error", err)
			m.scheduleRetry(dir, name, attempt+1, epoch)
			return
		}
		m.setInvalid(name, fi2, fmt.Sprintf("failed to open as ISO 9660: %v", err), epoch)
		return
	}
	checksum, err := h.validateContents(fi2.Size(), m.stopCh)
	if err != nil {
		h.Close()
		if err == errValidationCanceled {
			return
		}
		m.setInvalid(name, fi2, fmt.Sprintf("incomplete or structurally invalid ISO: %v", err), epoch)
		return
	}

	detectedStrategy, plan, detectedReason, err := detectSafely(h, fi2.Size())
	if err != nil {
		h.Close()
		m.setInvalid(name, fi2, err.Error(), epoch)
		return
	}

	// Reject a file which changed during structural validation/checksumming.
	openedInfo, statErr := h.f.Stat()
	pathInfo, pathErr := os.Stat(path)
	if statErr != nil || pathErr != nil || !sameFileVersion(fi2, openedInfo, pathInfo) {
		h.Close()
		m.log.Debug("image changed during validation, rescheduling", "file", name)
		m.scheduleValidate(dir, name, quiesce)
		return
	}

	m.mu.Lock()
	if m.stopped || m.epochs[name] != epoch {
		m.mu.Unlock()
		h.Close()
		return
	}
	old := m.handles[name]
	oldImage := m.byName[name]
	m.handles[name] = newISOGeneration(h, openedInfo)
	img := m.applySettings(&Image{
		FileName:         name,
		SizeBytes:        fi2.Size(),
		ModTime:          fi2.ModTime(),
		State:            StateReady,
		Reason:           detectedReason,
		Strategy:         detectedStrategy,
		Plan:             plan,
		SHA256:           checksum,
		detectedStrategy: detectedStrategy,
		detectedReason:   detectedReason,
		fileInfo:         openedInfo,
	})
	m.byName[name] = img
	delete(m.pending, name)
	if old != nil && oldImage != nil && oldImage.SHA256 != "" && oldImage.SHA256 != checksum {
		if m.retainLocked(*oldImage, old) {
			old = nil
		}
	}
	effectiveStrategy := img.Strategy
	m.mu.Unlock()
	if old != nil {
		old.retire()
	}
	m.refreshGauges()
	m.log.Info("image ready", "file", name, "strategy", effectiveStrategy, "family", plan.Family, "size", fi2.Size(), "sha256", checksum)
}

func detectSafely(h *isoHandle, size int64) (strategy Strategy, plan BootPlan, reason string, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			strategy = ""
			plan = BootPlan{}
			reason = ""
			err = fmt.Errorf("malformed ISO metadata during detection: %v", recovered)
		}
	}()
	return detect(h, size)
}

func (m *Manager) setValidating(name string, fi os.FileInfo, epoch uint64) bool {
	m.mu.Lock()
	if m.stopped || m.epochs[name] != epoch {
		m.mu.Unlock()
		return false
	}
	var unsafeOld *isoGeneration
	if existing := m.byName[name]; existing != nil && existing.State == StateReady && m.handles[name] != nil &&
		existing.fileInfo != nil && !os.SameFile(existing.fileInfo, fi) {
		// Last-known-good media keeps serving while a same-name replacement is
		// on a different inode and is validated. In-place writes mutate the
		// already-open descriptor, so those must be withdrawn immediately.
		m.pending[name] = fi
		m.mu.Unlock()
		return true
	}
	if existing := m.byName[name]; existing != nil && existing.State == StateReady {
		unsafeOld = m.handles[name]
		delete(m.handles, name)
	}
	m.byName[name] = m.applySettings(&Image{
		FileName:  name,
		SizeBytes: fi.Size(),
		ModTime:   fi.ModTime(),
		State:     StateValidating,
		Reason:    "checking copy completeness and ISO structure",
		fileInfo:  fi,
	})
	m.pending[name] = fi
	m.mu.Unlock()
	if unsafeOld != nil {
		unsafeOld.retire()
	}
	m.refreshGauges()
	return true
}

func (m *Manager) setInvalid(name string, fi os.FileInfo, reason string, epoch uint64) {
	m.mu.Lock()
	if m.stopped || m.epochs[name] != epoch {
		m.mu.Unlock()
		return
	}
	old := m.handles[name]
	oldImage := m.byName[name]
	delete(m.handles, name)
	m.byName[name] = m.applySettings(&Image{
		FileName:  name,
		SizeBytes: fi.Size(),
		ModTime:   fi.ModTime(),
		State:     StateInvalid,
		Reason:    reason,
		fileInfo:  fi,
	})
	delete(m.pending, name)
	if old != nil && oldImage != nil && oldImage.State == StateReady && oldImage.SHA256 != "" {
		if m.retainLocked(*oldImage, old) {
			old = nil
		}
	}
	m.mu.Unlock()
	if old != nil {
		old.retire()
	}
	m.refreshGauges()
	m.log.Warn("image invalid", "file", name, "reason", reason)
	m.alerts.Fire(alerts.ImageInvalid, name, "Image failed validation: "+name,
		map[string]string{"file": name, "reason": reason})
}

func (m *Manager) drop(name string) { m.dropMatching(name, 0, false) }

func (m *Manager) dropIfCurrent(name string, epoch uint64) {
	m.dropMatching(name, epoch, true)
}

func (m *Manager) dropMatching(name string, epoch uint64, requireEpoch bool) {
	m.mu.Lock()
	if requireEpoch && (m.stopped || m.epochs[name] != epoch) {
		m.mu.Unlock()
		return
	}
	m.epochs[name]++ // invalidate timers which have already begun executing
	old := m.handles[name]
	oldImage := m.byName[name]
	delete(m.handles, name)
	if t := m.timers[name]; t != nil {
		t.stop()
		delete(m.timers, name)
	}
	_, existed := m.byName[name]
	delete(m.byName, name)
	delete(m.pending, name)
	if old != nil && oldImage != nil && oldImage.State == StateReady && oldImage.SHA256 != "" {
		if m.retainLocked(*oldImage, old) {
			old = nil
		}
	}
	m.mu.Unlock()
	if old != nil {
		old.retire()
	}
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
	img.ISCSITarget = ""
	if m.runtimeISCSIActive && img.SHA256 != "" {
		img.ISCSITarget = iscsisrv.IQNPrefix + ":" + TargetVersionSuffix(img.FileName, img.SHA256)
	}
	if img.State == StateReady && img.detectedStrategy != "" {
		img.Strategy = img.detectedStrategy
		img.Reason = img.detectedReason
		if forced := s.Strategy; forced != "" && Strategy(forced) != img.detectedStrategy {
			img.Strategy = Strategy(forced)
			img.Reason = fmt.Sprintf("strategy forced to %s by config (detector said %s: %s)", forced, img.detectedStrategy, img.detectedReason)
		}
	}
	return img
}

// OnConfigChange re-applies attach settings, including adding, changing, or
// removing a forced strategy. The detector result retained at validation is
// the source of truth, so removing a force reliably restores auto-detection.
// The watched directory is deliberately pinned for this process lifetime;
// changing it requires a restart rather than creating a split-brain registry.
func (m *Manager) OnConfigChange() {
	configuredDir, err := canonicalDir(m.cfg().Images.Dir)
	m.mu.Lock()
	for _, img := range m.byName {
		m.applySettings(img)
	}
	activeDir := m.activeDir
	warnDir := err != nil || (activeDir != "" && !sameDir(activeDir, configuredDir))
	shouldWarn := warnDir && configuredDir != m.warnedDir
	if shouldWarn {
		m.warnedDir = configuredDir
	}
	m.mu.Unlock()
	if shouldWarn {
		m.log.Warn("images.dir change requires restart; continuing to use active directory",
			"active_dir", activeDir, "configured_dir", configuredDir, "error", err)
	}
	m.refreshGauges()
}

func retainedKey(name, digest string) string { return name + "\x00" + digest }

// retainLocked keeps an old validated generation only when a boot grant has
// pinned it, and within explicit disk/descriptor budgets. Caller holds mu.
func (m *Manager) retainLocked(img Image, gen *isoGeneration) bool {
	if gen == nil || img.SHA256 == "" {
		return false
	}
	key := retainedKey(img.FileName, img.SHA256)
	expires, pinned := m.pins[key]
	if !pinned || !expires.After(time.Now()) || img.SizeBytes > maxRetainedBytes {
		delete(m.pins, key)
		return false
	}
	if previous := m.retained[key]; previous != nil {
		delete(m.retained, key)
		m.retainedBytes -= previous.image.SizeBytes
		if previous.gen != gen {
			previous.gen.retire()
		}
	}
	for len(m.retained) >= maxRetainedGenerations || m.retainedBytes+img.SizeBytes > maxRetainedBytes {
		var oldestKey string
		var oldest *retainedImage
		for candidateKey, candidate := range m.retained {
			if oldest == nil || candidate.expires.Before(oldest.expires) {
				oldestKey, oldest = candidateKey, candidate
			}
		}
		if oldest == nil {
			return false
		}
		delete(m.retained, oldestKey)
		m.retainedBytes -= oldest.image.SizeBytes
		oldest.gen.retire()
		m.log.Warn("revoked oldest retained image generation to enforce retention budget",
			"file", oldest.image.FileName, "sha256", oldest.image.SHA256)
	}
	deadline := expires
	if maximum := time.Now().Add(retainedGenerationTTL); deadline.After(maximum) {
		deadline = maximum
	}
	m.retained[key] = &retainedImage{image: img, gen: gen, expires: deadline}
	m.retainedBytes += img.SizeBytes
	return true
}

// PinVersion records that a signed grant may need this generation until
// expires. No descriptor is retained unless the file is later replaced.
func (m *Manager) PinVersion(name, digest string, expires time.Time) bool {
	if digest == "" || !expires.After(time.Now()) {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	img := m.byName[name]
	gen := m.handles[name]
	if img == nil || gen == nil || img.State != StateReady || img.Disabled || img.SHA256 != digest ||
		!generationStable(gen) {
		return false
	}
	maxExpiry := time.Now().Add(retainedGenerationTTL)
	if expires.After(maxExpiry) {
		expires = maxExpiry
	}
	key := retainedKey(name, digest)
	if previous := m.pins[key]; previous.Before(expires) {
		m.pins[key] = expires
	}
	return true
}

func (m *Manager) pruneRetained(now time.Time) {
	var expired []*isoGeneration
	m.mu.Lock()
	for key, version := range m.retained {
		if !version.expires.After(now) {
			expired = append(expired, version.gen)
			m.retainedBytes -= version.image.SizeBytes
			delete(m.retained, key)
		}
	}
	for key, expires := range m.pins {
		if !expires.After(now) {
			delete(m.pins, key)
		}
	}
	m.mu.Unlock()
	for _, gen := range expired {
		gen.retire()
	}
}

// versionLocked resolves a current or grace-retained generation. Caller
// holds mu; current policy may disable even a retained generation.
func (m *Manager) versionLocked(name, digest string) (Image, *isoGeneration, bool, bool) {
	settings := m.settings(name)
	if img := m.byName[name]; img != nil && img.State == StateReady && img.SHA256 == digest &&
		!settings.Disabled {
		if gen := m.handles[name]; gen != nil && generationStable(gen) {
			snapshot := *img
			snapshot.Disabled = settings.Disabled
			snapshot.AnswerFile = settings.AnswerFile
			return snapshot, gen, true, true
		}
	}
	if version := m.retained[retainedKey(name, digest)]; version != nil &&
		version.expires.After(time.Now()) && !settings.Disabled && generationStable(version.gen) {
		snapshot := version.image
		snapshot.Disabled = settings.Disabled
		snapshot.AnswerFile = settings.AnswerFile
		return snapshot, version.gen, false, true
	}
	return Image{}, nil, false, false
}

func generationStable(gen *isoGeneration) bool {
	if gen == nil || gen.h == nil || gen.h.f == nil || gen.info == nil {
		return false
	}
	fi, err := gen.h.f.Stat()
	return err == nil && sameFileStamp(gen.info, fi) && os.SameFile(gen.info, fi)
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

// ActiveDir is the canonical image directory watched by this process. It may
// differ from a newly saved restart-required setting.
func (m *Manager) ActiveDir() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeDir
}

// ImageForTarget resolves a generated iSCSI suffix without exposing disabled
// or non-Ready media. It supports per-client authorization in the target.
func (m *Manager) ImageForTarget(suffix string) (Image, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, img := range m.byName {
		if img.State == StateReady && !img.Disabled && generationStable(m.handles[img.FileName]) &&
			TargetVersionSuffix(img.FileName, img.SHA256) == suffix {
			return *img, true
		}
	}
	for _, version := range m.retained {
		if version.expires.After(time.Now()) && !m.settings(version.image.FileName).Disabled &&
			generationStable(version.gen) &&
			TargetVersionSuffix(version.image.FileName, version.image.SHA256) == suffix {
			return version.image, true
		}
	}
	return Image{}, false
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

// GetVersion returns metadata only when it still matches the digest embedded
// in a boot grant. This prevents a same-name replacement from silently
// changing the boot plan halfway through a multi-request install.
func (m *Manager) GetVersion(name, digest string) (Image, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	img, _, _, ok := m.versionLocked(name, digest)
	return img, ok
}

// OpenRaw opens the ISO file itself for HTTP serving (one handle per
// request; http.ServeContent needs a ReadSeeker and closes via caller).
func (m *Manager) OpenRaw(name string) (*os.File, error) {
	if !isISOName(name) {
		return nil, fmt.Errorf("not an image name")
	}
	m.mu.Lock()
	img, ok := m.byName[name]
	gen := m.handles[name]
	dir := m.activeDir
	if !ok || gen == nil || img.State != StateReady || img.Disabled || !gen.acquire() {
		m.mu.Unlock()
		return nil, fmt.Errorf("image %s is not enabled and Ready", name)
	}
	m.mu.Unlock()
	defer gen.release()

	f, err := os.Open(filepath.Join(dir, filepath.Base(name)))
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil || !os.SameFile(gen.info, fi) || !sameFileStamp(gen.info, fi) {
		f.Close()
		return nil, fmt.Errorf("image %s changed since validation", name)
	}
	return f, nil
}

// OpenRawVersion atomically binds the returned descriptor and metadata to the
// digest carried by a boot grant. Replacement races fail closed rather than
// combining an old size/plan with bytes from a new ISO.
func (m *Manager) OpenRawVersion(name, digest string) (io.ReadSeekCloser, Image, error) {
	if !isISOName(name) || digest == "" {
		return nil, Image{}, fmt.Errorf("not an image version")
	}
	m.mu.Lock()
	img, gen, current, ok := m.versionLocked(name, digest)
	dir := m.activeDir
	if !ok || gen == nil || !gen.acquire() {
		m.mu.Unlock()
		return nil, Image{}, fmt.Errorf("image %s version is not enabled and Ready", name)
	}
	snapshot := img
	m.mu.Unlock()

	if current {
		f, err := os.Open(filepath.Join(dir, filepath.Base(name)))
		if err == nil {
			fi, statErr := f.Stat()
			if statErr == nil && os.SameFile(gen.info, fi) && sameFileStamp(gen.info, fi) {
				return &leasedFile{File: f, release: gen.release}, snapshot, nil
			}
			f.Close()
		}
	}
	// A retained/unlinked generation cannot be reopened by path. A SectionReader
	// uses the validated shared descriptor safely (ReaderAt is concurrency-safe).
	return &leasedReadSeeker{
		ReadSeeker: io.NewSectionReader(gen.h.f, 0, snapshot.SizeBytes), release: gen.release,
	}, snapshot, nil
}

// OpenInside returns a leased reader over one file inside an enabled, Ready
// ISO. The caller must close it so a retired generation can be reclaimed.
func (m *Manager) OpenInside(name, pathInISO string) (io.ReadSeekCloser, int64, time.Time, error) {
	m.mu.Lock()
	img, okImg := m.byName[name]
	gen, okH := m.handles[name]
	if !okImg || !okH || img.State != StateReady || img.Disabled || !gen.acquire() {
		m.mu.Unlock()
		return nil, 0, time.Time{}, fmt.Errorf("image %s is not enabled and Ready", name)
	}
	modTime := img.ModTime
	m.mu.Unlock()
	rs, size, err := gen.h.open(pathInISO)
	if err != nil {
		gen.release()
		return nil, 0, time.Time{}, err
	}
	return &leasedReadSeeker{ReadSeeker: rs, release: gen.release}, size, modTime, nil
}

// OpenInsideVersion is OpenInside with a generation digest check and a
// metadata snapshot from the same critical section.
func (m *Manager) OpenInsideVersion(name, digest, pathInISO string) (io.ReadSeekCloser, int64, time.Time, Image, error) {
	m.mu.Lock()
	img, gen, _, ok := m.versionLocked(name, digest)
	if !ok || gen == nil || !gen.acquire() {
		m.mu.Unlock()
		return nil, 0, time.Time{}, Image{}, fmt.Errorf("image %s version is not enabled and Ready", name)
	}
	snapshot := img
	m.mu.Unlock()
	rs, size, err := gen.h.open(pathInISO)
	if err != nil {
		gen.release()
		return nil, 0, time.Time{}, Image{}, err
	}
	return &leasedReadSeeker{ReadSeeker: rs, release: gen.release}, size, snapshot.ModTime, snapshot, nil
}

// refreshGauges recomputes the ready/invalid gauges.
func (m *Manager) refreshGauges() {
	m.metricsMu.Lock()
	defer m.metricsMu.Unlock()
	var ready, invalid float64
	m.mu.Lock()
	for _, img := range m.byName {
		switch img.State {
		case StateReady:
			if !img.Disabled {
				ready++
			}
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
	if filepath.Base(name) != name || len(name) == 0 || len(name) > 240 ||
		name != strings.TrimSpace(name) || !strings.EqualFold(filepath.Ext(name), ".iso") {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	stem := strings.ToLower(strings.TrimSuffix(name, filepath.Ext(name)))
	// Supported atomic publication workflow: copy to <name>.iso.partial and
	// rename to <name>.iso. Also refuse common temp-before-extension spellings
	// so a half-copy cannot become bootable accidentally.
	return !strings.HasSuffix(stem, ".partial") && !strings.HasSuffix(stem, ".part")
}

func canonicalDir(dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("path is empty")
	}
	return filepath.Abs(filepath.Clean(dir))
}

func sameDir(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

func sameFileStamp(a, b os.FileInfo) bool {
	return a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func sameFileVersion(want, opened, path os.FileInfo) bool {
	return sameFileStamp(want, opened) && sameFileStamp(want, path) &&
		os.SameFile(want, opened) && os.SameFile(want, path)
}

func (m *Manager) shutdown() {
	m.shutdownOnce.Do(func() {
		m.mu.Lock()
		m.stopped = true
		close(m.stopCh)
		for name, timer := range m.timers {
			timer.stop()
			m.epochs[name]++
		}
		handles := m.handles
		m.handles = map[string]*isoGeneration{}
		retained := m.retained
		m.retained = map[string]*retainedImage{}
		m.mu.Unlock()
		m.validatorWG.Wait()
		for _, gen := range handles {
			gen.retire()
		}
		for _, version := range retained {
			version.gen.retire()
		}
		close(m.shutdownDone)
	})
	<-m.shutdownDone
}

// Close cancels and joins validators before releasing image generations.
func (m *Manager) Close() { m.shutdown() }

// DiskFreeGB reports free space on the volume holding dir (diagnostics).
func DiskFreeGB(dir string) (float64, error) { return diskFreeGB(dir) }

// --- iSCSI target provider (iscsisrv.Provider) ---

// OpenTarget resolves an IQN suffix to a Ready image's raw ISO. Each session
// gets its own file handle so ISO removal never corrupts other sessions.
func (m *Manager) OpenTarget(suffix string) (io.ReaderAt, int64, func(), error) {
	m.mu.Lock()
	var sizeBytes int64
	var gen *isoGeneration
	for name, img := range m.byName {
		candidate := m.handles[name]
		if img.State == StateReady && !img.Disabled && TargetVersionSuffix(img.FileName, img.SHA256) == suffix &&
			candidate != nil && generationStable(candidate) && candidate.acquire() {
			sizeBytes, gen = img.SizeBytes, candidate
			break
		}
	}
	if gen == nil {
		for _, version := range m.retained {
			if version.expires.After(time.Now()) && !m.settings(version.image.FileName).Disabled &&
				TargetVersionSuffix(version.image.FileName, version.image.SHA256) == suffix &&
				generationStable(version.gen) && version.gen.acquire() {
				sizeBytes, gen = version.image.SizeBytes, version.gen
				break
			}
		}
	}
	m.mu.Unlock()
	if gen == nil {
		return nil, 0, nil, fmt.Errorf("no ready image for target %q", suffix)
	}
	return gen.h.f, sizeBytes, gen.release, nil
}

// TargetSuffixes lists discovery-offerable targets (Ready, not disabled).
func (m *Manager) TargetSuffixes() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, img := range m.byName {
		if img.State == StateReady && !img.Disabled {
			out = append(out, TargetVersionSuffix(img.FileName, img.SHA256))
		}
	}
	sort.Strings(out)
	return out
}

// TargetSuffix exposes the stable IQN suffix for one image. The digest is
// derived from the exact file name, eliminating collisions such as
// "foo_bar.iso" and "foo-bar.iso" while retaining a readable prefix.
func TargetSuffix(fileName string) string {
	base := strings.Trim(iscsisrv.SanitizeSuffix(fileName), "-.")
	if base == "" {
		base = "image"
	}
	sum := sha256.Sum256([]byte(fileName))
	digest := hex.EncodeToString(sum[:])
	const maxIQNBytes = 223
	maxBase := maxIQNBytes - len(iscsisrv.IQNPrefix) - 1 - 1 - len(digest)
	if len(base) > maxBase {
		base = strings.TrimRight(base[:maxBase], "-.")
	}
	return base + "-" + digest
}

// TargetVersionSuffix binds an iSCSI target to both the exact filename and
// validated content. A script issued for generation A can never attach to a
// same-name generation B after replacement.
func TargetVersionSuffix(fileName, contentDigest string) string {
	if len(contentDigest) != sha256.Size*2 {
		return TargetSuffix(fileName)
	}
	base := strings.Trim(iscsisrv.SanitizeSuffix(fileName), "-.")
	if base == "" {
		base = "image"
	}
	nameSum := sha256.Sum256([]byte(fileName))
	nameDigest := hex.EncodeToString(nameSum[:])
	const maxIQNBytes = 223
	maxBase := maxIQNBytes - len(iscsisrv.IQNPrefix) - 1 - 1 - len(nameDigest) - 1 - len(contentDigest)
	if maxBase < 1 {
		maxBase = 1
	}
	if len(base) > maxBase {
		base = strings.TrimRight(base[:maxBase], "-.")
		if base == "" {
			base = "i"
		}
	}
	return base + "-" + nameDigest + "-" + strings.ToLower(contentDigest)
}
