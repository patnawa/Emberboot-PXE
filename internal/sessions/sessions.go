// Package sessions tracks Boot Sessions — one Client's journey from first
// DHCP request to a fully loaded Image — in an embedded SQLite database.
//
// The database is a disposable cache (ADR-0002): deleting it loses history
// but never affects boot service. Every write path here is best-effort; a
// broken database degrades observability, not booting.
package sessions

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

var errSessionNotPersisted = errors.New("session row is not persisted")

// Result values for finished sessions.
const (
	// ResultHandoff means Emberboot delivered the decisive payload or
	// established the requested virtual media session. It deliberately does
	// not claim that the operating system booted or installed successfully.
	ResultHandoff = "handoff"
	// ResultCompleted is kept as a source-compatible alias for integrations
	// compiled against v0.5; persisted "completed" rows are migrated below.
	ResultCompleted = ResultHandoff
	ResultFailed    = "failed"
	ResultStalled   = "stalled"
)

// sessionGap: a new event from a MAC more than this long after its last
// activity starts a new Boot Session rather than extending the old one.
const sessionGap = 5 * time.Minute

// stallAfter: an unfinished session with no activity for this long is marked
// stalled (the "stuck at 43%" case).
const stallAfter = 15 * time.Minute

// identityTTL bounds how long an observed IP may stand in for a MAC. DHCP
// addresses are reusable; keeping this mapping forever could apply a prior
// client's targeting policy to a different machine.
const identityTTL = 5 * time.Minute

const (
	defaultWriteQueueSize = 4096
	maxActiveSessions     = 10000
	maxIPIdentities       = 10000
	operationTouch        = "touch"
	operationMeta         = "meta"
	operationFinish       = "finish"
)

type writeKind uint8

const (
	writeTouch writeKind = iota
	writeMeta
	writeFinish
)

// writeOperation is deliberately value-only: callers can enqueue it and
// immediately return to DHCP/TFTP/HTTP service without retaining request
// objects or waiting for SQLite.
type writeOperation struct {
	kind writeKind

	id         int64
	replacedID int64
	newSession bool
	mac        string
	ip         string
	stage      string
	detail     string
	startedAt  int64
	at         int64

	firmware string
	image    string
	strategy string
	result   string
	sequence uint64
}

// Event is one step in a session timeline.
type Event struct {
	At     time.Time `json:"at"`
	Stage  string    `json:"stage"`  // dhcp|tftp|script|payload|answer|handoff|fail
	Detail string    `json:"detail"` // human-readable, e.g. "served snponly.efi"
}

// Session is a Boot Session row plus, when loaded fully, its timeline.
type Session struct {
	ID        int64     `json:"id"`
	MAC       string    `json:"mac"`
	IP        string    `json:"ip"`
	Firmware  string    `json:"firmware"` // bios|uefi-x64|uefi-ia32|uefi-arm64|http
	Image     string    `json:"image"`
	Strategy  string    `json:"strategy"`
	StartedAt time.Time `json:"started_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Result    string    `json:"result"` // "" while in progress
	// Stages lists the distinct stages seen (list queries only) so the
	// dashboard can draw the boot pipeline without loading full timelines.
	Stages []string `json:"stages,omitempty"`
	Events []Event  `json:"events,omitempty"`
}

// SpikeConfig mirrors config.FailureSpike, provided per-check so hot reloads
// apply.
type SpikeConfig struct {
	Window      time.Duration
	ThresholdPc int
	MinSessions int
}

// Store owns the SQLite database plus an in-memory index of active sessions.
type Store struct {
	log *slog.Logger
	db  *sql.DB

	mu                 sync.Mutex
	active             map[string]int64 // mac -> session id
	lastAt             map[string]time.Time
	ipToMAC            map[string]ipIdentity // recent client IP -> MAC/session key
	nextID             int64
	identityGeneration uint64
	now                func() time.Time

	queueMu      sync.Mutex
	writes       chan writeOperation
	normalLimit  int
	accepted     uint64 // guarded by queueMu; highest successfully queued sequence
	processed    atomic.Uint64
	progress     chan struct{}
	closed       bool
	workerWG     sync.WaitGroup
	closeOnce    sync.Once
	closeErr     error
	beforeWrite  func()                     // tests only; nil in production
	writeFailure func(writeOperation) error // tests only; nil in production

	hookMu   sync.RWMutex
	onFinish func(result string) // metrics hook
	onDrop   func(operation string)
	dropped  atomic.Uint64

	// Accessed only by the single writer goroutine.
	lastWriteErrorLog time.Time
	writeErrorsHidden uint64
}

type ipIdentity struct {
	MAC        string
	LastSeen   time.Time
	Generation uint64
	BootUntil  time.Time
}

// Open creates/opens the database, applying schema. The parent directory is
// created if missing.
func Open(path string, log *slog.Logger) (*Store, error) {
	return openWithQueue(path, log, defaultWriteQueueSize, nil)
}

// openWithQueue exists to make saturation/backpressure deterministic in unit
// tests. Production always uses Open and its generously sized bounded queue.
func openWithQueue(path string, log *slog.Logger, queueSize int, beforeWrite func()) (*Store, error) {
	if queueSize < 1 {
		return nil, errors.New("sessions queue size must be positive")
	}
	if log == nil {
		log = slog.Default()
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("sessions dir: %w", err)
	}
	if fi, err := os.Stat(dir); err == nil && fi.Mode().Perm()&0o077 != 0 {
		log.Warn("sessions directory permits access by other local users; use mode 0700",
			"dir", dir, "mode", fi.Mode().Perm())
	}
	// modernc.org/sqlite: single writer; busy_timeout smooths concurrent use.
	dsn := "file:" + filepath.ToSlash(path) +
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	const schema = `
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mac TEXT NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  firmware TEXT NOT NULL DEFAULT '',
  image TEXT NOT NULL DEFAULT '',
  strategy TEXT NOT NULL DEFAULT '',
  started_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  result TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_mac ON sessions(mac);
CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at);
CREATE TABLE IF NOT EXISTS events (
  session_id INTEGER NOT NULL,
  at INTEGER NOT NULL,
  stage TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("sessions schema: %w", err)
	}
	// SQLite creates the main file and its WAL/SHM companions. The containing
	// directory is the primary protection; tighten every file already present
	// as well for manual (non-systemd) deployments.
	for _, privatePath := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(privatePath, 0o600); err != nil && !os.IsNotExist(err) {
			db.Close()
			return nil, fmt.Errorf("secure sessions file %s: %w", privatePath, err)
		}
	}
	// In-memory active indexes cannot survive a process restart. Resolve any
	// rows left open by the previous process now; otherwise they remain
	// permanently "in progress" and can never be reached by the janitor.
	interruptedAt := time.Now().UnixMilli()
	tx, err := db.Begin()
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("sessions recovery: %w", err)
	}
	if _, err := tx.Exec(`UPDATE sessions SET result=? WHERE result='completed'`, ResultHandoff); err != nil {
		tx.Rollback()
		db.Close()
		return nil, fmt.Errorf("sessions result migration: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO events(session_id, at, stage, detail)
	  SELECT id, ?, 'fail', 'service stopped or restarted before completion'
	  FROM sessions WHERE result=''`, interruptedAt); err != nil {
		tx.Rollback()
		db.Close()
		return nil, fmt.Errorf("sessions recovery event: %w", err)
	}
	recovered, err := tx.Exec(`UPDATE sessions SET result=?, updated_at=? WHERE result=''`,
		ResultStalled, interruptedAt)
	if err != nil {
		tx.Rollback()
		db.Close()
		return nil, fmt.Errorf("sessions recovery update: %w", err)
	}
	if err := tx.Commit(); err != nil {
		db.Close()
		return nil, fmt.Errorf("sessions recovery commit: %w", err)
	}
	if n, err := recovered.RowsAffected(); err == nil && n > 0 {
		log.Info("recovered interrupted boot sessions", "count", n)
	}
	var nextID int64
	if err := db.QueryRow(`SELECT COALESCE(MAX(id), 0) + 1 FROM sessions`).Scan(&nextID); err != nil {
		db.Close()
		return nil, fmt.Errorf("sessions next id: %w", err)
	}
	reserve := queueSize / 8
	if reserve < 1 && queueSize > 1 {
		reserve = 1
	}
	normalLimit := queueSize - reserve
	if normalLimit < 1 {
		normalLimit = 1
	}
	s := &Store{
		log:         log,
		db:          db,
		active:      map[string]int64{},
		lastAt:      map[string]time.Time{},
		ipToMAC:     map[string]ipIdentity{},
		nextID:      nextID,
		now:         time.Now,
		writes:      make(chan writeOperation, queueSize),
		normalLimit: normalLimit,
		progress:    make(chan struct{}, 1),
		beforeWrite: beforeWrite,
	}
	s.workerWG.Add(1)
	go s.writeWorker()
	return s, nil
}

// OnFinish registers a hook called with the result of every finished session.
func (s *Store) OnFinish(f func(result string)) {
	s.hookMu.Lock()
	s.onFinish = f
	s.hookMu.Unlock()
}

// OnDrop registers the low-cardinality metric hook for telemetry discarded
// under sustained storage backpressure. The hook must return quickly.
func (s *Store) OnDrop(f func(operation string)) {
	s.hookMu.Lock()
	s.onDrop = f
	s.hookMu.Unlock()
}

// DroppedCount reports all telemetry operations dropped since Open. Prometheus
// uses OnDrop for the operation breakdown; this total is useful to tests and
// lightweight diagnostics.
func (s *Store) DroppedCount() uint64 { return s.dropped.Load() }

// Close stops accepting telemetry, drains accepted writes, and closes SQLite.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		s.queueMu.Lock()
		s.closed = true
		close(s.writes)
		s.queueMu.Unlock()
		s.workerWG.Wait()
		s.closeErr = s.db.Close()
	})
	return s.closeErr
}

// Flush waits until every operation accepted before this call has reached the
// SQLite writer. It is intended for management reads, shutdown, and tests —
// never for the DHCP/TFTP/HTTP boot path.
func (s *Store) Flush(ctx context.Context) error {
	s.queueMu.Lock()
	target := s.accepted
	s.queueMu.Unlock()
	recheck := time.NewTicker(10 * time.Millisecond)
	defer recheck.Stop()
	for s.processed.Load() < target {
		select {
		case <-s.progress:
		case <-recheck.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// Ping verifies the database is readable (diagnostics).
func (s *Store) Ping() error {
	s.syncAcceptedWrites()
	var v int
	return s.db.QueryRow(`SELECT COUNT(*) FROM sessions LIMIT 1`).Scan(&v)
}

// ActiveCount reports in-progress sessions (for the gauge).
func (s *Store) ActiveCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.active)
}

// Touch records an event for a MAC, creating a session if none is active.
// This entry point is authoritative: DHCP is the only network service which
// learns a hardware address directly from the client packet.
func (s *Store) Touch(mac, ip, stage, detail string) int64 {
	return s.touch(mac, ip, stage, detail, true)
}

// TouchObserved adds telemetry after ObserveIdentity has recorded a DHCP
// packet. An older handler finishing later must not undo a newer observation.
func (s *Store) TouchObserved(mac, ip, stage, detail string) int64 {
	return s.touch(mac, ip, stage, detail, false)
}

// ObserveIdentity records DHCP identity independently of optional telemetry.
// Call it even for denied clients: an IP reassignment must revoke the previous
// occupant's policy before HTTP or iSCSI can authorize another request.
func (s *Store) ObserveIdentity(mac, ip string) {
	canonical, ok := hardwareMAC(mac)
	addr := net.ParseIP(ip)
	if !ok || addr == nil || addr.IsUnspecified() || addr.IsMulticast() {
		return
	}
	s.mu.Lock()
	s.rememberIdentityLocked(addr.String(), canonical, s.now())
	s.mu.Unlock()
}

func (s *Store) touch(mac, ip, stage, detail string, authoritativeIdentity bool) int64 {
	mac = strings.ToLower(mac)
	now := s.now()

	s.mu.Lock()
	// Identity is boot authorization data, not optional telemetry. Record a
	// real hardware address before touching the bounded SQLite queue so a
	// saturated observability path cannot silently weaken menu policy.
	if canonical, ok := hardwareMAC(mac); authoritativeIdentity && ok && ip != "" {
		s.rememberIdentityLocked(ip, canonical, now)
	}
	id, ok := s.active[mac]
	newSession := !ok || now.Sub(s.lastAt[mac]) > sessionGap
	op := writeOperation{
		kind: writeTouch, id: id, mac: mac, ip: ip, stage: stage,
		detail: detail, at: now.UnixMilli(),
	}
	if newSession {
		if !ok && len(s.active) >= maxActiveSessions {
			s.mu.Unlock()
			s.noteDrop(operationTouch)
			return 0
		}
		op.id = s.nextID
		op.startedAt = now.UnixMilli()
		op.newSession = true
		if ok {
			op.replacedID = id
		}
		// Creating/replacing a session is lifecycle telemetry, so it may use
		// the queue capacity reserved from noisy progress events.
		if !s.enqueue(op, true) {
			s.mu.Unlock()
			s.noteDrop(operationTouch)
			return 0
		}
		s.nextID++
		id = op.id
		s.active[mac] = id
	} else if !s.enqueue(op, false) {
		// Even when the detailed event is dropped, remember real activity in
		// memory so the janitor does not falsely call an active client stalled.
		s.lastAt[mac] = now
		s.mu.Unlock()
		s.noteDrop(operationTouch)
		return id
	}
	s.lastAt[mac] = now
	s.mu.Unlock()
	return id
}

// TouchByIP records an event when only the client IP is known (TFTP and HTTP
// have no MAC). If the IP maps to a known session, the event joins it;
// otherwise a session keyed by the IP is created so the activity is still
// visible.
func (s *Store) TouchByIP(ip, stage, detail string) int64 {
	if ip == "" {
		return 0
	}
	s.mu.Lock()
	identity, ok := s.ipToMAC[ip]
	if identity.MAC == "" {
		ok = false
	}
	if ok && s.now().Sub(identity.LastSeen) > identityTTL {
		if !s.now().Before(identity.BootUntil) {
			delete(s.ipToMAC, ip)
		}
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		identity.MAC = "ip-" + ip
	}
	// Attribution from an IP-only protocol may join the observed session, but
	// it must never renew that DHCP observation. Otherwise a different client
	// which reuses the IP can keep the prior MAC policy alive indefinitely.
	return s.touch(identity.MAC, ip, stage, detail, false)
}

// TouchID appends progress only to the exact active session captured in a
// signed boot grant. It never creates a replacement session, so multi-range
// HTTP SAN reads and late WinPE requests cannot fragment one boot into
// hundreds of rows or attach to a newer boot from the same MAC.
func (s *Store) TouchID(id int64, ip, stage, detail string) bool {
	if id == 0 {
		return false
	}
	now := s.now()
	s.mu.Lock()
	mac := ""
	for key, activeID := range s.active {
		if activeID == id {
			mac = key
			break
		}
	}
	if mac == "" {
		s.mu.Unlock()
		return false
	}
	s.lastAt[mac] = now
	ok := s.enqueue(writeOperation{
		kind: writeTouch, id: id, mac: mac, ip: ip, stage: stage,
		detail: detail, at: now.UnixMilli(),
	}, false)
	s.mu.Unlock()
	if !ok {
		s.noteDrop(operationTouch)
	}
	return ok
}

// MACForIP resolves the best-known MAC for a client IP ("" if unknown).
func (s *Store) MACForIP(ip string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	identity, ok := s.ipToMAC[ip]
	if !ok {
		return ""
	}
	if s.now().Sub(identity.LastSeen) > identityTTL {
		if !s.now().Before(identity.BootUntil) {
			delete(s.ipToMAC, ip)
		}
		return ""
	}
	if identity.MAC == "" {
		return ""
	} // anonymous boot-generation marker
	mac, ok := hardwareMAC(identity.MAC)
	if !ok {
		delete(s.ipToMAC, ip)
		return ""
	}
	return mac
}

func hardwareMAC(value string) (string, bool) {
	mac, err := net.ParseMAC(value)
	if err != nil {
		return "", false
	}
	return strings.ToLower(mac.String()), true
}

func (s *Store) rememberIdentityLocked(ip, mac string, now time.Time) {
	if _, exists := s.ipToMAC[ip]; !exists && len(s.ipToMAC) >= maxIPIdentities {
		return // fail closed under identity-flood pressure
	}
	identity := s.ipToMAC[ip]
	if identity.MAC != mac {
		s.identityGeneration++
		identity = ipIdentity{MAC: mac, Generation: s.identityGeneration}
	}
	identity.LastSeen = now
	s.ipToMAC[ip] = identity
}

// SetMeta attaches firmware/image/strategy details to a MAC's active session
// as they become known. Empty values leave existing ones untouched.
func (s *Store) SetMeta(mac, firmware, image, strategy string) {
	mac = strings.ToLower(mac)
	s.mu.Lock()
	id, ok := s.active[mac]
	s.mu.Unlock()
	if !ok {
		return
	}
	if !s.enqueue(writeOperation{
		kind: writeMeta, id: id, firmware: firmware, image: image, strategy: strategy,
	}, false) {
		s.noteDrop(operationMeta)
	}
}

// SetMetaID is the generation-safe counterpart used by signed boot grants.
func (s *Store) SetMetaID(id int64, firmware, image, strategy string) bool {
	if id == 0 {
		return false
	}
	s.mu.Lock()
	active := false
	for _, activeID := range s.active {
		if activeID == id {
			active = true
			break
		}
	}
	s.mu.Unlock()
	if !active {
		return false
	}
	if !s.enqueue(writeOperation{
		kind: writeMeta, id: id, firmware: firmware, image: image, strategy: strategy,
	}, false) {
		s.noteDrop(operationMeta)
		return false
	}
	return true
}

// Finish closes a MAC's active session with a result.
func (s *Store) Finish(mac, result, detail string) {
	mac = strings.ToLower(mac)
	if result != ResultHandoff && result != ResultFailed && result != ResultStalled {
		result = ResultFailed
		if detail == "" {
			detail = "invalid terminal result"
		}
	}
	now := s.now()
	s.mu.Lock()
	id, ok := s.active[mac]
	if !ok {
		s.mu.Unlock()
		return
	}
	if !s.enqueue(writeOperation{
		kind: writeFinish, id: id, result: result, detail: detail, at: now.UnixMilli(),
	}, true) {
		s.mu.Unlock()
		s.noteDrop(operationFinish)
		return
	}
	delete(s.active, mac)
	delete(s.lastAt, mac)
	s.mu.Unlock()
}

// FinishID closes only the exact session generation captured when a long
// transfer began. A stale response can therefore never finish a newer boot
// which reused the same MAC after the session gap.
func (s *Store) FinishID(id int64, result, detail string) {
	if id == 0 {
		return
	}
	s.mu.Lock()
	key := ""
	for mac, activeID := range s.active {
		if activeID == id {
			key = mac
			break
		}
	}
	s.mu.Unlock()
	if key != "" {
		s.finishIfCurrent(key, id, result, detail)
	}
}

func (s *Store) finishIfCurrent(mac string, expectedID int64, result, detail string) {
	mac = strings.ToLower(mac)
	if result != ResultHandoff && result != ResultFailed && result != ResultStalled {
		result = ResultFailed
		if detail == "" {
			detail = "invalid terminal result"
		}
	}
	now := s.now()
	s.mu.Lock()
	id, ok := s.active[mac]
	if !ok || id != expectedID {
		s.mu.Unlock()
		return
	}
	if !s.enqueue(writeOperation{
		kind: writeFinish, id: id, result: result, detail: detail, at: now.UnixMilli(),
	}, true) {
		s.mu.Unlock()
		s.noteDrop(operationFinish)
		return
	}
	delete(s.active, mac)
	delete(s.lastAt, mac)
	s.mu.Unlock()
}

// enqueue is bounded and never waits. Normal progress events stop at
// normalLimit, leaving a small reserve for session creation and terminal
// results. queueMu serializes the capacity check with sends and shutdown.
func (s *Store) enqueue(op writeOperation, lifecycle bool) bool {
	s.queueMu.Lock()
	defer s.queueMu.Unlock()
	if s.closed {
		return false
	}
	if !lifecycle && len(s.writes) >= s.normalLimit {
		return false
	}
	if len(s.writes) >= cap(s.writes) {
		return false
	}
	s.accepted++
	op.sequence = s.accepted
	select {
	case s.writes <- op:
		return true
	default:
		s.accepted--
		return false
	}
}

func (s *Store) noteDrop(operation string) {
	s.dropped.Add(1)
	s.hookMu.RLock()
	hook := s.onDrop
	s.hookMu.RUnlock()
	if hook != nil {
		// A metrics hook must never be able to take down a boot request.
		func() {
			defer func() { _ = recover() }()
			hook(operation)
		}()
	}
}

func (s *Store) fireFinish(result string) {
	s.hookMu.RLock()
	hook := s.onFinish
	s.hookMu.RUnlock()
	if hook != nil {
		func() {
			defer func() { _ = recover() }()
			hook(result)
		}()
	}
}

func (s *Store) writeWorker() {
	defer s.workerWG.Done()
	failedCreates := make(map[int64]writeOperation)
	for op := range s.writes {
		if s.beforeWrite != nil {
			s.beforeWrite()
		}
		if create, retry := failedCreates[op.id]; retry && !op.newSession {
			finished, err := s.applyWriteTestable(create)
			if err != nil {
				s.noteDrop(op.operation())
				s.logWriteError(err)
				s.markProcessed(op.sequence)
				continue
			}
			delete(failedCreates, op.id)
			if finished != "" {
				s.fireFinish(finished)
			}
			s.restoreRecoveredSession(create, op)
		}
		finished, err := s.applyWriteTestable(op)
		if err != nil {
			if op.kind == writeTouch && op.newSession {
				if len(failedCreates) >= 1024 {
					for id := range failedCreates {
						delete(failedCreates, id)
						break
					}
				}
				failedCreates[op.id] = op
			}
			s.reconcileFailedWrite(op)
			s.noteDrop(op.operation())
			s.logWriteError(err)
		} else if finished != "" {
			s.fireFinish(finished)
		}
		s.markProcessed(op.sequence)
	}
}

func (s *Store) applyWriteTestable(op writeOperation) (string, error) {
	if s.writeFailure != nil {
		if err := s.writeFailure(op); err != nil {
			return "", err
		}
	}
	return s.applyWrite(op)
}

func (s *Store) markProcessed(sequence uint64) {
	s.processed.Store(sequence)
	select {
	case s.progress <- struct{}{}:
	default:
	}
}

func (s *Store) restoreRecoveredSession(create, current writeOperation) {
	if current.kind == writeFinish {
		return
	}
	s.mu.Lock()
	activeID, exists := s.active[create.mac]
	if !exists || activeID == create.id || activeID == create.replacedID {
		s.active[create.mac] = create.id
		s.lastAt[create.mac] = time.UnixMilli(current.at)
	}
	s.mu.Unlock()
}

func (s *Store) reconcileFailedWrite(op writeOperation) {
	if op.kind != writeTouch || !op.newSession {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active[op.mac] != op.id {
		return
	}
	if op.replacedID != 0 {
		// The transactional replacement rolled back, so restore the old row
		// as stale. A subsequent Touch will retry the replacement; otherwise
		// the janitor will close it on its next pass.
		s.active[op.mac] = op.replacedID
		s.lastAt[op.mac] = time.UnixMilli(op.at).Add(-sessionGap - time.Nanosecond)
		return
	}
	delete(s.active, op.mac)
	delete(s.lastAt, op.mac)
}

func (op writeOperation) operation() string {
	switch op.kind {
	case writeTouch:
		return operationTouch
	case writeMeta:
		return operationMeta
	case writeFinish:
		return operationFinish
	default:
		// The default is fixed and is never used for network-supplied data.
		return operationTouch
	}
}

// applyWrite runs in the sole writer goroutine. Multi-statement lifecycle
// transitions use transactions so a database fault cannot leave a terminal
// event without its result (or replace an old session without creating the
// new one).
func (s *Store) applyWrite(op writeOperation) (string, error) {
	switch op.kind {
	case writeTouch:
		tx, err := s.db.Begin()
		if err != nil {
			return "", err
		}
		defer tx.Rollback()
		replaced := false
		if op.replacedID != 0 {
			const replacementDetail = "superseded by a new boot after inactivity"
			if _, err := tx.Exec(`INSERT INTO events(session_id, at, stage, detail)
			  SELECT id, ?, 'fail', ? FROM sessions WHERE id=? AND result=''`,
				op.at, replacementDetail, op.replacedID); err != nil {
				return "", err
			}
			res, err := tx.Exec(`UPDATE sessions SET result=?, updated_at=? WHERE id=? AND result=''`,
				ResultStalled, op.at, op.replacedID)
			if err != nil {
				return "", err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return "", err
			}
			replaced = n > 0
		}
		if op.newSession {
			if _, err := tx.Exec(`INSERT INTO sessions(id, mac, ip, started_at, updated_at)
			  VALUES (?,?,?,?,?)`, op.id, op.mac, op.ip, op.startedAt, op.at); err != nil {
				return "", err
			}
		}
		res, err := tx.Exec(`UPDATE sessions SET updated_at=?,
		  ip=CASE WHEN ?='' THEN ip ELSE ? END WHERE id=? AND result=''`,
			op.at, op.ip, op.ip, op.id)
		if err != nil {
			return "", err
		}
		if n, err := res.RowsAffected(); err != nil {
			return "", err
		} else if n == 0 {
			return "", errSessionNotPersisted
		}
		if _, err := tx.Exec(`INSERT INTO events(session_id, at, stage, detail)
		  SELECT id, ?, ?, ? FROM sessions WHERE id=? AND result=''`,
			op.at, op.stage, op.detail, op.id); err != nil {
			return "", err
		}
		if err := tx.Commit(); err != nil {
			return "", err
		}
		if replaced {
			return ResultStalled, nil
		}
		return "", nil

	case writeMeta:
		res, err := s.db.Exec(`UPDATE sessions SET
		  firmware=CASE WHEN ?='' THEN firmware ELSE ? END,
		  image=CASE WHEN ?='' THEN image ELSE ? END,
		  strategy=CASE WHEN ?='' THEN strategy ELSE ? END
		  WHERE id=?`,
			op.firmware, op.firmware, op.image, op.image, op.strategy, op.strategy, op.id)
		if err != nil {
			return "", err
		}
		if n, err := res.RowsAffected(); err != nil {
			return "", err
		} else if n == 0 {
			return "", errSessionNotPersisted
		}
		return "", nil

	case writeFinish:
		tx, err := s.db.Begin()
		if err != nil {
			return "", err
		}
		defer tx.Rollback()
		stage := "handoff"
		if op.result != ResultHandoff {
			stage = "fail"
		}
		if _, err := tx.Exec(`INSERT INTO events(session_id, at, stage, detail)
		  SELECT id, ?, ?, ? FROM sessions WHERE id=? AND result=''`,
			op.at, stage, op.detail, op.id); err != nil {
			return "", err
		}
		res, err := tx.Exec(`UPDATE sessions SET result=?, updated_at=? WHERE id=? AND result=''`,
			op.result, op.at, op.id)
		if err != nil {
			return "", err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return "", err
		}
		if err := tx.Commit(); err != nil {
			return "", err
		}
		if n > 0 {
			return op.result, nil
		}
		return "", errSessionNotPersisted
	default:
		return "", fmt.Errorf("unknown session write operation %d", op.kind)
	}
}

func (s *Store) logWriteError(err error) {
	now := time.Now()
	if now.Sub(s.lastWriteErrorLog) < 30*time.Second {
		s.writeErrorsHidden++
		return
	}
	hidden := s.writeErrorsHidden
	s.lastWriteErrorLog = now
	s.writeErrorsHidden = 0
	s.log.Warn("session write failed", "error", err, "suppressed_since_last", hidden)
}

// Janitor runs maintenance until ctx is done: stall detection, retention,
// size capping. Call in its own goroutine.
func (s *Store) Janitor(ctx context.Context, retentionDays, maxSizeMB int, spike func() SpikeConfig, onSpike func(failed, total int)) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.pruneIdentities()
			s.markStalled()
			s.purge(retentionDays, maxSizeMB)
			if cfg := spike(); cfg.MinSessions > 0 {
				if failed, total, spiking := s.checkSpike(cfg); spiking {
					onSpike(failed, total)
				}
			}
		}
	}
}

func (s *Store) pruneIdentities() {
	cutoff := s.now().Add(-identityTTL)
	s.mu.Lock()
	for ip, identity := range s.ipToMAC {
		if identity.LastSeen.Before(cutoff) && !s.now().Before(identity.BootUntil) {
			delete(s.ipToMAC, ip)
		}
	}
	s.mu.Unlock()
}

// markStalled fails active sessions with no recent activity.
func (s *Store) markStalled() {
	now := s.now()
	cutoff := now.Add(-stallAfter)
	dropped := 0
	s.mu.Lock()
	for mac, at := range s.lastAt {
		if at.Before(cutoff) {
			id, ok := s.active[mac]
			if !ok {
				continue
			}
			if !s.enqueue(writeOperation{
				kind: writeFinish, id: id, result: ResultStalled,
				detail: fmt.Sprintf("no activity for %s", stallAfter), at: now.UnixMilli(),
			}, true) {
				dropped++
				continue
			}
			delete(s.active, mac)
			delete(s.lastAt, mac)
			for ip, identity := range s.ipToMAC {
				if identity.MAC == mac && !now.Before(identity.BootUntil) {
					delete(s.ipToMAC, ip)
				}
			}
		}
	}
	s.mu.Unlock()
	for i := 0; i < dropped; i++ {
		s.noteDrop(operationFinish)
	}
}

// purge enforces retention and the size cap (oldest sessions first).
func (s *Store) purge(retentionDays, maxSizeMB int) {
	s.syncAcceptedWrites()
	cutoff := time.Now().AddDate(0, 0, -retentionDays).UnixMilli()
	s.exec(`DELETE FROM events WHERE session_id IN (SELECT id FROM sessions WHERE started_at < ?)`, cutoff)
	s.exec(`DELETE FROM sessions WHERE started_at < ?`, cutoff)

	var pageCount, pageSize int64
	if err := s.db.QueryRow(`PRAGMA page_count`).Scan(&pageCount); err != nil {
		return
	}
	if err := s.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		return
	}
	if pageCount*pageSize > int64(maxSizeMB)*1024*1024 {
		// Drop the oldest 10% of sessions and reclaim space.
		s.exec(`DELETE FROM events WHERE session_id IN
		  (SELECT id FROM sessions ORDER BY started_at ASC LIMIT (SELECT COUNT(*)/10+1 FROM sessions))`)
		s.exec(`DELETE FROM sessions WHERE id IN
		  (SELECT id FROM sessions ORDER BY started_at ASC LIMIT (SELECT COUNT(*)/10+1 FROM sessions))`)
		s.exec(`VACUUM`)
	}
}

// checkSpike reports whether the failure rate over the window crossed the
// threshold.
func (s *Store) checkSpike(cfg SpikeConfig) (failed, total int, spiking bool) {
	s.syncAcceptedWrites()
	since := time.Now().Add(-cfg.Window).UnixMilli()
	err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN result IN (?,?) THEN 1 ELSE 0 END),0)
	  FROM sessions WHERE updated_at >= ? AND result != ''`,
		ResultFailed, ResultStalled, since).Scan(&total, &failed)
	if err != nil {
		s.log.Warn("spike query failed", "error", err)
		return 0, 0, false
	}
	if total < cfg.MinSessions {
		return failed, total, false
	}
	return failed, total, failed*100 >= total*cfg.ThresholdPc
}

// ActivityBucket is one hour of finished Boot Sessions, for the dashboard
// activity chart.
type ActivityBucket struct {
	Hour    time.Time `json:"hour"`
	Handoff int       `json:"handoff"`
	Failed  int       `json:"failed"`
	Stalled int       `json:"stalled"`
}

// Activity returns per-hour result counts for the last N hours, oldest
// first. Hours with no sessions are included as zero buckets so the chart's
// time axis is continuous.
func (s *Store) Activity(hours int) ([]ActivityBucket, error) {
	s.syncAcceptedWrites()
	const hourMs = int64(time.Hour / time.Millisecond)
	now := time.Now()
	start := now.Truncate(time.Hour).Add(-time.Duration(hours-1) * time.Hour)

	rows, err := s.db.Query(`SELECT (started_at/?)*? AS h, result, COUNT(*)
	  FROM sessions WHERE started_at >= ? AND result != '' GROUP BY h, result`,
		hourMs, hourMs, start.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byHour := map[int64]*ActivityBucket{}
	out := make([]ActivityBucket, hours)
	for i := range out {
		t := start.Add(time.Duration(i) * time.Hour)
		out[i].Hour = t
		byHour[t.UnixMilli()] = &out[i]
	}
	for rows.Next() {
		var h int64
		var result string
		var n int
		if err := rows.Scan(&h, &result, &n); err != nil {
			return nil, err
		}
		b, ok := byHour[h]
		if !ok {
			continue
		}
		switch result {
		case ResultHandoff:
			b.Handoff += n
		case ResultFailed:
			b.Failed += n
		case ResultStalled:
			b.Stalled += n
		}
	}
	return out, rows.Err()
}

const listColumns = `id, mac, ip, firmware, image, strategy, started_at, updated_at, result,
  COALESCE((SELECT GROUP_CONCAT(DISTINCT stage) FROM events e WHERE e.session_id=sessions.id), '')`

// Recent returns the newest sessions (without events, with stage summary).
func (s *Store) Recent(limit int) ([]Session, error) {
	s.syncAcceptedWrites()
	rows, err := s.db.Query(`SELECT `+listColumns+`
	  FROM sessions ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSessions(rows)
}

// ForMAC returns a MAC's sessions, newest first.
func (s *Store) ForMAC(mac string, limit int) ([]Session, error) {
	s.syncAcceptedWrites()
	rows, err := s.db.Query(`SELECT `+listColumns+`
	  FROM sessions WHERE mac=? ORDER BY started_at DESC LIMIT ?`, strings.ToLower(mac), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSessions(rows)
}

// Get loads one session with its full timeline.
func (s *Store) Get(id int64) (*Session, error) {
	s.syncAcceptedWrites()
	row := s.db.QueryRow(`SELECT id, mac, ip, firmware, image, strategy, started_at, updated_at, result
	  FROM sessions WHERE id=?`, id)
	sess, err := scanSession(row)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT at, stage, detail FROM events WHERE session_id=? ORDER BY at ASC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var at int64
		var e Event
		if err := rows.Scan(&at, &e.Stage, &e.Detail); err != nil {
			return nil, err
		}
		e.At = time.UnixMilli(at)
		sess.Events = append(sess.Events, e)
	}
	return sess, rows.Err()
}

type rowScanner interface{ Scan(dest ...any) error }

func scanSession(r rowScanner) (*Session, error) {
	var sess Session
	var started, updated int64
	if err := r.Scan(&sess.ID, &sess.MAC, &sess.IP, &sess.Firmware, &sess.Image,
		&sess.Strategy, &started, &updated, &sess.Result); err != nil {
		return nil, err
	}
	sess.StartedAt = time.UnixMilli(started)
	sess.UpdatedAt = time.UnixMilli(updated)
	return &sess, nil
}

func scanSessions(rows *sql.Rows) ([]Session, error) {
	var out []Session
	for rows.Next() {
		var sess Session
		var started, updated int64
		var stageCSV string
		if err := rows.Scan(&sess.ID, &sess.MAC, &sess.IP, &sess.Firmware, &sess.Image,
			&sess.Strategy, &started, &updated, &sess.Result, &stageCSV); err != nil {
			return nil, err
		}
		sess.StartedAt = time.UnixMilli(started)
		sess.UpdatedAt = time.UnixMilli(updated)
		if stageCSV != "" {
			sess.Stages = strings.Split(stageCSV, ",")
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// syncAcceptedWrites makes management/maintenance reads internally
// consistent without ever putting a wait on the network boot path.
func (s *Store) syncAcceptedWrites() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.Flush(ctx)
}

// exec runs a best-effort maintenance write. Boot-path writes never call it;
// they go through the bounded asynchronous queue above.
func (s *Store) exec(query string, args ...any) {
	if _, err := s.db.Exec(query, args...); err != nil {
		s.log.Warn("session write failed", "error", err)
	}
}
