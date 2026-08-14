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
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Result values for finished sessions.
const (
	ResultCompleted = "completed"
	ResultFailed    = "failed"
	ResultStalled   = "stalled"
)

// sessionGap: a new event from a MAC more than this long after its last
// activity starts a new Boot Session rather than extending the old one.
const sessionGap = 5 * time.Minute

// stallAfter: an unfinished session with no activity for this long is marked
// stalled (the "stuck at 43%" case).
const stallAfter = 15 * time.Minute

// Event is one step in a session timeline.
type Event struct {
	At     time.Time `json:"at"`
	Stage  string    `json:"stage"`  // dhcp|tftp|script|payload|answer|complete|fail
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
	Events    []Event   `json:"events,omitempty"`
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

	mu      sync.Mutex
	active  map[string]int64 // mac -> session id
	lastAt  map[string]time.Time
	ipToMAC map[string]string // last-seen client IP -> mac

	onFinish func(result string) // metrics hook
}

// Open creates/opens the database, applying schema. The parent directory is
// created if missing.
func Open(path string, log *slog.Logger) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("sessions dir: %w", err)
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
	return &Store{
		log:     log,
		db:      db,
		active:  map[string]int64{},
		lastAt:  map[string]time.Time{},
		ipToMAC: map[string]string{},
	}, nil
}

// OnFinish registers a hook called with the result of every finished session.
func (s *Store) OnFinish(f func(result string)) { s.onFinish = f }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// ActiveCount reports in-progress sessions (for the gauge).
func (s *Store) ActiveCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.active)
}

// Touch records an event for a MAC, creating a session if none is active.
// It is the single entry point used by the DHCP, TFTP and HTTP services.
func (s *Store) Touch(mac, ip, stage, detail string) {
	mac = strings.ToLower(mac)
	now := time.Now()

	s.mu.Lock()
	id, ok := s.active[mac]
	if !ok || now.Sub(s.lastAt[mac]) > sessionGap {
		var err error
		id, err = s.newSession(mac, ip, now)
		if err != nil {
			s.mu.Unlock()
			s.log.Warn("session create failed", "mac", mac, "error", err)
			return
		}
		s.active[mac] = id
	}
	s.lastAt[mac] = now
	if ip != "" {
		s.ipToMAC[ip] = mac
	}
	s.mu.Unlock()

	s.exec(`UPDATE sessions SET updated_at=?, ip=CASE WHEN ?='' THEN ip ELSE ? END WHERE id=?`,
		now.UnixMilli(), ip, ip, id)
	s.exec(`INSERT INTO events(session_id, at, stage, detail) VALUES (?,?,?,?)`,
		id, now.UnixMilli(), stage, detail)
}

// TouchByIP records an event when only the client IP is known (TFTP and HTTP
// have no MAC). If the IP maps to a known session, the event joins it;
// otherwise a session keyed by the IP is created so the activity is still
// visible.
func (s *Store) TouchByIP(ip, stage, detail string) {
	if ip == "" {
		return
	}
	s.mu.Lock()
	mac, ok := s.ipToMAC[ip]
	s.mu.Unlock()
	if !ok {
		mac = "ip-" + ip
	}
	s.Touch(mac, ip, stage, detail)
}

// MACForIP resolves the best-known MAC for a client IP ("" if unknown).
func (s *Store) MACForIP(ip string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ipToMAC[ip]
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
	s.exec(`UPDATE sessions SET
	  firmware=CASE WHEN ?='' THEN firmware ELSE ? END,
	  image=CASE WHEN ?='' THEN image ELSE ? END,
	  strategy=CASE WHEN ?='' THEN strategy ELSE ? END
	  WHERE id=?`,
		firmware, firmware, image, image, strategy, strategy, id)
}

// Finish closes a MAC's active session with a result.
func (s *Store) Finish(mac, result, detail string) {
	mac = strings.ToLower(mac)
	now := time.Now()
	s.mu.Lock()
	id, ok := s.active[mac]
	if ok {
		delete(s.active, mac)
		delete(s.lastAt, mac)
	}
	s.mu.Unlock()
	if !ok {
		return
	}
	stage := "complete"
	if result != ResultCompleted {
		stage = "fail"
	}
	s.exec(`INSERT INTO events(session_id, at, stage, detail) VALUES (?,?,?,?)`,
		id, now.UnixMilli(), stage, detail)
	s.exec(`UPDATE sessions SET result=?, updated_at=? WHERE id=?`, result, now.UnixMilli(), id)
	if s.onFinish != nil {
		s.onFinish(result)
	}
}

// newSession inserts a session row. Caller holds s.mu.
func (s *Store) newSession(mac, ip string, now time.Time) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO sessions(mac, ip, started_at, updated_at) VALUES (?,?,?,?)`,
		mac, ip, now.UnixMilli(), now.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
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

// markStalled fails active sessions with no recent activity.
func (s *Store) markStalled() {
	cutoff := time.Now().Add(-stallAfter)
	var stale []string
	s.mu.Lock()
	for mac, at := range s.lastAt {
		if at.Before(cutoff) {
			stale = append(stale, mac)
		}
	}
	s.mu.Unlock()
	for _, mac := range stale {
		s.Finish(mac, ResultStalled, fmt.Sprintf("no activity for %s", stallAfter))
	}
}

// purge enforces retention and the size cap (oldest sessions first).
func (s *Store) purge(retentionDays, maxSizeMB int) {
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

// Recent returns the newest sessions (without events).
func (s *Store) Recent(limit int) ([]Session, error) {
	rows, err := s.db.Query(`SELECT id, mac, ip, firmware, image, strategy, started_at, updated_at, result
	  FROM sessions ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSessions(rows)
}

// ForMAC returns a MAC's sessions, newest first.
func (s *Store) ForMAC(mac string, limit int) ([]Session, error) {
	rows, err := s.db.Query(`SELECT id, mac, ip, firmware, image, strategy, started_at, updated_at, result
	  FROM sessions WHERE mac=? ORDER BY started_at DESC LIMIT ?`, strings.ToLower(mac), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSessions(rows)
}

// Get loads one session with its full timeline.
func (s *Store) Get(id int64) (*Session, error) {
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
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *sess)
	}
	return out, rows.Err()
}

// exec runs a best-effort write: errors degrade observability, never booting.
func (s *Store) exec(query string, args ...any) {
	if _, err := s.db.Exec(query, args...); err != nil {
		s.log.Warn("session write failed", "error", err)
	}
}
