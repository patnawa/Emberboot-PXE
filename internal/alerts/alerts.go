// Package alerts implements Emberboot's fixed alert catalog, delivered as JSON
// webhooks. The catalog is deliberately small: every alert here pages a
// human, so each one must be actionable.
package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Kind enumerates the fixed v1 alert catalog.
type Kind string

const (
	CrashRestart    Kind = "crash_restart"     // service started after unclean exit
	ImageInvalid    Kind = "image_invalid"     // Image failed validation
	FailureSpike    Kind = "failure_spike"     // Boot Session failure-rate spike
	DiskLow         Kind = "disk_low"          // image volume free space low
	ConfigRejected  Kind = "config_rejected"   // reload rejected, last-known-good serving
	RoguePXEServer  Kind = "rogue_pxe_server"  // another PXE responder heard on the wire
)

// Alert is the webhook payload and the dashboard history entry.
type Alert struct {
	Site    string            `json:"site"`
	Kind    Kind              `json:"kind"`
	Message string            `json:"message"`
	Details map[string]string `json:"details,omitempty"`
	Time    time.Time         `json:"time"`
}

// dedupeWindow suppresses repeats of the same (kind, dedupeKey) — a rogue
// server answering every DHCP request must not page every three seconds.
const dedupeWindow = 15 * time.Minute

const historySize = 200

// Notifier fires alerts. Safe for concurrent use. The webhook URL and site
// are read per-alert so config hot-reloads take effect immediately.
type Notifier struct {
	log     *slog.Logger
	client  *http.Client
	setting func() (site, webhookURL string)

	mu      sync.Mutex
	lastFired map[string]time.Time
	history []Alert
}

// New creates a Notifier. setting returns the current site name and webhook
// URL (empty URL = log-only).
func New(log *slog.Logger, setting func() (site, webhookURL string)) *Notifier {
	return &Notifier{
		log:       log,
		client:    &http.Client{Timeout: 10 * time.Second},
		setting:   setting,
		lastFired: map[string]time.Time{},
	}
}

// Fire raises an alert. dedupeKey groups repeats (use "" when every
// occurrence matters). Delivery is asynchronous; Fire never blocks callers.
func (n *Notifier) Fire(kind Kind, dedupeKey, message string, details map[string]string) {
	site, url := n.setting()
	a := Alert{Site: site, Kind: kind, Message: message, Details: details, Time: time.Now()}

	n.mu.Lock()
	key := string(kind) + "|" + dedupeKey
	if last, ok := n.lastFired[key]; ok && time.Since(last) < dedupeWindow {
		n.mu.Unlock()
		n.log.Debug("alert suppressed (dedupe)", "kind", kind, "key", dedupeKey)
		return
	}
	n.lastFired[key] = a.Time
	n.history = append(n.history, a)
	if len(n.history) > historySize {
		n.history = n.history[len(n.history)-historySize:]
	}
	n.mu.Unlock()

	n.log.Warn("alert", "kind", kind, "message", message, "details", details)
	if url == "" {
		return
	}
	go n.deliver(url, a)
}

// History returns recent alerts, newest last, for the dashboard.
func (n *Notifier) History() []Alert {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]Alert, len(n.history))
	copy(out, n.history)
	return out
}

// deliver POSTs with retries. An unreachable webhook must never affect boot
// service, so failures only log.
func (n *Notifier) deliver(url string, a Alert) {
	body, err := json.Marshal(a)
	if err != nil {
		n.log.Error("alert marshal", "error", err)
		return
	}
	backoff := 2 * time.Second
	for attempt := 1; attempt <= 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := n.client.Do(req)
		cancel()
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 300 {
				return
			}
			err = fmt.Errorf("webhook returned %s", resp.Status)
		}
		n.log.Warn("alert delivery failed", "attempt", attempt, "error", err)
		if attempt < 3 {
			time.Sleep(backoff)
			backoff *= 2
		}
	}
}
