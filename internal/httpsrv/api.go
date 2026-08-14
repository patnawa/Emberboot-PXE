package httpsrv

import (
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"emberboot/internal/alerts"
	"emberboot/internal/config"
	"emberboot/internal/images"
	"emberboot/internal/logging"
	"emberboot/internal/metrics"
	"emberboot/internal/sessions"
)

//go:embed dashboard.html
var dashboardHTML []byte

// APIDeps wires the dashboard/API server.
type APIDeps struct {
	Log       *slog.Logger
	Cfg       *config.Manager
	Images    *images.Manager
	Sessions  *sessions.Store
	Alerts    *alerts.Notifier
	Metrics   *metrics.M
	Version   string
	StartTime time.Time
	// AdvertiseIP and HTTPBase describe this instance's network identity, so
	// the Config view can show admins the exact DHCP 66/67 values to use.
	AdvertiseIP string
	HTTPBase    string
	// LogRing exposes recent log records to the diagnostics view (optional).
	LogRing *logging.Ring
	// RogueActive reports whether rogue-PXE monitoring is running (optional).
	RogueActive func() bool
}

// APIServer is the authenticated management server (read-mostly dashboard +
// REST API, ADR-0002: the API automates, it does not become a second config
// write path).
type APIServer struct {
	d        APIDeps
	srv      *http.Server
	warnOnce sync.Once
}

// NewAPI builds the server for the configured dashboard bind address.
func NewAPI(d APIDeps, addr string) *APIServer {
	s := &APIServer{d: d}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.auth(s.handleIndex))
	mux.HandleFunc("GET /api/health", s.auth(s.handleHealth))
	mux.HandleFunc("GET /api/images", s.auth(s.handleImages))
	mux.HandleFunc("GET /api/sessions", s.auth(s.handleSessions))
	mux.HandleFunc("GET /api/sessions/{id}", s.auth(s.handleSession))
	mux.HandleFunc("GET /api/activity", s.auth(s.handleActivity))
	mux.HandleFunc("GET /api/alerts", s.auth(s.handleAlerts))
	mux.HandleFunc("GET /api/config", s.auth(s.handleConfig))
	mux.HandleFunc("POST /api/reload", s.auth(s.handleReload))
	s.registerManagement(mux)
	mux.Handle("GET /metrics", s.authHandler(d.Metrics.Handler()))
	s.srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	return s
}

func (s *APIServer) Serve() error {
	err := s.srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *APIServer) Close() { _ = s.srv.Close() }

// --- auth ---

func (s *APIServer) auth(next http.HandlerFunc) http.HandlerFunc {
	return s.authHandler(next).ServeHTTP
}

// authHandler accepts a bearer API token or Basic admin credentials. With no
// auth configured, access is allowed (rely on dashboard_bind) but warned.
func (s *APIServer) authHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := s.d.Cfg.Current()
		if cfg.Auth.AdminPasswordHash == "" && len(cfg.Auth.APITokens) == 0 {
			s.warnOnce.Do(func() {
				s.d.Log.Warn("dashboard/API has no auth configured; restrict network.dashboard_bind or set auth")
			})
			next.ServeHTTP(w, r)
			return
		}
		if tok, ok := bearerToken(r); ok {
			for _, t := range cfg.Auth.APITokens {
				if subtle.ConstantTimeCompare([]byte(t), []byte(tok)) == 1 {
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		if user, pass, ok := r.BasicAuth(); ok && user == "admin" && cfg.Auth.AdminPasswordHash != "" {
			if bcrypt.CompareHashAndPassword([]byte(cfg.Auth.AdminPasswordHash), []byte(pass)) == nil {
				next.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="Emberboot"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func bearerToken(r *http.Request) (string, bool) {
	const p = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(p) && h[:len(p)] == p {
		return h[len(p):], true
	}
	return "", false
}

// --- handlers ---

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *APIServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(dashboardHTML)
}

func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	cfg := s.d.Cfg.Current()
	writeJSON(w, map[string]any{
		"status":          "ok",
		"site":            cfg.Site,
		"version":         s.d.Version,
		"uptime_seconds":  int(time.Since(s.d.StartTime).Seconds()),
		"active_sessions": s.d.Sessions.ActiveCount(),
		"advertise_ip":    s.d.AdvertiseIP,
		"http_base":       s.d.HTTPBase,
		"dhcp_mode":       string(cfg.Network.DHCPMode),
		"tftp_port":       cfg.Network.TFTPPort,
		"http_port":       cfg.Network.HTTPPort,
		"iscsi_port":      cfg.Network.ISCSIPort,
		"auth_configured": cfg.Auth.AdminPasswordHash != "" || len(cfg.Auth.APITokens) > 0,
	})
}

func (s *APIServer) handleImages(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.d.Images.List())
}

func (s *APIServer) handleSessions(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 1000 {
		limit = v
	}
	var (
		list []sessions.Session
		err  error
	)
	if mac := r.URL.Query().Get("mac"); mac != "" {
		list, err = s.d.Sessions.ForMAC(mac, limit)
	} else {
		list, err = s.d.Sessions.Recent(limit)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if list == nil {
		list = []sessions.Session{}
	}
	writeJSON(w, list)
}

func (s *APIServer) handleSession(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	sess, err := s.d.Sessions.Get(id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, sess)
}

func (s *APIServer) handleActivity(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if v, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && v >= 1 && v <= 168 {
		hours = v
	}
	buckets, err := s.d.Sessions.Activity(hours)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, buckets)
}

func (s *APIServer) handleAlerts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.d.Alerts.History())
}

func (s *APIServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.d.Cfg.Status())
}

func (s *APIServer) handleReload(w http.ResponseWriter, r *http.Request) {
	if err := s.d.Cfg.Reload(); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}
