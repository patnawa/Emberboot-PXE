package httpsrv

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
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
	// RuntimeConfig is the immutable startup snapshot for listeners and
	// restart-bound paths. Current config may contain pending hot edits.
	RuntimeConfig *config.Config
	// LogRing exposes recent log records to the diagnostics view (optional).
	LogRing *logging.Ring
	// RogueActive reports whether rogue-PXE monitoring is running (optional).
	RogueActive func() bool
}

// APIServer is the authenticated management server (read-mostly dashboard +
// REST API, ADR-0002: the API automates, it does not become a second config
// write path).
type APIServer struct {
	d            APIDeps
	srv          *http.Server
	warnOnce     sync.Once
	authMu       sync.Mutex
	authFailures map[string]authFailure
	authGlobal   authFailure
	authInFlight map[string]int
	authActive   int
	comparePass  func([]byte, []byte) error
	runtime      *config.Config
	bindHost     string
	tlsMu        sync.Mutex
	tlsCertFile  string
	tlsKeyFile   string
	tlsDigest    [sha256.Size]byte
	tlsCert      *tls.Certificate
	tlsLastWarn  time.Time
}

type authFailure struct {
	First   time.Time
	Count   int
	Blocked time.Time
}

// NewAPI builds the server for the configured dashboard bind address.
func NewAPI(d APIDeps, addr string) *APIServer {
	runtimeCfg := d.RuntimeConfig
	if runtimeCfg == nil {
		copyCfg := *d.Cfg.Current()
		runtimeCfg = &copyCfg
	}
	bindHost, _, _ := net.SplitHostPort(addr)
	s := &APIServer{
		d: d, authFailures: make(map[string]authFailure), authInFlight: make(map[string]int),
		runtime: runtimeCfg, bindHost: bindHost,
	}
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
		Handler:           securityHeaders(s.requestGuard(mux)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	return s
}

func (s *APIServer) Serve() error {
	return serverResult(s.srv.ListenAndServe())
}

// ServeTLS starts the management listener with an operator-provided
// certificate. PXE payload HTTP remains separate because many firmware and
// installer stacks cannot validate private PKI.
func (s *APIServer) ServeTLS(certFile, keyFile string) error {
	s.tlsMu.Lock()
	s.tlsCertFile, s.tlsKeyFile = certFile, keyFile
	_, err := s.loadTLSCertificateLocked()
	s.tlsMu.Unlock()
	if err != nil {
		return err
	}
	s.srv.TLSConfig = &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: s.getTLSCertificate,
	}
	// Empty paths are intentional: GetCertificate owns loading and hot
	// renewal, retaining the last known-good pair if a replacement is only
	// partially written.
	return serverResult(s.srv.ListenAndServeTLS("", ""))
}

func (s *APIServer) getTLSCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.tlsMu.Lock()
	defer s.tlsMu.Unlock()
	cert, err := s.loadTLSCertificateLocked()
	if err == nil {
		return cert, nil
	}
	if s.tlsCert != nil {
		now := time.Now()
		if now.Sub(s.tlsLastWarn) >= time.Minute {
			s.tlsLastWarn = now
			if s.d.Log != nil {
				s.d.Log.Warn("dashboard TLS renewal rejected; retaining last known-good certificate", "error", err)
			}
		}
		return s.tlsCert, nil
	}
	return nil, err
}

func (s *APIServer) loadTLSCertificateLocked() (*tls.Certificate, error) {
	certPEM, err := os.ReadFile(s.tlsCertFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(s.tlsKeyFile)
	if err != nil {
		return nil, err
	}
	material := make([]byte, 0, len(certPEM)+1+len(keyPEM))
	material = append(material, certPEM...)
	material = append(material, 0)
	material = append(material, keyPEM...)
	digest := sha256.Sum256(material)
	if s.tlsCert != nil && digest == s.tlsDigest {
		return s.tlsCert, nil
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("leaf certificate is not currently valid")
	}
	cert.Leaf = leaf
	s.tlsDigest = digest
	s.tlsCert = &cert
	return s.tlsCert, nil
}

func serverResult(err error) error {
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *APIServer) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := s.srv.Shutdown(ctx); err != nil {
		_ = s.srv.Close()
	}
}

// --- auth ---

func (s *APIServer) auth(next http.HandlerFunc) http.HandlerFunc {
	return s.authHandler(next).ServeHTTP
}

// authHandler accepts a bearer API token or Basic admin credentials. A blank
// first-run configuration is usable only from loopback, which closes the
// historical remote bootstrap race without making local setup cumbersome.
func (s *APIServer) authHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := s.d.Cfg.Current()
		if cfg.Auth.AdminPasswordHash == "" && len(cfg.Auth.APITokens) == 0 {
			s.warnOnce.Do(func() {
				s.d.Log.Warn("dashboard/API has no auth configured; bootstrap access is restricted to loopback")
			})
			if isLoopbackRequest(r) {
				s.serveAuthenticated(w, r, next, "bootstrap-local")
				return
			}
			http.Error(w, "management authentication is not configured", http.StatusForbidden)
			return
		}

		remote := clientIP(r)
		if retry := s.authRetryAfter(remote, time.Now()); retry > 0 {
			s.authMetric("blocked")
			w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
			http.Error(w, "too many authentication failures", http.StatusTooManyRequests)
			return
		}
		if tok, ok := bearerToken(r); ok {
			for _, t := range cfg.Auth.APITokens {
				if verifyAPIToken(t, tok) {
					s.clearAuthFailures(remote)
					s.serveAuthenticated(w, r, next, tokenPrincipal(t))
					return
				}
			}
		}
		if user, pass, ok := r.BasicAuth(); ok && user == "admin" && cfg.Auth.AdminPasswordHash != "" {
			if !s.beginPasswordCheck(remote) {
				s.authMetric("busy")
				w.Header().Set("Retry-After", "1")
				http.Error(w, "authentication service is busy", http.StatusTooManyRequests)
				return
			}
			compare := s.comparePass
			if compare == nil {
				compare = bcrypt.CompareHashAndPassword
			}
			err := compare([]byte(cfg.Auth.AdminPasswordHash), []byte(pass))
			s.endPasswordCheck(remote)
			if err == nil {
				s.clearAuthFailures(remote)
				s.serveAuthenticated(w, r, next, "admin")
				return
			}
		}
		localBlocked, globalBlocked := s.recordAuthFailure(remote, time.Now())
		s.authMetric("failed")
		if (localBlocked || globalBlocked) && s.d.Log != nil {
			s.d.Log.Warn("management authentication source blocked",
				"remote_ip", remote, "global_block", globalBlocked)
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="Emberboot"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func isLoopbackRequest(r *http.Request) bool {
	ip := net.ParseIP(clientIP(r))
	return ip != nil && ip.IsLoopback()
}

const (
	authFailureWindow      = 5 * time.Minute
	authBlockDuration      = 5 * time.Minute
	authFailureLimit       = 8
	authGlobalFailureLimit = 256
	maxAuthFailureSources  = 1024
	maxPasswordChecks      = 8
	maxPasswordChecksPerIP = 8
)

// beginPasswordCheck bounds the expensive bcrypt verifier independently of
// the failure window. Without this admission step, a concurrent burst can
// pass the pre-check before the first failure is recorded and consume every
// CPU core.
func (s *APIServer) beginPasswordCheck(remote string) bool {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if s.authActive >= maxPasswordChecks || s.authInFlight[remote] >= maxPasswordChecksPerIP {
		return false
	}
	if s.authInFlight == nil {
		s.authInFlight = make(map[string]int)
	}
	s.authActive++
	s.authInFlight[remote]++
	return true
}

func (s *APIServer) endPasswordCheck(remote string) {
	s.authMu.Lock()
	if n := s.authInFlight[remote]; n <= 1 {
		delete(s.authInFlight, remote)
	} else {
		s.authInFlight[remote] = n - 1
	}
	if s.authActive > 0 {
		s.authActive--
	}
	s.authMu.Unlock()
}

func (s *APIServer) authRetryAfter(remote string, now time.Time) time.Duration {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if s.authGlobal.Blocked.After(now) {
		return s.authGlobal.Blocked.Sub(now)
	}
	f, ok := s.authFailures[remote]
	if !ok || !f.Blocked.After(now) {
		return 0
	}
	return f.Blocked.Sub(now)
}

func (s *APIServer) recordAuthFailure(remote string, now time.Time) (localBlocked, globalBlocked bool) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	g := s.authGlobal
	if g.First.IsZero() || now.Sub(g.First) > authFailureWindow {
		g = authFailure{First: now}
	}
	g.Count++
	if g.Count >= authGlobalFailureLimit && !g.Blocked.After(now) {
		g.Blocked = now.Add(authBlockDuration)
		globalBlocked = true
	}
	s.authGlobal = g

	if len(s.authFailures) >= maxAuthFailureSources {
		for ip, f := range s.authFailures {
			if now.Sub(f.First) > authFailureWindow && !f.Blocked.After(now) {
				delete(s.authFailures, ip)
			}
		}
		if len(s.authFailures) >= maxAuthFailureSources {
			oldestIP := ""
			var oldest time.Time
			for ip, f := range s.authFailures {
				if oldestIP == "" || f.First.Before(oldest) {
					oldestIP, oldest = ip, f.First
				}
			}
			delete(s.authFailures, oldestIP)
		}
	}
	f := s.authFailures[remote]
	if f.First.IsZero() || now.Sub(f.First) > authFailureWindow {
		f = authFailure{First: now}
	}
	f.Count++
	if f.Count >= authFailureLimit && !f.Blocked.After(now) {
		f.Blocked = now.Add(authBlockDuration)
		localBlocked = true
	}
	s.authFailures[remote] = f
	return localBlocked, globalBlocked
}

func (s *APIServer) clearAuthFailures(remote string) {
	s.authMu.Lock()
	delete(s.authFailures, remote)
	s.authMu.Unlock()
}

type principalContextKey struct{}

func (s *APIServer) serveAuthenticated(w http.ResponseWriter, r *http.Request, next http.Handler, principal string) {
	r = r.WithContext(context.WithValue(r.Context(), principalContextKey{}, principal))
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		next.ServeHTTP(w, r)
		return
	}
	aw := &auditResponseWriter{ResponseWriter: w, status: http.StatusOK}
	started := time.Now()
	next.ServeHTTP(aw, r)
	if s.d.Log != nil {
		s.d.Log.Info("management mutation",
			"principal", principal, "remote_ip", clientIP(r),
			"method", r.Method, "path", r.URL.Path, "status", aw.status,
			"duration_ms", time.Since(started).Milliseconds())
	}
}

type auditResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *auditResponseWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *auditResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

func tokenPrincipal(stored string) string {
	parts := strings.Split(stored, ":")
	if len(parts) == 3 && parts[0] == "sha256" {
		return "token:" + parts[1]
	}
	return "token:legacy"
}

func (s *APIServer) authMetric(result string) {
	if s.d.Metrics != nil && s.d.Metrics.ManagementAuth != nil {
		s.d.Metrics.ManagementAuth.WithLabelValues(result).Inc()
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// requestGuard blocks browser cross-origin mutations (including first-run
// loopback takeover) without burdening non-browser API clients with a CSRF
// token. TLS protects exposed deployments; this guard also covers cached
// Basic credentials and DNS-rebinding attempts against local bootstrap.
func (s *APIServer) requestGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !dashboardRequestHostAllowed(s.bindHost, r.Host) {
			http.Error(w, "invalid management host", http.StatusForbidden)
			return
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if site := strings.ToLower(r.Header.Get("Sec-Fetch-Site")); site != "" && site != "same-origin" && site != "none" {
			http.Error(w, "cross-origin management request denied", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			if err != nil || !strings.EqualFold(u.Scheme, scheme) || !strings.EqualFold(u.Host, r.Host) {
				http.Error(w, "cross-origin management request denied", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func dashboardRequestHostAllowed(bindHost, requestHostPort string) bool {
	bindHost = strings.TrimSuffix(strings.ToLower(bindHost), ".")
	bindIP := net.ParseIP(bindHost)
	if bindHost != "localhost" && (bindIP == nil || !bindIP.IsLoopback()) {
		return true // Remote management is authenticated and TLS-only.
	}
	requestHost := requestHostPort
	if host, _, err := net.SplitHostPort(requestHostPort); err == nil {
		requestHost = host
	}
	requestHost = strings.Trim(strings.TrimSuffix(strings.ToLower(requestHost), "."), "[]")
	if requestHost == "localhost" {
		return true
	}
	ip := net.ParseIP(requestHost)
	return ip != nil && ip.IsLoopback()
}

func bearerToken(r *http.Request) (string, bool) {
	const p = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(p) && h[:len(p)] == p {
		return h[len(p):], true
	}
	return "", false
}

const apiTokenHashPrefix = config.APITokenHashPrefix

// APITokenRecord stores only a SHA-256 verifier plus a short non-secret hint.
// API tokens are 192 random bits, so an offline digest does not make guessing
// practical and raw-config access no longer discloses live credentials.
func APITokenRecord(token string) string {
	return config.APITokenRecord(token)
}

func verifyAPIToken(stored, presented string) bool {
	if strings.HasPrefix(stored, apiTokenHashPrefix) {
		parts := strings.Split(stored, ":")
		if len(parts) != 3 {
			return false
		}
		want, err := hex.DecodeString(parts[2])
		if err != nil || len(want) != sha256.Size {
			return false
		}
		got := sha256.Sum256([]byte(presented))
		return subtle.ConstantTimeCompare(want, got[:]) == 1
	}
	// Backward compatibility for one startup: main migrates legacy plaintext
	// records immediately after loading a writable configuration.
	return subtle.ConstantTimeCompare([]byte(stored), []byte(presented)) == 1
}

// MigrateLegacyAPITokens replaces old plaintext token records before any
// network listener starts.
func MigrateLegacyAPITokens(mgr *config.Manager) (int, error) {
	changed := 0
	err := mgr.UpdateAPITokens(func(current []string) ([]string, error) {
		var next []string
		next, changed = config.NormalizeLegacyAPITokens(current)
		return next, nil
	})
	if err != nil {
		return 0, err
	}
	return changed, nil
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
	pending := restartRequiredFields(cfg, s.runtime)
	writeJSON(w, map[string]any{
		"status":                 "ok",
		"site":                   cfg.Site,
		"version":                s.d.Version,
		"uptime_seconds":         int(time.Since(s.d.StartTime).Seconds()),
		"active_sessions":        s.d.Sessions.ActiveCount(),
		"advertise_ip":           s.d.AdvertiseIP,
		"http_base":              s.d.HTTPBase,
		"dhcp_mode":              string(s.runtime.Network.DHCPMode),
		"tftp_port":              s.runtime.Network.TFTPPort,
		"http_port":              s.runtime.Network.HTTPPort,
		"iscsi_port":             s.runtime.Network.ISCSIPort,
		"iscsi_enabled":          s.runtime.ISCSIActive(),
		"restart_required":       len(pending) > 0,
		"pending_restart_fields": pending,
		"auth_configured":        cfg.Auth.AdminPasswordHash != "" || len(cfg.Auth.APITokens) > 0,
	})
}

func restartRequiredFields(current, runtimeCfg *config.Config) []string {
	if current == nil || runtimeCfg == nil {
		return nil
	}
	var fields []string
	add := func(changed bool, name string) {
		if changed {
			fields = append(fields, name)
		}
	}
	a, b := current.Network, runtimeCfg.Network
	add(a.DHCPMode != b.DHCPMode, "network.dhcp_mode")
	add(a.Interface != b.Interface, "network.interface")
	add(a.AdvertiseIP != b.AdvertiseIP, "network.advertise_ip")
	add(a.TFTPPort != b.TFTPPort, "network.tftp_port")
	add(a.HTTPPort != b.HTTPPort, "network.http_port")
	add(a.HTTPMaxStreams != b.HTTPMaxStreams, "network.http_max_streams")
	add(a.HTTPMaxStreamsPerIP != b.HTTPMaxStreamsPerIP, "network.http_max_streams_per_ip")
	add(a.DashboardBind != b.DashboardBind, "network.dashboard_bind")
	add(a.DashboardTLSCert != b.DashboardTLSCert, "network.dashboard_tls_cert")
	add(a.DashboardTLSKey != b.DashboardTLSKey, "network.dashboard_tls_key")
	add(a.ISCSIPort != b.ISCSIPort, "network.iscsi_port")
	add(current.ISCSIActive() != runtimeCfg.ISCSIActive(), "network.iscsi_enabled")
	add(a.ISCSIMaxConnections != b.ISCSIMaxConnections, "network.iscsi_max_connections")
	add(a.ISCSIMaxConnectionsPerIP != b.ISCSIMaxConnectionsPerIP, "network.iscsi_max_connections_per_ip")
	add(current.Images.Dir != runtimeCfg.Images.Dir, "images.dir")
	add(current.Images.AnswersDir != runtimeCfg.Images.AnswersDir, "images.answers_dir")
	add(current.Sessions.DBPath != runtimeCfg.Sessions.DBPath, "sessions.db_path")
	add(current.Sessions.RetentionDays != runtimeCfg.Sessions.RetentionDays, "sessions.retention_days")
	add(current.Sessions.MaxSizeMB != runtimeCfg.Sessions.MaxSizeMB, "sessions.max_size_mb")
	return fields
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
