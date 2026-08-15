package httpsrv

// Management endpoints (ADR-0004): every write below mutates the config file
// or a file in answers/ — validated, atomic, hot-reloaded. Nothing is stored
// anywhere the file system can't show.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"emberboot/internal/bootfiles"
	"emberboot/internal/config"
	"emberboot/internal/images"
)

const maxAnswerFileSize int64 = 4 << 20

func (s *APIServer) registerManagement(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/config/full", s.auth(s.handleConfigFull))
	mux.HandleFunc("GET /api/config/raw", s.auth(s.handleConfigRawGet))
	mux.HandleFunc("PUT /api/config/raw", s.auth(s.handleConfigRawPut))
	mux.HandleFunc("PATCH /api/config", s.auth(s.handleConfigPatch))
	mux.HandleFunc("GET /api/answers", s.auth(s.handleAnswersList))
	mux.HandleFunc("GET /api/answers/{name}", s.auth(s.handleAnswerGet))
	mux.HandleFunc("PUT /api/answers/{name}", s.auth(s.handleAnswerPut))
	mux.HandleFunc("DELETE /api/answers/{name}", s.auth(s.handleAnswerDelete))
	mux.HandleFunc("POST /api/auth/password", s.auth(s.handleSetPassword))
	mux.HandleFunc("GET /api/auth/tokens", s.auth(s.handleTokensList))
	mux.HandleFunc("POST /api/auth/tokens", s.auth(s.handleTokenCreate))
	mux.HandleFunc("DELETE /api/auth/tokens/{index}", s.auth(s.handleTokenDelete))
	mux.HandleFunc("GET /api/logs", s.auth(s.handleLogs))
	mux.HandleFunc("GET /api/diagnostics", s.auth(s.handleDiagnostics))
}

func badRequest(w http.ResponseWriter, err error) {
	writeJSONStatus(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
}

func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func requireJSONBody(w http.ResponseWriter, r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return false
	}
	return true
}

// --- config ---

func (s *APIServer) handleConfigFull(w http.ResponseWriter, r *http.Request) {
	doc, err := s.d.Cfg.Redacted()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg := s.d.Cfg.Current()
	writeJSON(w, map[string]any{
		"config":       doc,
		"has_password": cfg.Auth.AdminPasswordHash != "",
		"token_count":  len(cfg.Auth.APITokens),
	})
}

func (s *APIServer) handleConfigRawGet(w http.ResponseWriter, r *http.Request) {
	data, err := s.d.Cfg.RawBytes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (s *APIServer) handleConfigRawPut(w http.ResponseWriter, r *http.Request) {
	if !requireJSONBody(w, r) {
		return
	}
	var body struct {
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		badRequest(w, err)
		return
	}
	if err := s.d.Cfg.SaveRaw([]byte(body.YAML)); err != nil {
		badRequest(w, err)
		return
	}
	s.d.Log.Info("config saved from management UI (raw editor)")
	writeJSON(w, map[string]any{"ok": true})
}

func (s *APIServer) handleConfigPatch(w http.ResponseWriter, r *http.Request) {
	if !requireJSONBody(w, r) {
		return
	}
	var body struct {
		Ops []config.PatchOp `json:"ops"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		badRequest(w, err)
		return
	}
	if len(body.Ops) == 0 {
		badRequest(w, fmt.Errorf("no operations"))
		return
	}
	if err := s.d.Cfg.Patch(body.Ops); err != nil {
		badRequest(w, err)
		return
	}
	s.d.Log.Info("config saved from management UI", "ops", len(body.Ops))
	writeJSON(w, map[string]any{"ok": true})
}

// --- answer files ---

var answerNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func (s *APIServer) answerPath(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := r.PathValue("name")
	if !answerNameRe.MatchString(name) || name == "." || name == ".." {
		badRequest(w, fmt.Errorf("answer file names may only use letters, digits, dot, dash, underscore"))
		return "", false
	}
	return filepath.Join(s.runtime.Images.AnswersDir, name), true
}

func (s *APIServer) handleAnswersList(w http.ResponseWriter, r *http.Request) {
	dir := s.runtime.Images.AnswersDir
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type row struct {
		Name    string    `json:"name"`
		Size    int64     `json:"size"`
		ModTime time.Time `json:"mod_time"`
	}
	out := []row{}
	for _, e := range entries {
		if e.IsDir() || e.Type()&os.ModeSymlink != 0 {
			continue
		}
		if fi, err := e.Info(); err == nil && fi.Mode().IsRegular() && fi.Size() <= maxAnswerFileSize {
			out = append(out, row{e.Name(), fi.Size(), fi.ModTime()})
		}
	}
	writeJSON(w, out)
}

func (s *APIServer) handleAnswerGet(w http.ResponseWriter, r *http.Request) {
	p, ok := s.answerPath(w, r)
	if !ok {
		return
	}
	data, code := readPrivateFile(p, maxAnswerFileSize)
	if code != http.StatusOK {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (s *APIServer) handleAnswerPut(w http.ResponseWriter, r *http.Request) {
	p, ok := s.answerPath(w, r)
	if !ok {
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxAnswerFileSize+1))
	if err != nil {
		badRequest(w, err)
		return
	}
	if int64(len(data)) > maxAnswerFileSize {
		badRequest(w, fmt.Errorf("answer file exceeds 4 MiB"))
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := writeAtomicPrivate(p, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.d.Log.Info("answer file saved from management UI", "file", filepath.Base(p))
	writeJSON(w, map[string]any{"ok": true})
}

func readPrivateFile(path string, limit int64) ([]byte, int) {
	f, err := os.Open(path)
	if err != nil {
		return nil, http.StatusNotFound
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > limit {
		return nil, http.StatusNotFound
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(fi, pathInfo) {
		return nil, http.StatusNotFound
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, http.StatusNotFound
	}
	return data, http.StatusOK
}

// writeAtomicPrivate prevents boot clients from observing a partially saved
// answer file and keeps deployment credentials private from local users.
func writeAtomicPrivate(path string, data []byte) (retErr error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".emberboot-answer-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		_ = f.Close()
		if retErr != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncAnswerDir(dir)
}

func syncAnswerDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (s *APIServer) handleAnswerDelete(w http.ResponseWriter, r *http.Request) {
	p, ok := s.answerPath(w, r)
	if !ok {
		return
	}
	if err := os.Remove(p); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := syncAnswerDir(filepath.Dir(p)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.d.Log.Info("answer file deleted from management UI", "file", filepath.Base(p))
	writeJSON(w, map[string]any{"ok": true})
}

// --- auth management ---

func (s *APIServer) handleSetPassword(w http.ResponseWriter, r *http.Request) {
	if !requireJSONBody(w, r) {
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		badRequest(w, err)
		return
	}
	if len(body.Password) < 12 {
		badRequest(w, fmt.Errorf("password must be at least 12 characters"))
		return
	}
	if len(body.Password) > 72 {
		badRequest(w, fmt.Errorf("password must be at most 72 UTF-8 bytes"))
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.d.Cfg.Patch([]config.PatchOp{{Path: []string{"auth", "admin_password_hash"}, Value: string(hash)}}); err != nil {
		badRequest(w, err)
		return
	}
	s.d.Log.Info("admin password set from management UI")
	writeJSON(w, map[string]any{"ok": true})
}

func maskToken(t string) string {
	if len(t) > len(apiTokenHashPrefix) && t[:len(apiTokenHashPrefix)] == apiTokenHashPrefix {
		parts := strings.Split(t, ":")
		if len(parts) == 3 && parts[1] != "" {
			return parts[1] + "…"
		}
		return "hashed credential"
	}
	if len(t) <= 8 {
		return "••••"
	}
	return t[:4] + "…" + t[len(t)-4:]
}

func (s *APIServer) handleTokensList(w http.ResponseWriter, r *http.Request) {
	type row struct {
		Index int    `json:"index"`
		Hint  string `json:"hint"`
	}
	out := []row{}
	for i, t := range s.d.Cfg.Current().Auth.APITokens {
		out = append(out, row{i, maskToken(t)})
	}
	writeJSON(w, out)
}

func (s *APIServer) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	if s.d.Cfg.Current().Auth.AdminPasswordHash == "" {
		badRequest(w, fmt.Errorf("set an admin password before creating API tokens"))
		return
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	token := "eb_" + hex.EncodeToString(buf)
	if err := s.d.Cfg.UpdateAPITokens(func(current []string) ([]string, error) {
		return append(current, APITokenRecord(token)), nil
	}); err != nil {
		badRequest(w, err)
		return
	}
	s.d.Log.Info("API token created from management UI")
	// Shown once; only the masked hint is retrievable afterwards.
	writeJSON(w, map[string]any{"ok": true, "token": token})
}

func (s *APIServer) handleTokenDelete(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.PathValue("index"))
	snapshot := s.d.Cfg.Current().Auth.APITokens
	if err != nil || idx < 0 || idx >= len(snapshot) {
		badRequest(w, fmt.Errorf("no such token"))
		return
	}
	wanted := snapshot[idx]
	if err := s.d.Cfg.UpdateAPITokens(func(current []string) ([]string, error) {
		for i, token := range current {
			if token == wanted {
				return append(current[:i:i], current[i+1:]...), nil
			}
		}
		return nil, fmt.Errorf("no such token")
	}); err != nil {
		badRequest(w, err)
		return
	}
	s.d.Log.Info("API token revoked from management UI", "index", idx)
	writeJSON(w, map[string]any{"ok": true})
}

// --- logs ---

func (s *APIServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	if s.d.LogRing == nil {
		writeJSON(w, []any{})
		return
	}
	level := slog.LevelInfo
	switch r.URL.Query().Get("level") {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	limit := 300
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 1000 {
		limit = v
	}
	writeJSON(w, s.d.LogRing.Records(level, limit))
}

// --- diagnostics ---

// Check is one self-test result.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pass | warn | fail
	Detail string `json:"detail"`
}

func (s *APIServer) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	cfg := s.d.Cfg.Current()
	runtimeCfg := s.runtime
	var checks []Check
	add := func(name, status, detail string) { checks = append(checks, Check{name, status, detail}) }

	// Config file state.
	if st := s.d.Cfg.Status(); st.Rejected != "" {
		add("Config file", "fail", "Latest edit was rejected; serving last known good: "+st.Rejected)
	} else {
		add("Config file", "pass", "Valid and serving")
	}
	if pending := restartRequiredFields(cfg, runtimeCfg); len(pending) > 0 {
		add("Pending restart", "warn", "Saved but not active until restart: "+strings.Join(pending, ", "))
	}

	// Advertise IP still present on an interface.
	if ipPresent(s.d.AdvertiseIP) {
		add("Advertised IP", "pass", s.d.AdvertiseIP+" is present on a network interface")
	} else {
		add("Advertised IP", "fail", s.d.AdvertiseIP+" is not on any interface — clients are being told to fetch from an address this host no longer has; set network.advertise_ip and restart")
	}

	// Boot HTTP reachable (loopback self-request).
	client := &http.Client{Timeout: 3 * time.Second}
	if resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", runtimeCfg.Network.HTTPPort)); err == nil && resp.StatusCode == 200 {
		resp.Body.Close()
		add("Boot HTTP", "pass", fmt.Sprintf("Serving on port %d", runtimeCfg.Network.HTTPPort))
	} else {
		add("Boot HTTP", "fail", fmt.Sprintf("No response on port %d — boot payloads cannot be served", runtimeCfg.Network.HTTPPort))
	}

	// TFTP: real RRQ probe for the generated autoexec script.
	if err := tftpProbe(runtimeCfg.Network.TFTPPort); err != nil {
		add("TFTP", "fail", fmt.Sprintf("Probe of port %d failed: %v — clients cannot fetch the iPXE bootloader", runtimeCfg.Network.TFTPPort, err))
	} else {
		add("TFTP", "pass", fmt.Sprintf("Served %s over port %d", bootfiles.FileAutoexec, runtimeCfg.Network.TFTPPort))
	}

	// iSCSI target (virtual CDs for the long-tail ISOs). An empty ACL is a
	// deliberate secure default, not a healthy client-facing service.
	if !runtimeCfg.ISCSIActive() {
		add("iSCSI target", "pass", "Disabled; no TCP listener is exposed")
	} else if c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", runtimeCfg.Network.ISCSIPort), 3*time.Second); err == nil {
		c.Close()
		add("iSCSI target", "pass", fmt.Sprintf("Listening on port %d; source ACL contains %d subnet(s)", runtimeCfg.Network.ISCSIPort, len(cfg.Security.ISCSIAllowedSubnets)))
	} else {
		add("iSCSI target", "fail", fmt.Sprintf("Not accepting on port %d — virtual-CD boots will fail", runtimeCfg.Network.ISCSIPort))
	}

	// DHCP responder.
	if s.d.RogueActive != nil && s.d.RogueActive() {
		add("Rogue PXE detection", "pass", "Passively monitoring udp/68 for other PXE servers")
	} else {
		add("Rogue PXE detection", "warn", "Disabled — udp/68 is held by another process (usually a DHCP client daemon); rogue servers will not be detected")
	}

	// Disk space.
	activeImagesDir := s.d.Images.ActiveDir()
	if free, err := images.DiskFreeGB(activeImagesDir); err != nil {
		add("Disk space", "warn", "Could not check free space: "+err.Error())
	} else if free < float64(cfg.Images.MinFreeGB) {
		add("Disk space", "fail", fmt.Sprintf("%.1f GB free on the image volume (threshold %d GB)", free, cfg.Images.MinFreeGB))
	} else {
		add("Disk space", "pass", fmt.Sprintf("%.1f GB free on the image volume", free))
	}

	// Folder writability.
	for _, d := range []struct{ name, dir string }{{"Images folder", activeImagesDir}, {"Answers folder", runtimeCfg.Images.AnswersDir}} {
		if err := writable(d.dir); err != nil {
			add(d.name, "fail", d.dir+": "+err.Error())
		} else {
			add(d.name, "pass", d.dir+" is writable")
		}
	}

	// Session store.
	if err := s.d.Sessions.Ping(); err != nil {
		add("Session history", "warn", "Database not readable ("+err.Error()+") — booting is unaffected, history is not being recorded")
	} else {
		add("Session history", "pass", "Database readable and recording")
	}

	// Auth.
	if cfg.Auth.AdminPasswordHash != "" || len(cfg.Auth.APITokens) > 0 {
		add("Console sign-in", "pass", "Password or API token required")
	} else {
		add("Console sign-in", "warn", "Local bootstrap only — set an admin password before exposing the management listener")
	}
	if runtimeCfg.Network.DashboardTLSCert != "" {
		add("Console transport", "pass", "HTTPS certificate and key configured")
	} else {
		add("Console transport", "warn", "HTTP is permitted only on loopback; configure TLS before binding to a management VLAN")
	}

	writeJSON(w, map[string]any{"checks": checks, "ran_at": time.Now()})
}

func ipPresent(ip string) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.String() == ip {
			return true
		}
	}
	return false
}

func writable(dir string) error {
	f, err := os.CreateTemp(dir, ".diag-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// tftpProbe performs a minimal real TFTP read of autoexec.ipxe against
// loopback: RRQ → DATA(1) → ACK(1). Proves the listener is alive end to end.
// The socket must be unconnected: TFTP servers reply from an ephemeral port,
// not from port 69.
func tftpProbe(port int) error {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer pc.Close()
	// RRQ: opcode 1 | filename | 0 | "octet" | 0
	rrq := append([]byte{0, 1}, bootfiles.FileAutoexec...)
	rrq = append(rrq, 0)
	rrq = append(rrq, "octet"...)
	rrq = append(rrq, 0)
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	if _, err := pc.WriteToUDP(rrq, dst); err != nil {
		return err
	}
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, peer, err := pc.ReadFromUDP(buf)
	if err != nil {
		return fmt.Errorf("no DATA reply: %w", err)
	}
	if n < 4 || buf[1] != 3 {
		return fmt.Errorf("unexpected reply opcode %d", buf[1])
	}
	// ACK block 1 so the server ends the transfer cleanly.
	_, _ = pc.WriteToUDP([]byte{0, 4, buf[2], buf[3]}, peer)
	return nil
}
