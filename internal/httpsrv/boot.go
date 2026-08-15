// Package httpsrv implements Emberboot's two HTTP servers:
//
//   - the boot server (this file): unauthenticated, reachable from every
//     client VLAN, serves iPXE scripts and all boot payloads (ADR-0001);
//   - the dashboard/API server (api.go): authenticated, bindable to a
//     management VLAN.
package httpsrv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"emberboot/internal/bootfiles"
	"emberboot/internal/config"
	"emberboot/internal/images"
	"emberboot/internal/metrics"
	"emberboot/internal/rules"
	"emberboot/internal/sessions"
)

// BootDeps wires the boot server.
type BootDeps struct {
	Log      *slog.Logger
	Cfg      func() *config.Config
	Images   *images.Manager
	Metrics  *metrics.M
	Sessions *sessions.Store
	// GrantKey is a persistent 32-byte HMAC key. Keeping it in state makes
	// stage-two installer URLs survive daemon restarts and upgrades.
	GrantKey []byte
	// Restart-bound values are captured at process startup. Hot edits remain
	// visible as pending config but must not redirect clients to listeners or
	// answer directories which have not actually moved yet.
	RuntimeISCSIPort           int
	RuntimeISCSIEnabled        *bool
	RuntimeAnswersDir          string
	RuntimeHTTPMaxStreams      int
	RuntimeHTTPMaxStreamsPerIP int
}

// BootServer is the client-facing HTTP server.
type BootServer struct {
	d             BootDeps
	srv           *http.Server
	grantKey      []byte
	streamMu      sync.Mutex
	activeStreams int
	streamsByIP   map[string]int
	connMu        sync.Mutex
	connections   map[net.Conn]string
	connsByIP     map[string]int
	limitLogAfter time.Time
	limitHidden   uint64
	answerMu      sync.Mutex
	answerDigests map[string]answerDigestEntry
	answerReader  func(string) ([]byte, os.FileInfo, int)
}

type answerDigestEntry struct {
	info     os.FileInfo
	digest   string
	lastUsed time.Time
}

const maxAnswerDigestEntries = 256

// NewBoot builds the boot server for addr (e.g. ":8090").
func NewBoot(d BootDeps, addr string) (*BootServer, error) {
	if len(d.GrantKey) != 32 {
		return nil, fmt.Errorf("boot authorization key must be exactly 32 bytes")
	}
	if d.RuntimeHTTPMaxStreams <= 0 {
		d.RuntimeHTTPMaxStreams = 600
	}
	if d.RuntimeHTTPMaxStreamsPerIP <= 0 {
		d.RuntimeHTTPMaxStreamsPerIP = 8
	}
	s := &BootServer{
		d: d, grantKey: append([]byte(nil), d.GrantKey...),
		streamsByIP: make(map[string]int),
		connections: make(map[net.Conn]string), connsByIP: make(map[string]int),
		answerDigests: make(map[string]answerDigestEntry),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /boot.ipxe", s.handleBootStub)
	mux.HandleFunc("GET /menu.ipxe", s.handleMenu)
	mux.HandleFunc("GET /boot/{file}", s.handleBootFile)
	// Signed path form used by generated scripts. The legacy routes remain
	// registered so stale clients receive a clear 403 instead of a 404.
	mux.HandleFunc("GET /g/{grant}/iso/{name}", s.handleISO)
	mux.HandleFunc("GET /g/{grant}/img/{name}/boot.ipxe", s.handleImageScript)
	mux.HandleFunc("GET /g/{grant}/img/{name}/file/{path...}", s.handleISOFile)
	mux.HandleFunc("GET /g/{grant}/img/{name}/winpeshl.ini", s.handleWinpeshl)
	mux.HandleFunc("GET /g/{grant}/img/{name}/install.bat", s.handleInstallBat)
	mux.HandleFunc("GET /g/{grant}/answers/{file}", s.handleAnswer)
	mux.HandleFunc("GET /g/{grant}/seed/{file}/{leaf}", s.handleSeed)
	mux.HandleFunc("GET /iso/{name}", s.handleISO)
	mux.HandleFunc("GET /img/{name}/boot.ipxe", s.handleImageScript)
	mux.HandleFunc("GET /img/{name}/file/{path...}", s.handleISOFile)
	mux.HandleFunc("GET /img/{name}/winpeshl.ini", s.handleWinpeshl)
	mux.HandleFunc("GET /img/{name}/install.bat", s.handleInstallBat)
	mux.HandleFunc("GET /answers/{file}", s.handleAnswer)
	mux.HandleFunc("GET /seed/{file}/{leaf}", s.handleSeed)
	s.srv = &http.Server{
		Addr:              addr,
		Handler:           rejectBootRequestBody(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		MaxHeaderBytes:    64 << 10,
		// No WriteTimeout: a 6GB install.wim to 300 clients takes as long as
		// it takes. Idle and header timeouts still bound abuse.
		IdleTimeout: 2 * time.Minute,
		ConnState:   s.connectionState,
	}
	return s, nil
}

// Boot endpoints are GET-only and never need a request body. Rejecting one
// before routing, closing the connection, and retaining a finite ReadTimeout
// prevents a stalled chunked body from occupying a connection-admission slot.
func rejectBootRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
			r.Close = true
			w.Header().Set("Connection", "close")
			http.Error(w, "boot requests must not include a body", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *BootServer) Serve() error {
	ln, err := net.Listen("tcp4", s.srv.Addr)
	if err != nil {
		return err
	}
	return serverResult(s.srv.Serve(ln))
}

// Close stops accepting new boot requests and gives active payload streams up
// to four minutes to finish before forcing them closed. The supplied systemd
// unit allows a slightly longer stop window.
func (s *BootServer) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if err := s.srv.Shutdown(ctx); err != nil {
		_ = s.srv.Close()
	}
}

// --- helpers ---

// base returns the absolute URL prefix the client used, for kernel args that
// the booted OS (not iPXE) will fetch.
func base(r *http.Request) string {
	return "http://" + r.Host
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// identity uses the connection address and Emberboot's DHCP observation as
// authority. iPXE query parameters are intentionally not trusted: a client
// can write them itself. In options-66/67 mode, subnet rules still work, but
// MAC targeting requires Emberboot to have observed the client's DHCP flow.
func (s *BootServer) identity(r *http.Request) (net.HardwareAddr, net.IP, string) {
	connIP := clientIP(r)
	var mac net.HardwareAddr
	if s.d.Sessions != nil {
		if known := s.d.Sessions.MACForIP(connIP); known != "" {
			mac, _ = net.ParseMAC(known)
		}
	}
	return mac, net.ParseIP(connIP), connIP
}

// track records a session event, preferring MAC identity.
func (s *BootServer) track(r *http.Request, stage, detail string) int64 {
	_, _, connIP := s.identity(r)
	return s.d.Sessions.TouchByIP(connIP, stage, detail)
}

func (s *BootServer) trackGrant(r *http.Request, grant bootGrant, stage, detail string) int64 {
	if grant.Session != 0 {
		s.d.Sessions.TouchID(grant.Session, grant.IP, stage, detail)
		return grant.Session
	}
	return s.track(r, stage, detail)
}

func (s *BootServer) count(kind string, code int) {
	s.d.Metrics.HTTPRequests.WithLabelValues(kind, strconv.Itoa(code)).Inc()
}

func (s *BootServer) scriptConfig() *config.Config {
	runtimeCfg := *s.d.Cfg()
	if s.d.RuntimeISCSIPort != 0 {
		runtimeCfg.Network.ISCSIPort = s.d.RuntimeISCSIPort
	}
	if s.d.RuntimeISCSIEnabled != nil {
		enabled := *s.d.RuntimeISCSIEnabled
		runtimeCfg.Network.ISCSIEnabled = &enabled
		if !enabled {
			runtimeCfg.Security.ISCSIAllowedSubnets = nil
		}
	}
	return &runtimeCfg
}

func (s *BootServer) acquireStream(ip string) bool {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	if s.activeStreams >= s.d.RuntimeHTTPMaxStreams ||
		s.streamsByIP[ip] >= s.d.RuntimeHTTPMaxStreamsPerIP {
		s.admissionRejected("stream")
		return false
	}
	s.activeStreams++
	s.streamsByIP[ip]++
	return true
}

func (s *BootServer) connectionState(conn net.Conn, state http.ConnState) {
	s.connMu.Lock()
	switch state {
	case http.StateNew:
		ip := remoteIP(conn.RemoteAddr())
		if len(s.connections) >= s.d.RuntimeHTTPMaxStreams ||
			s.connsByIP[ip] >= s.d.RuntimeHTTPMaxStreamsPerIP {
			s.connMu.Unlock()
			s.admissionRejected("connection")
			_ = conn.Close()
			return
		}
		s.connections[conn] = ip
		s.connsByIP[ip]++
	case http.StateHijacked, http.StateClosed:
		if ip, ok := s.connections[conn]; ok {
			delete(s.connections, conn)
			s.connsByIP[ip]--
			if s.connsByIP[ip] == 0 {
				delete(s.connsByIP, ip)
			}
		}
	}
	s.connMu.Unlock()
}

func remoteIP(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil && host != "" {
		return host
	}
	return addr.String()
}

func (s *BootServer) admissionRejected(resource string) {
	if s.d.Metrics != nil && s.d.Metrics.BootAdmissionRejected != nil {
		s.d.Metrics.BootAdmissionRejected.WithLabelValues(resource).Inc()
	}
	if s.d.Log == nil {
		return
	}
	now := time.Now()
	s.connMu.Lock()
	if now.Before(s.limitLogAfter) {
		s.limitHidden++
		s.connMu.Unlock()
		return
	}
	hidden := s.limitHidden
	s.limitHidden = 0
	s.limitLogAfter = now.Add(30 * time.Second)
	s.connMu.Unlock()
	s.d.Log.Warn("boot HTTP capacity limit reached", "resource", resource, "suppressed_since_last", hidden)
}

func (s *BootServer) releaseStream(ip string) {
	s.streamMu.Lock()
	if s.activeStreams > 0 {
		s.activeStreams--
	}
	if s.streamsByIP[ip] <= 1 {
		delete(s.streamsByIP, ip)
	} else {
		s.streamsByIP[ip]--
	}
	s.streamMu.Unlock()
}

func (s *BootServer) admitStream(w http.ResponseWriter, r *http.Request, kind string) bool {
	ip := clientIP(r)
	if !s.acquireStream(ip) {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "boot payload capacity reached; retry shortly", http.StatusServiceUnavailable)
		s.count(kind, http.StatusServiceUnavailable)
		return false
	}
	return true
}

// deny enforces Override deny/lockdown on every boot-path endpoint.
func (s *BootServer) denied(w http.ResponseWriter, r *http.Request, kind string) bool {
	mac, ip, _ := s.identity(r)
	dec := rules.Evaluate(s.d.Cfg(), mac, ip)
	if dec.Deny {
		http.Error(w, "boot service denied", http.StatusForbidden)
		s.count(kind, http.StatusForbidden)
		return true
	}
	return false
}

func writeScript(w http.ResponseWriter, script string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, script)
}

// countingWriter measures payload bytes to detect fully-served payloads.
type countingWriter struct {
	http.ResponseWriter
	n    int64
	code int
}

func (c *countingWriter) WriteHeader(code int) {
	c.code = code
	c.ResponseWriter.WriteHeader(code)
}

func (c *countingWriter) Write(p []byte) (int, error) {
	if c.code == 0 {
		c.code = http.StatusOK
	}
	n, err := c.ResponseWriter.Write(p)
	c.n += int64(n)
	return n, err
}

// ReadFrom preserves net/http's optimized file-to-socket path (sendfile on
// supported platforms) while still counting payload bytes. Without this,
// wrapping ResponseWriter forces every multi-gigabyte ISO through a 32 KiB
// userspace copy loop.
func (c *countingWriter) ReadFrom(r io.Reader) (int64, error) {
	if c.code == 0 {
		c.code = http.StatusOK
	}
	var (
		n   int64
		err error
	)
	if rf, ok := c.ResponseWriter.(io.ReaderFrom); ok {
		n, err = rf.ReadFrom(r)
	} else {
		n, err = io.Copy(c.ResponseWriter, r)
	}
	c.n += n
	return n, err
}

func (c *countingWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// --- handlers ---

func (s *BootServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, "ok")
}

func (s *BootServer) handleBootStub(w http.ResponseWriter, r *http.Request) {
	if s.denied(w, r, "script") {
		return
	}
	s.track(r, "script", "fetched boot stub")
	writeScript(w, bootStub())
	s.count("script", http.StatusOK)
}

func (s *BootServer) handleMenu(w http.ResponseWriter, r *http.Request) {
	if s.denied(w, r, "script") {
		return
	}
	mac, ip, connIP := s.identity(r)
	decision := rules.Evaluate(s.d.Cfg(), mac, ip)
	sessionID := s.track(r, "script", "fetched boot menu")
	grantFor := func(img images.Image) string {
		expires := time.Now().Add(s.grantTTL())
		answer := effectiveAnswer(img, decision.AnswerFile)
		answerDigest := ""
		if answer != "" {
			var code int
			answerDigest, code = s.answerDigest(answer)
			if code != http.StatusOK {
				s.d.Log.Warn("could not read assigned answer file for boot grant", "image", img.FileName, "answer", answer)
				return ""
			}
		}
		if !s.d.Images.PinVersion(img.FileName, img.SHA256, expires) {
			s.d.Log.Warn("could not pin image generation for boot grant", "image", img.FileName)
			return ""
		}
		grant, err := s.signGrant(bootGrant{
			Expires: expires.Unix(), IP: connIP, MAC: strings.ToLower(mac.String()), Image: img.FileName,
			Digest: img.SHA256,
			Answer: answer, AnswerDigest: answerDigest,
			Session: sessionID,
		})
		if err != nil {
			s.d.Log.Error("could not issue boot grant", "image", img.FileName, "error", err)
			return ""
		}
		return grant
	}
	writeScript(w, menuScript(s.scriptConfig(), s.d.Images.List(), mac, ip, grantFor))
	s.count("script", http.StatusOK)
}

// handleBootFile serves embedded binaries (wimboot; iPXE for UEFI HTTP Boot).
func (s *BootServer) handleBootFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	data, ok := bootfiles.Get(name)
	if !ok {
		http.NotFound(w, r)
		s.count("bootfile", http.StatusNotFound)
		return
	}
	ip := clientIP(r)
	if !s.acquireStream(ip) {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "boot server is at transfer capacity; retry shortly", http.StatusServiceUnavailable)
		s.count("bootfile", http.StatusServiceUnavailable)
		return
	}
	defer s.releaseStream(ip)
	s.track(r, "payload", "fetched "+name)
	cw := &countingWriter{ResponseWriter: w}
	http.ServeContent(cw, r, name, time.Time{}, bytes.NewReader(data))
	code := cw.code
	if code == 0 {
		code = http.StatusOK
	}
	s.count("bootfile", code)
}

func (s *BootServer) handleImageScript(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	grant, ok := s.requireGrant(w, r, "script", name, "")
	if !ok {
		return
	}
	img, ok := s.d.Images.GetVersion(name, grant.Digest)
	if !ok {
		http.Error(w, "image version changed; restart this boot", http.StatusConflict)
		s.count("script", http.StatusConflict)
		return
	}
	mac, ip := grant.mac(), net.ParseIP(grant.IP)
	s.trackGrant(r, grant, "script", "selected "+img.DisplayName)
	if grant.Session != 0 {
		s.d.Sessions.SetMetaID(grant.Session, "", img.FileName, string(img.Strategy))
	} else if mac != nil {
		s.d.Sessions.SetMeta(mac.String(), "", img.FileName, string(img.Strategy))
	}
	memMB, _ := strconv.Atoi(r.URL.Query().Get("mem"))
	writeScript(w, imageScript(s.scriptConfig(), img, mac, ip, base(r), memMB, grantToken(r)))
	s.count("script", http.StatusOK)
}

func (s *BootServer) handleISO(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	grant, ok := s.requireGrant(w, r, "iso", name, "")
	if !ok {
		return
	}
	if !s.admitStream(w, r, "iso") {
		return
	}
	defer s.releaseStream(clientIP(r))
	f, img, err := s.d.Images.OpenRawVersion(name, grant.Digest)
	if err != nil {
		http.Error(w, "image version changed; restart this boot", http.StatusConflict)
		s.count("iso", http.StatusConflict)
		return
	}
	defer f.Close()
	sessionID := s.trackGrant(r, grant, "payload", "downloading ISO "+name)
	w.Header().Set("Cache-Control", "private, no-store")
	cw := &countingWriter{ResponseWriter: w}
	http.ServeContent(cw, r, name, img.ModTime, f)
	s.d.Metrics.HTTPPayloadBytes.Add(float64(cw.n))
	s.count("iso", cw.code)
	if cw.code == http.StatusPartialContent && cw.n > 0 {
		s.finishHandoff(sessionID, fmt.Sprintf("HTTP SAN media %s is being read (%d-byte range); OS boot not confirmed", name, cw.n))
	} else {
		s.finishIfComplete(sessionID, cw.code, img, name, cw.n, img.SizeBytes)
	}
}

func (s *BootServer) handleISOFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	grant, ok := s.requireGrant(w, r, "isofile", name, "")
	if !ok {
		return
	}
	if !s.admitStream(w, r, "isofile") {
		return
	}
	defer s.releaseStream(clientIP(r))
	inside := r.PathValue("path")
	if !safeISOPath(inside) {
		http.Error(w, "bad path", http.StatusBadRequest)
		s.count("isofile", http.StatusBadRequest)
		return
	}
	rs, size, mod, img, err := s.d.Images.OpenInsideVersion(name, grant.Digest, inside)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		s.count("isofile", http.StatusNotFound)
		return
	}
	defer rs.Close()
	sessionID := s.trackGrant(r, grant, "payload", fmt.Sprintf("fetching %s from %s", inside, name))
	w.Header().Set("Cache-Control", "private, no-store")
	cw := &countingWriter{ResponseWriter: w}
	http.ServeContent(cw, r, path.Base(inside), mod, rs)
	s.d.Metrics.HTTPPayloadBytes.Add(float64(cw.n))
	s.count("isofile", cw.code)
	if isFinalPayload(img, inside) {
		s.finishIfComplete(sessionID, cw.code, img, inside, cw.n, size)
	}
}

// finishIfComplete records a transport handoff when the decisive payload was
// served in full (not a partial range). It makes no claim that the OS boot or
// installation succeeded after Emberboot handed over control.
func (s *BootServer) finishIfComplete(sessionID int64, code int, img images.Image, what string, served, total int64) {
	if code != http.StatusOK || served != total {
		return
	}
	s.finishHandoff(sessionID, fmt.Sprintf("payload %s fully delivered (%d bytes); handing off to the OS", what, total))
}

func (s *BootServer) finishHandoff(sessionID int64, detail string) {
	s.d.Sessions.FinishID(sessionID, sessions.ResultHandoff, detail)
}

// isFinalPayload identifies the transport milestone after which Emberboot has
// handed control to the client-side boot stack.
func isFinalPayload(img images.Image, inside string) bool {
	l := strings.ToLower(inside)
	switch {
	case strings.HasSuffix(l, "filesystem.squashfs"), strings.HasSuffix(l, "airootfs.sfs"):
		return true // live families: rootfs loaded
	case strings.HasSuffix(l, "install.wim"), strings.HasSuffix(l, "install.esd"):
		return true // windows: sources delivered
	case strings.HasSuffix(l, "boot.wim") && img.Plan.Files["install"] == "":
		return true // windows without injected sources: WinPE is the payload
	case strings.HasSuffix(l, "images/install.img"):
		return true // anaconda stage2
	}
	return false
}

func (s *BootServer) handleWinpeshl(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, ok := s.requireGrant(w, r, "script", name, ""); !ok {
		return
	}
	writeScript(w, winpeshlINI)
	s.count("script", http.StatusOK)
}

func (s *BootServer) handleInstallBat(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	grant, ok := s.requireGrant(w, r, "script", name, "")
	if !ok {
		return
	}
	img, ok := s.d.Images.GetVersion(name, grant.Digest)
	installFile := ""
	if ok && img.Plan.Files["install"] != "" {
		installFile = installName(img.Plan.Files["install"])
	}
	hasAnswer := r.URL.Query().Get("answer") == "true"
	writeScript(w, installBAT(installFile, hasAnswer))
	s.count("script", http.StatusOK)
}

// handleAnswer serves an Answer File with trivial substitution.
func (s *BootServer) handleAnswer(w http.ResponseWriter, r *http.Request) {
	answerName := r.PathValue("file")
	grant, err := s.verifyGrant(grantToken(r), clientIP(r), time.Now())
	if err != nil {
		http.Error(w, "boot authorization required", http.StatusForbidden)
		s.count("answer", http.StatusForbidden)
		return
	}
	if _, allowed := s.requireGrant(w, r, "answer", grant.Image, answerName); !allowed {
		return
	}
	data, code := s.readGrantedAnswer(grant, answerName)
	if code != http.StatusOK {
		http.Error(w, "answer file not available", code)
		s.count("answer", code)
		return
	}
	mac, connIP := grant.mac(), grant.IP
	macStr := ""
	if mac != nil {
		macStr = mac.String()
	}
	s.trackGrant(r, grant, "answer", "fetched answer file "+r.PathValue("file"))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(substituteAnswer(data, s.d.Cfg().Site, macStr, connIP))
	s.count("answer", http.StatusOK)
}

// handleSeed synthesizes a NoCloud seed directory for Ubuntu autoinstall:
// user-data is the named Answer File, meta-data is empty-but-present.
func (s *BootServer) handleSeed(w http.ResponseWriter, r *http.Request) {
	answerName := r.PathValue("file")
	grant, err := s.verifyGrant(grantToken(r), clientIP(r), time.Now())
	if err != nil {
		http.Error(w, "boot authorization required", http.StatusForbidden)
		s.count("answer", http.StatusForbidden)
		return
	}
	if _, ok := s.requireGrant(w, r, "answer", grant.Image, answerName); !ok {
		return
	}
	data, code := s.readGrantedAnswer(grant, answerName)
	if code != http.StatusOK {
		http.Error(w, "answer file changed; restart this boot", code)
		s.count("answer", code)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	switch r.PathValue("leaf") {
	case "meta-data":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "")
		s.count("answer", http.StatusOK)
	case "user-data":
		mac, connIP := grant.mac(), grant.IP
		macStr := ""
		if mac != nil {
			macStr = mac.String()
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		s.trackGrant(r, grant, "answer", "fetched NoCloud seed "+answerName)
		_, _ = w.Write(substituteAnswer(data, s.d.Cfg().Site, macStr, connIP))
		s.count("answer", http.StatusOK)
	case "vendor-data":
		w.Header().Set("Content-Type", "text/plain")
		s.count("answer", http.StatusOK)
	default:
		http.NotFound(w, r)
		s.count("answer", http.StatusNotFound)
	}
}

// readAnswer loads an answer file, refusing path escapes.
func (s *BootServer) readAnswer(name string) ([]byte, int) {
	data, _, code := s.readAnswerVersion(name)
	return data, code
}

func (s *BootServer) readAnswerVersion(name string) ([]byte, os.FileInfo, int) {
	if !answerNameRe.MatchString(name) || name == "." || name == ".." {
		return nil, nil, http.StatusBadRequest
	}
	dir := s.d.RuntimeAnswersDir
	if dir == "" {
		dir = s.d.Cfg().Images.AnswersDir
	}
	file, err := os.Open(joinClean(dir, name))
	if err != nil {
		return nil, nil, http.StatusNotFound
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxAnswerFileSize {
		return nil, nil, http.StatusNotFound
	}
	pathInfo, err := os.Lstat(file.Name())
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(fi, pathInfo) {
		return nil, nil, http.StatusNotFound
	}
	data, err := io.ReadAll(io.LimitReader(file, maxAnswerFileSize+1))
	if err != nil || int64(len(data)) > maxAnswerFileSize {
		return nil, nil, http.StatusNotFound
	}
	after, err := file.Stat()
	pathAfter, pathErr := os.Lstat(file.Name())
	if err != nil || pathErr != nil || !os.SameFile(fi, after) || !os.SameFile(after, pathAfter) ||
		after.Size() != fi.Size() || !after.ModTime().Equal(fi.ModTime()) {
		return nil, nil, http.StatusConflict
	}
	return data, after, http.StatusOK
}

func digestAnswer(data []byte) string {
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest[:])
}

// answerDigest caches only a digest tied to the current regular-file
// generation. The lock deliberately covers the at-most-4-MiB read so a menu
// burst cannot make every request hash the same answer concurrently.
func (s *BootServer) answerDigest(name string) (string, int) {
	if !answerNameRe.MatchString(name) || name == "." || name == ".." {
		return "", http.StatusBadRequest
	}
	dir := s.d.RuntimeAnswersDir
	if dir == "" {
		dir = s.d.Cfg().Images.AnswersDir
	}
	pathName := joinClean(dir, name)

	s.answerMu.Lock()
	defer s.answerMu.Unlock()
	current, err := os.Lstat(pathName)
	if err != nil || !current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 || current.Size() > maxAnswerFileSize {
		delete(s.answerDigests, name)
		return "", http.StatusNotFound
	}
	if cached, ok := s.answerDigests[name]; ok && os.SameFile(cached.info, current) &&
		cached.info.Size() == current.Size() && cached.info.ModTime().Equal(current.ModTime()) {
		cached.lastUsed = time.Now()
		s.answerDigests[name] = cached
		return cached.digest, http.StatusOK
	}
	reader := s.answerReader
	if reader == nil {
		reader = s.readAnswerVersion
	}
	data, info, code := reader(name)
	if code != http.StatusOK {
		delete(s.answerDigests, name)
		return "", code
	}
	if s.answerDigests == nil {
		s.answerDigests = make(map[string]answerDigestEntry)
	}
	if len(s.answerDigests) >= maxAnswerDigestEntries {
		oldestName := ""
		var oldest time.Time
		for candidate, entry := range s.answerDigests {
			if oldestName == "" || entry.lastUsed.Before(oldest) {
				oldestName, oldest = candidate, entry.lastUsed
			}
		}
		delete(s.answerDigests, oldestName)
	}
	digest := digestAnswer(data)
	s.answerDigests[name] = answerDigestEntry{info: info, digest: digest, lastUsed: time.Now()}
	return digest, http.StatusOK
}

func (s *BootServer) readGrantedAnswer(grant bootGrant, name string) ([]byte, int) {
	data, code := s.readAnswer(name)
	if code != http.StatusOK {
		return nil, code
	}
	if grant.Answer != name || grant.AnswerDigest == "" || digestAnswer(data) != grant.AnswerDigest {
		return nil, http.StatusConflict
	}
	return data, http.StatusOK
}

func joinClean(dir, name string) string {
	return dir + string(os.PathSeparator) + path.Base(name)
}

func safeISOPath(name string) bool {
	if name == "" || strings.ContainsRune(name, '\\') {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
