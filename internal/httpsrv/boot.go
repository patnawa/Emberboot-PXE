// Package httpsrv implements Emberboot's two HTTP servers:
//
//   - the boot server (this file): unauthenticated, reachable from every
//     client VLAN, serves iPXE scripts and all boot payloads (ADR-0001);
//   - the dashboard/API server (api.go): authenticated, bindable to a
//     management VLAN.
package httpsrv

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
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
}

// BootServer is the client-facing HTTP server.
type BootServer struct {
	d   BootDeps
	srv *http.Server
}

// NewBoot builds the boot server for addr (e.g. ":8090").
func NewBoot(d BootDeps, addr string) *BootServer {
	s := &BootServer{d: d}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /boot.ipxe", s.handleBootStub)
	mux.HandleFunc("GET /menu.ipxe", s.handleMenu)
	mux.HandleFunc("GET /boot/{file}", s.handleBootFile)
	mux.HandleFunc("GET /iso/{name}", s.handleISO)
	mux.HandleFunc("GET /img/{name}/boot.ipxe", s.handleImageScript)
	mux.HandleFunc("GET /img/{name}/file/{path...}", s.handleISOFile)
	mux.HandleFunc("GET /img/{name}/winpeshl.ini", s.handleWinpeshl)
	mux.HandleFunc("GET /img/{name}/install.bat", s.handleInstallBat)
	mux.HandleFunc("GET /answers/{file}", s.handleAnswer)
	mux.HandleFunc("GET /seed/{file}/{leaf}", s.handleSeed)
	s.srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: a 6GB install.wim to 300 clients takes as long as
		// it takes. Idle and header timeouts still bound abuse.
		IdleTimeout: 2 * time.Minute,
	}
	return s
}

func (s *BootServer) Serve() error {
	err := s.srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *BootServer) Close() { _ = s.srv.Close() }

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

// identity extracts mac/ip from query parameters (the boot stub forwards
// them) with the connection IP as fallback.
func (s *BootServer) identity(r *http.Request) (net.HardwareAddr, net.IP, string) {
	macStr := r.URL.Query().Get("mac")
	mac, _ := net.ParseMAC(macStr)
	ipStr := r.URL.Query().Get("ip")
	if ipStr == "" {
		ipStr = clientIP(r)
	}
	ip := net.ParseIP(ipStr)
	if mac == nil {
		if known := s.d.Sessions.MACForIP(clientIP(r)); known != "" {
			mac, _ = net.ParseMAC(known)
		}
	}
	return mac, ip, clientIP(r)
}

// track records a session event, preferring MAC identity.
func (s *BootServer) track(r *http.Request, stage, detail string) {
	mac, _, connIP := s.identity(r)
	if mac != nil {
		s.d.Sessions.Touch(mac.String(), connIP, stage, detail)
	} else {
		s.d.Sessions.TouchByIP(connIP, stage, detail)
	}
}

func (s *BootServer) count(kind string, code int) {
	s.d.Metrics.HTTPRequests.WithLabelValues(kind, strconv.Itoa(code)).Inc()
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
	mac, ip, _ := s.identity(r)
	s.track(r, "script", "fetched boot menu")
	writeScript(w, menuScript(s.d.Cfg(), s.d.Images.List(), mac, ip))
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
	s.track(r, "payload", "fetched "+name)
	http.ServeContent(w, r, name, time.Time{}, strings.NewReader(string(data)))
	s.count("bootfile", http.StatusOK)
}

func (s *BootServer) handleImageScript(w http.ResponseWriter, r *http.Request) {
	if s.denied(w, r, "script") {
		return
	}
	name, err := url.PathUnescape(r.PathValue("name"))
	if err != nil {
		http.Error(w, "bad name", http.StatusBadRequest)
		return
	}
	img, ok := s.d.Images.Get(name)
	if !ok || img.State != images.StateReady || img.Disabled {
		http.Error(w, "image not available", http.StatusNotFound)
		s.count("script", http.StatusNotFound)
		return
	}
	mac, ip, connIP := s.identity(r)
	if mac != nil {
		s.d.Sessions.Touch(mac.String(), connIP, "script", "selected "+img.DisplayName)
		s.d.Sessions.SetMeta(mac.String(), "", img.FileName, string(img.Strategy))
	} else {
		s.d.Sessions.TouchByIP(connIP, "script", "selected "+img.DisplayName)
	}
	memMB, _ := strconv.Atoi(r.URL.Query().Get("mem"))
	writeScript(w, imageScript(s.d.Cfg(), img, mac, ip, base(r), memMB))
	s.count("script", http.StatusOK)
}

func (s *BootServer) handleISO(w http.ResponseWriter, r *http.Request) {
	if s.denied(w, r, "iso") {
		return
	}
	name, err := url.PathUnescape(r.PathValue("name"))
	if err != nil {
		http.Error(w, "bad name", http.StatusBadRequest)
		return
	}
	img, ok := s.d.Images.Get(name)
	if !ok || img.State != images.StateReady {
		http.Error(w, "image not available", http.StatusNotFound)
		s.count("iso", http.StatusNotFound)
		return
	}
	f, err := s.d.Images.OpenRaw(name)
	if err != nil {
		http.Error(w, "open failed", http.StatusInternalServerError)
		s.count("iso", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	s.track(r, "payload", "downloading ISO "+name)
	cw := &countingWriter{ResponseWriter: w}
	http.ServeContent(cw, r, name, img.ModTime, f)
	s.d.Metrics.HTTPPayloadBytes.Add(float64(cw.n))
	s.count("iso", cw.code)
	s.finishIfComplete(r, img, name, cw.n, img.SizeBytes)
}

func (s *BootServer) handleISOFile(w http.ResponseWriter, r *http.Request) {
	if s.denied(w, r, "isofile") {
		return
	}
	name, err := url.PathUnescape(r.PathValue("name"))
	if err != nil {
		http.Error(w, "bad name", http.StatusBadRequest)
		return
	}
	inside := r.PathValue("path")
	rs, size, mod, err := s.d.Images.OpenInside(name, inside)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		s.count("isofile", http.StatusNotFound)
		return
	}
	img, _ := s.d.Images.Get(name)
	s.track(r, "payload", fmt.Sprintf("fetching %s from %s", inside, name))
	cw := &countingWriter{ResponseWriter: w}
	http.ServeContent(cw, r, path.Base(inside), mod, rs)
	s.d.Metrics.HTTPPayloadBytes.Add(float64(cw.n))
	s.count("isofile", cw.code)
	if isFinalPayload(img, inside) {
		s.finishIfComplete(r, img, inside, cw.n, size)
	}
}

// finishIfComplete closes the Boot Session as completed when the decisive
// payload was served in full (not a partial range).
func (s *BootServer) finishIfComplete(r *http.Request, img images.Image, what string, served, total int64) {
	if served < total {
		return
	}
	mac, _, connIP := s.identity(r)
	key := ""
	if mac != nil {
		key = mac.String()
	} else if known := s.d.Sessions.MACForIP(connIP); known != "" {
		key = known
	} else {
		key = "ip-" + connIP
	}
	s.d.Sessions.Finish(key, sessions.ResultCompleted,
		fmt.Sprintf("payload %s fully delivered (%d bytes); handing off to the OS", what, total))
}

// isFinalPayload: serving this file completely means the Client is on its
// way and the Boot Session can be marked completed.
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
	writeScript(w, winpeshlINI)
	s.count("script", http.StatusOK)
}

func (s *BootServer) handleInstallBat(w http.ResponseWriter, r *http.Request) {
	name, _ := url.PathUnescape(r.PathValue("name"))
	img, ok := s.d.Images.Get(name)
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
	if s.denied(w, r, "answer") {
		return
	}
	data, code := s.readAnswer(r.PathValue("file"))
	if code != http.StatusOK {
		http.Error(w, "answer file not available", code)
		s.count("answer", code)
		return
	}
	mac, _, connIP := s.identity(r)
	macStr := ""
	if mac != nil {
		macStr = mac.String()
	}
	s.track(r, "answer", "fetched answer file "+r.PathValue("file"))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(substituteAnswer(data, s.d.Cfg().Site, macStr, connIP))
	s.count("answer", http.StatusOK)
}

// handleSeed synthesizes a NoCloud seed directory for Ubuntu autoinstall:
// user-data is the named Answer File, meta-data is empty-but-present.
func (s *BootServer) handleSeed(w http.ResponseWriter, r *http.Request) {
	if s.denied(w, r, "answer") {
		return
	}
	switch r.PathValue("leaf") {
	case "meta-data":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "")
		s.count("answer", http.StatusOK)
	case "user-data":
		data, code := s.readAnswer(r.PathValue("file"))
		if code != http.StatusOK {
			http.Error(w, "answer file not available", code)
			s.count("answer", code)
			return
		}
		mac, _, connIP := s.identity(r)
		macStr := ""
		if mac != nil {
			macStr = mac.String()
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
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
	name = path.Base(name) // no traversal
	unescaped, err := url.PathUnescape(name)
	if err != nil {
		return nil, http.StatusBadRequest
	}
	data, err := os.ReadFile(joinClean(s.d.Cfg().Images.AnswersDir, unescaped))
	if err != nil {
		return nil, http.StatusNotFound
	}
	return data, http.StatusOK
}

func joinClean(dir, name string) string {
	return dir + string(os.PathSeparator) + path.Base(name)
}
