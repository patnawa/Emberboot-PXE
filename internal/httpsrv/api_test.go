package httpsrv

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"emberboot/internal/config"
)

func authTestManager(t *testing.T, authYAML string) *config.Manager {
	t.Helper()
	return configTestManager(t, "site: test\nnetwork:\n  dashboard_bind: \"\"\n"+authYAML)
}

func configTestManager(t *testing.T, doc string) *config.Manager {
	t.Helper()
	path := filepath.Join(t.TempDir(), "emberboot.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	mgr, err := config.NewManager(path, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return mgr
}

func authRequest(remote string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://emberboot.test/api/health", nil)
	r.RemoteAddr = remote
	return r
}

func TestBlankAuthIsLoopbackOnly(t *testing.T) {
	mgr := authTestManager(t, "")
	s := &APIServer{
		d:            APIDeps{Cfg: mgr, Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
		authFailures: make(map[string]authFailure),
	}
	h := s.authHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	local := httptest.NewRecorder()
	h.ServeHTTP(local, authRequest("127.0.0.1:1234"))
	if local.Code != http.StatusNoContent {
		t.Fatalf("loopback status = %d, want %d", local.Code, http.StatusNoContent)
	}

	remote := httptest.NewRecorder()
	h.ServeHTTP(remote, authRequest("192.0.2.10:1234"))
	if remote.Code != http.StatusForbidden {
		t.Fatalf("remote status = %d, want %d", remote.Code, http.StatusForbidden)
	}
}

func TestPasswordAuthAndRateLimit(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	mgr := authTestManager(t, "auth:\n  admin_password_hash: \""+string(hash)+"\"\n")
	s := &APIServer{
		d:            APIDeps{Cfg: mgr, Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
		authFailures: make(map[string]authFailure),
	}
	h := s.authHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for i := 0; i < authFailureLimit; i++ {
		r := authRequest("192.0.2.20:4567")
		r.SetBasicAuth("admin", "wrong password")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d status = %d, want 401", i+1, w.Code)
		}
	}
	blocked := httptest.NewRecorder()
	r := authRequest("192.0.2.20:4567")
	r.SetBasicAuth("admin", "correct horse battery staple")
	h.ServeHTTP(blocked, r)
	if blocked.Code != http.StatusTooManyRequests || blocked.Header().Get("Retry-After") == "" {
		t.Fatalf("blocked response = %d Retry-After=%q", blocked.Code, blocked.Header().Get("Retry-After"))
	}

	good := httptest.NewRecorder()
	r = authRequest("192.0.2.21:4567")
	r.SetBasicAuth("admin", "correct horse battery staple")
	h.ServeHTTP(good, r)
	if good.Code != http.StatusNoContent {
		t.Fatalf("valid password status = %d, want 204", good.Code)
	}
}

func TestConcurrentPasswordVerificationIsBounded(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	mgr := authTestManager(t, "auth:\n  admin_password_hash: \""+string(hash)+"\"\n")
	started := make(chan struct{}, maxPasswordChecksPerIP)
	release := make(chan struct{})
	var comparisons atomic.Int32
	s := &APIServer{
		d:            APIDeps{Cfg: mgr, Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
		authFailures: make(map[string]authFailure),
		authInFlight: make(map[string]int),
		comparePass: func(_, _ []byte) error {
			comparisons.Add(1)
			started <- struct{}{}
			<-release
			return bcrypt.ErrMismatchedHashAndPassword
		},
	}
	h := s.authHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	const attempts = maxPasswordChecksPerIP + 8
	statuses := make(chan int, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := authRequest("192.0.2.30:4567")
			r.SetBasicAuth("admin", "wrong password")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			statuses <- w.Code
		}()
	}
	for range maxPasswordChecksPerIP {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("password verification admission did not fill")
		}
	}
	busy := 0
	deadline := time.After(2 * time.Second)
	for busy < attempts-maxPasswordChecksPerIP {
		select {
		case code := <-statuses:
			if code != http.StatusTooManyRequests {
				t.Fatalf("admission response = %d, want 429", code)
			}
			busy++
		case <-deadline:
			t.Fatalf("only %d concurrent attempts were rejected", busy)
		}
	}
	close(release)
	wg.Wait()
	if got := comparisons.Load(); got != maxPasswordChecksPerIP {
		t.Fatalf("bcrypt comparisons = %d, want %d", got, maxPasswordChecksPerIP)
	}
}

func TestAuthFailureMapIsBoundedAndNeverFailsOpen(t *testing.T) {
	s := &APIServer{authFailures: make(map[string]authFailure)}
	now := time.Now()
	last := ""
	for i := 0; i < maxAuthFailureSources+25; i++ {
		last = "2001:db8::" + strconv.Itoa(i)
		s.recordAuthFailure(last, now.Add(time.Duration(i)*time.Microsecond))
	}
	s.authMu.Lock()
	_, newestTracked := s.authFailures[last]
	tracked := len(s.authFailures)
	globalBlocked := s.authGlobal.Blocked.After(now)
	s.authMu.Unlock()
	if tracked > maxAuthFailureSources {
		t.Fatalf("tracked %d auth sources, cap is %d", tracked, maxAuthFailureSources)
	}
	if !newestTracked {
		t.Fatal("new source was dropped from throttling when the source map filled")
	}
	if !globalBlocked {
		t.Fatal("distributed failures did not activate the global overflow throttle")
	}
}

func TestTLSCertificateReloadRetainsLastKnownGood(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	writeAPITestCertificate(t, certPath, keyPath, 1)
	s := &APIServer{
		d:           APIDeps{Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
		tlsCertFile: certPath,
		tlsKeyFile:  keyPath,
	}
	first, err := s.loadTLSCertificateLocked()
	if err != nil {
		t.Fatal(err)
	}
	if first.Leaf == nil || first.Leaf.SerialNumber.Int64() != 1 {
		t.Fatalf("first certificate serial = %v", first.Leaf)
	}
	writeAPITestCertificate(t, certPath, keyPath, 2)
	second, err := s.getTLSCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.Leaf == nil || second.Leaf.SerialNumber.Int64() != 2 {
		t.Fatalf("renewed certificate serial = %v", second.Leaf)
	}
	if err := os.WriteFile(keyPath, []byte("partial renewal"), 0o600); err != nil {
		t.Fatal(err)
	}
	retained, err := s.getTLSCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if retained.Leaf == nil || retained.Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("partial renewal did not retain the last known-good certificate")
	}
}

func TestAPITokensAreOneWayVerifiers(t *testing.T) {
	token := "eb_0123456789abcdef0123456789abcdef0123456789abcdef"
	record := APITokenRecord(token)
	if strings.Contains(record, token) {
		t.Fatal("stored record contains plaintext token")
	}
	if !verifyAPIToken(record, token) {
		t.Fatal("valid token did not match its verifier")
	}
	if verifyAPIToken(record, token+"x") {
		t.Fatal("invalid token matched verifier")
	}
}

func TestManagementRequestGuardBlocksCrossOriginAndDNSRebinding(t *testing.T) {
	mgr := configTestManager(t, "site: test\nnetwork:\n  dashboard_bind: \"127.0.0.1:8443\"\n")
	s := &APIServer{d: APIDeps{Cfg: mgr}, bindHost: "127.0.0.1"}
	h := s.requestGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	dnsRebind := httptest.NewRequest(http.MethodGet, "http://attacker.example/", nil)
	dnsRebind.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, dnsRebind)
	if w.Code != http.StatusForbidden {
		t.Fatalf("DNS-rebinding Host status = %d, want 403", w.Code)
	}

	crossSite := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8443/api/reload", nil)
	crossSite.RemoteAddr = "127.0.0.1:1234"
	crossSite.Header.Set("Origin", "https://attacker.example")
	crossSite.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, crossSite)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site mutation status = %d, want 403", w.Code)
	}

	sameOrigin := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8443/api/reload", nil)
	sameOrigin.RemoteAddr = "127.0.0.1:1234"
	sameOrigin.Header.Set("Origin", "http://127.0.0.1:8443")
	sameOrigin.Header.Set("Sec-Fetch-Site", "same-origin")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, sameOrigin)
	if w.Code != http.StatusNoContent {
		t.Fatalf("same-origin mutation status = %d, want 204", w.Code)
	}
}

func TestPasswordMutationRequiresJSON(t *testing.T) {
	mgr := authTestManager(t, "")
	s := &APIServer{d: APIDeps{Cfg: mgr, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8443/api/auth/password",
		strings.NewReader(`{"password":"attacker-controlled"}`))
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	s.handleSetPassword(w, r)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain password mutation status = %d, want 415", w.Code)
	}
	if mgr.Current().Auth.AdminPasswordHash != "" {
		t.Fatal("password changed despite rejected content type")
	}
}

func TestLegacyAPITokensMigrateOnStartup(t *testing.T) {
	token := "eb_legacy-secret-value"
	mgr := authTestManager(t, "auth:\n  api_tokens: [\""+token+"\"]\n")
	n, err := MigrateLegacyAPITokens(mgr)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("migrated %d tokens, want 1", n)
	}
	stored := mgr.Current().Auth.APITokens[0]
	if stored == token || !verifyAPIToken(stored, token) {
		t.Fatalf("legacy token was not safely migrated: %q", stored)
	}
}

func writeAPITestCertificate(t *testing.T, certPath, keyPath string, serial int64) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "emberboot.test"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}
