package httpsrv

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAnswerDigestCacheCoalescesConcurrentMenus(t *testing.T) {
	dir := t.TempDir()
	name := "site.yaml"
	path := filepath.Join(dir, name)
	data := []byte(strings.Repeat("answer-data\n", 1024))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &BootServer{
		d:             BootDeps{RuntimeAnswersDir: dir, Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
		answerDigests: make(map[string]answerDigestEntry),
	}
	var reads atomic.Int32
	s.answerReader = func(got string) ([]byte, os.FileInfo, int) {
		reads.Add(1)
		return s.readAnswerVersion(got)
	}

	const callers = 32
	var wg sync.WaitGroup
	errs := make(chan struct{}, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, code := s.answerDigest(name)
			if code != http.StatusOK || got != digestAnswer(data) {
				errs <- struct{}{}
			}
		}()
	}
	wg.Wait()
	close(errs)
	if len(errs) != 0 {
		t.Fatal("concurrent answer digest lookup failed")
	}
	if got := reads.Load(); got != 1 {
		t.Fatalf("answer file reads = %d, want 1", got)
	}
}

func TestBootRequestBodyIsRejectedWithoutReading(t *testing.T) {
	h := rejectBootRequestBody(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodGet, "http://boot.test/menu.ipxe", panicReader{})
	r.ContentLength = -1
	r.TransferEncoding = []string{"chunked"}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || w.Header().Get("Connection") != "close" {
		t.Fatalf("body rejection status=%d connection=%q", w.Code, w.Header().Get("Connection"))
	}
}

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("request body was read") }

func TestBootGrantRoundTripAndClientBinding(t *testing.T) {
	s := &BootServer{grantKey: bytes.Repeat([]byte{0x42}, 32)}
	now := time.Now().Truncate(time.Second)
	want := bootGrant{
		Expires:      now.Add(time.Hour).Unix(),
		IP:           "192.0.2.25",
		MAC:          "AA-BB-CC-DD-EE-FF",
		Image:        "installer.iso",
		Digest:       strings.Repeat("a", 64),
		Answer:       "site.yaml",
		AnswerDigest: strings.Repeat("c", 64),
	}
	token, err := s.signGrant(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.verifyGrant(token, want.IP, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Image != want.Image || got.Answer != want.Answer || got.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("grant = %#v", got)
	}
	if _, err := s.verifyGrant(token, "192.0.2.26", now); !errors.Is(err, errGrantClient) {
		t.Fatalf("wrong-client error = %v, want %v", err, errGrantClient)
	}
}

func TestGrantedAnswerRejectsSameNameReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "site.yaml")
	first := []byte("password: first\n")
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &BootServer{d: BootDeps{RuntimeAnswersDir: dir}}
	grant := bootGrant{Answer: "site.yaml", AnswerDigest: digestAnswer(first)}
	if _, code := s.readGrantedAnswer(grant, "site.yaml"); code != http.StatusOK {
		t.Fatalf("original answer status = %d", code)
	}
	if err := os.WriteFile(path, []byte("password: replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, code := s.readGrantedAnswer(grant, "site.yaml"); code != http.StatusConflict || data != nil {
		t.Fatalf("replacement answer returned code=%d data=%q", code, data)
	}
}

func TestBootGrantRejectsTamperAndExpiry(t *testing.T) {
	s := &BootServer{grantKey: bytes.Repeat([]byte{0x24}, 32)}
	now := time.Now().Truncate(time.Second)
	token, err := s.signGrant(bootGrant{
		Expires: now.Add(time.Minute).Unix(), IP: "198.51.100.7", Image: "rescue.iso",
		Digest: strings.Repeat("b", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	replacement := byte('A')
	if token[0] == replacement {
		replacement = 'B'
	}
	tampered := string(replacement) + token[1:]
	if _, err := s.verifyGrant(tampered, "198.51.100.7", now); !errors.Is(err, errGrantMalformed) {
		t.Fatalf("tamper error = %v, want %v", err, errGrantMalformed)
	}
	if _, err := s.verifyGrant(token, "198.51.100.7", now.Add(2*time.Minute)); !errors.Is(err, errGrantExpired) {
		t.Fatalf("expiry error = %v, want %v", err, errGrantExpired)
	}
}
