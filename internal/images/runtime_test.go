package images

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/kdomanski/iso9660"

	"emberboot/internal/alerts"
	"emberboot/internal/config"
	"emberboot/internal/iscsisrv"
	"emberboot/internal/metrics"
)

func writeRuntimeTestISO(t *testing.T, dir, name string, files map[string]string) string {
	t.Helper()
	w, err := iso9660.NewWriter()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Cleanup()
	for path, content := range files {
		if err := w.AddFile(strings.NewReader(content), path); err != nil {
			t.Fatalf("AddFile(%q): %v", path, err)
		}
	}
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteTo(f, "EMBERBOOT-TEST"); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func readyRuntimeManager(t *testing.T, disabled bool) (*Manager, *config.Config, *isoGeneration) {
	t.Helper()
	dir := t.TempDir()
	const name = "runtime.iso"
	path := writeRuntimeTestISO(t, dir, name, map[string]string{"boot/payload": "validated payload"})
	h, err := openISO(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := h.f.Stat()
	if err != nil {
		h.Close()
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.ApplyDefaults()
	cfg.Images.Dir = dir
	cfg.Images.AnswersDir = t.TempDir()
	cfg.Images.Attach = map[string]config.ImageSettings{name: {Disabled: disabled}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := NewManager(log, func() *config.Config { return cfg }, metrics.New(),
		alerts.New(log, func() (string, string) { return "test", "" }))
	gen := newISOGeneration(h, info)
	mgr.activeDir = dir
	mgr.handles[name] = gen
	mgr.byName[name] = mgr.applySettings(&Image{
		FileName:         name,
		SizeBytes:        info.Size(),
		ModTime:          info.ModTime(),
		State:            StateReady,
		Strategy:         StrategyLinuxExtract,
		Reason:           "detected test image",
		detectedStrategy: StrategyLinuxExtract,
		detectedReason:   "detected test image",
	})
	t.Cleanup(mgr.shutdown)
	return mgr, cfg, gen
}

func generationClosed(g *isoGeneration) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closed
}

func TestTargetSuffixIsStableCollisionResistantAndBounded(t *testing.T) {
	a := TargetSuffix("foo_bar.iso")
	b := TargetSuffix("foo-bar.iso")
	if a == b {
		t.Fatalf("sanitization collision was not disambiguated: %q", a)
	}
	if again := TargetSuffix("foo_bar.iso"); again != a {
		t.Fatalf("target suffix is not deterministic: %q then %q", a, again)
	}
	if !regexp.MustCompile(`^[a-z0-9.-]+$`).MatchString(a) {
		t.Fatalf("target suffix is not IQN-safe: %q", a)
	}
	longName := strings.Repeat("a", 255) + ".iso"
	full := iscsisrv.IQNPrefix + ":" + TargetSuffix(longName)
	if len(full) > 223 {
		t.Fatalf("IQN is %d bytes, maximum is 223: %q", len(full), full)
	}
}

func TestDisabledImageCannotBeOpenedThroughAnyRuntimePath(t *testing.T) {
	mgr, _, _ := readyRuntimeManager(t, true)
	if f, err := mgr.OpenRaw("runtime.iso"); err == nil {
		f.Close()
		t.Fatal("disabled image opened through raw path")
	}
	if r, _, _, err := mgr.OpenInside("runtime.iso", "boot/payload"); err == nil {
		r.Close()
		t.Fatal("disabled image opened through internal-file path")
	}
	if r, _, closeTarget, err := mgr.OpenTarget(TargetSuffix("runtime.iso")); err == nil {
		_ = r
		closeTarget()
		t.Fatal("disabled image opened through iSCSI path")
	}
	if got := mgr.TargetSuffixes(); len(got) != 0 {
		t.Fatalf("disabled image was advertised by discovery: %v", got)
	}
}

func TestRetiredGenerationStaysOpenForActiveReader(t *testing.T) {
	mgr, _, gen := readyRuntimeManager(t, false)
	r, _, _, err := mgr.OpenInside("runtime.iso", "boot/payload")
	if err != nil {
		t.Fatal(err)
	}
	mgr.drop("runtime.iso")
	if generationClosed(gen) {
		t.Fatal("generation closed while an active reader held a lease")
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read from retired generation: %v", err)
	}
	if string(got) != "validated payload" {
		t.Fatalf("payload = %q", got)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if !generationClosed(gen) {
		t.Fatal("retired generation was not closed after its final reader")
	}
	if err := r.Close(); err != nil { // idempotence for deferred cleanup
		t.Fatal(err)
	}
}

func TestConfigReloadAppliesAndRemovesForcedStrategy(t *testing.T) {
	mgr, cfg, _ := readyRuntimeManager(t, false)
	settings := cfg.Images.Attach["runtime.iso"]
	settings.Strategy = string(StrategyISCSI)
	cfg.Images.Attach["runtime.iso"] = settings
	mgr.OnConfigChange()
	img, _ := mgr.Get("runtime.iso")
	if img.Strategy != StrategyISCSI || !strings.Contains(img.Reason, "strategy forced") {
		t.Fatalf("force was not applied: strategy=%q reason=%q", img.Strategy, img.Reason)
	}

	settings.Strategy = ""
	cfg.Images.Attach["runtime.iso"] = settings
	mgr.OnConfigChange()
	img, _ = mgr.Get("runtime.iso")
	if img.Strategy != StrategyLinuxExtract || img.Reason != "detected test image" {
		t.Fatalf("auto-detection was not restored: strategy=%q reason=%q", img.Strategy, img.Reason)
	}
}

func TestImagesDirChangeIsPinnedUntilRestart(t *testing.T) {
	mgr, cfg, _ := readyRuntimeManager(t, false)
	active := mgr.activeDir
	cfg.Images.Dir = t.TempDir()
	mgr.OnConfigChange()
	if mgr.activeDir != active {
		t.Fatalf("active directory changed without watcher restart: %q -> %q", active, mgr.activeDir)
	}
	f, err := mgr.OpenRaw("runtime.iso")
	if err != nil {
		t.Fatalf("active directory stopped serving after config-only change: %v", err)
	}
	f.Close()
}

func TestTemporaryISOFilenamesAreNeverPublished(t *testing.T) {
	cases := map[string]bool{
		"ready.iso":          true,
		"READY.ISO":          true,
		"copy.iso.partial":   false,
		"copy.partial.iso":   false,
		"copy.part.iso":      false,
		"directory/file.iso": false,
		"notes.txt":          false,
	}
	for name, want := range cases {
		if got := isISOName(name); got != want {
			t.Errorf("isISOName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestContentValidationChecksumsWholeFileAndRejectsTruncation(t *testing.T) {
	dir := t.TempDir()
	path := writeRuntimeTestISO(t, dir, "content.iso", map[string]string{
		"one/file": "one",
		"two/file": strings.Repeat("payload", 4096),
	})
	h, err := openISO(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := h.f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := h.validateContents(info.Size(), nil)
	if err != nil {
		t.Fatalf("valid ISO rejected: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(data)
	if digest != hex.EncodeToString(want[:]) {
		t.Fatalf("checksum = %q, want %x", digest, want)
	}
	h.Close()

	if err := os.Truncate(path, info.Size()/2); err != nil {
		t.Fatal(err)
	}
	h, err = openISO(path)
	if err == nil {
		defer h.Close()
		if _, err := h.validateContents(info.Size(), nil); err == nil {
			t.Fatal("truncated ISO passed full-content validation")
		}
	}
}
