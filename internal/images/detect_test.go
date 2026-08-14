package images

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kdomanski/iso9660"
)

// makeISO builds a real ISO 9660 image containing the given in-ISO paths.
func makeISO(t *testing.T, paths ...string) *isoHandle {
	t.Helper()
	w, err := iso9660.NewWriter()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Cleanup()
	for _, p := range paths {
		if err := w.AddFile(strings.NewReader("content of "+p), p); err != nil {
			t.Fatalf("AddFile(%s): %v", p, err)
		}
	}
	path := filepath.Join(t.TempDir(), "test.iso")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteTo(f, "TEST"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	h, err := openISO(path)
	if err != nil {
		t.Fatalf("openISO: %v", err)
	}
	t.Cleanup(h.Close)
	return h
}

func TestDetectWindows(t *testing.T) {
	h := makeISO(t, "sources/boot.wim", "sources/install.wim", "boot/bcd", "boot/boot.sdi", "bootmgr")
	strategy, plan, reason, err := detect(h, 5<<30)
	if err != nil {
		t.Fatal(err)
	}
	if strategy != StrategyWimboot || plan.Family != "windows" {
		t.Fatalf("got %s/%s (%s)", strategy, plan.Family, reason)
	}
	for _, key := range []string{"boot.wim", "bcd", "boot.sdi", "install"} {
		if plan.Files[key] == "" {
			t.Errorf("plan.Files[%q] missing; files=%v", key, plan.Files)
		}
	}
}

func TestDetectCasper(t *testing.T) {
	h := makeISO(t, "casper/vmlinuz", "casper/initrd")
	strategy, plan, _, err := detect(h, 3<<30)
	if err != nil {
		t.Fatal(err)
	}
	if strategy != StrategyLinuxExtract || plan.Family != "ubuntu-casper" {
		t.Fatalf("got %s/%s", strategy, plan.Family)
	}
	if !strings.Contains(plan.Args, "url=${ISOURL}") {
		t.Errorf("casper args should fetch the raw ISO: %s", plan.Args)
	}
	if !strings.Contains(plan.Args, "ramdisk_size=") {
		t.Errorf("casper args need ramdisk sizing: %s", plan.Args)
	}
}

func TestDetectDebianLive(t *testing.T) {
	h := makeISO(t, "live/vmlinuz", "live/initrd.img", "live/filesystem.squashfs")
	strategy, plan, _, err := detect(h, 400<<20)
	if err != nil {
		t.Fatal(err)
	}
	if strategy != StrategyLinuxExtract || plan.Family != "debian-live" {
		t.Fatalf("got %s/%s", strategy, plan.Family)
	}
	if !strings.Contains(plan.Args, "fetch=${CONTENT}/live/filesystem.squashfs") {
		t.Errorf("debian-live args: %s", plan.Args)
	}
}

func TestDetectArchISO(t *testing.T) {
	h := makeISO(t, "arch/boot/x86_64/vmlinuz-linux", "arch/boot/x86_64/initramfs-linux.img",
		"arch/boot/intel-ucode.img", "arch/x86_64/airootfs.sfs")
	strategy, plan, _, err := detect(h, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if strategy != StrategyLinuxExtract || plan.Family != "archiso" {
		t.Fatalf("got %s/%s", strategy, plan.Family)
	}
	if len(plan.Initrds) != 2 {
		t.Errorf("expected ucode + initramfs, got %v", plan.Initrds)
	}
}

func TestDetectAnaconda(t *testing.T) {
	h := makeISO(t, "images/pxeboot/vmlinuz", "images/pxeboot/initrd.img", "images/install.img")
	strategy, plan, _, err := detect(h, 2<<30)
	if err != nil {
		t.Fatal(err)
	}
	if strategy != StrategyLinuxExtract || plan.Family != "anaconda" {
		t.Fatalf("got %s/%s", strategy, plan.Family)
	}
	if !strings.Contains(plan.Args, "inst.repo=${CONTENT}") {
		t.Errorf("anaconda must use a served tree, never the raw ISO: %s", plan.Args)
	}
}

func TestDetectSuse(t *testing.T) {
	h := makeISO(t, "boot/x86_64/loader/linux", "boot/x86_64/loader/initrd")
	strategy, plan, _, err := detect(h, 4<<30)
	if err != nil {
		t.Fatal(err)
	}
	if strategy != StrategyLinuxExtract || plan.Family != "suse" {
		t.Fatalf("got %s/%s", strategy, plan.Family)
	}
	if !strings.Contains(plan.Args, "install=${ISOURL}") {
		t.Errorf("suse linuxrc accepts the raw ISO URL: %s", plan.Args)
	}
}

func TestDetectFallbackMemdisk(t *testing.T) {
	h := makeISO(t, "some/random/file.txt")
	strategy, plan, reason, err := detect(h, 100<<20)
	if err != nil {
		t.Fatal(err)
	}
	if strategy != StrategyMemdisk || plan.Family != "unknown" {
		t.Fatalf("got %s/%s", strategy, plan.Family)
	}
	if reason == "" {
		t.Error("fallback must explain itself")
	}
}

func TestResolveCaseInsensitive(t *testing.T) {
	h := makeISO(t, "Boot/BCD")
	if !h.exists("boot/bcd") {
		t.Error("resolution should be case-insensitive")
	}
	rs, size, err := h.open("BOOT/bcd")
	if err != nil || size == 0 {
		t.Fatalf("open: %v size=%d", err, size)
	}
	buf := make([]byte, size)
	if _, err := rs.Read(buf); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(buf), "content of ") {
		t.Errorf("unexpected content: %q", buf)
	}
}
