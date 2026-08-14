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

func TestDetectDracutLive(t *testing.T) {
	h := makeISO(t, "LiveOS/squashfs.img", "images/pxeboot/vmlinuz", "images/pxeboot/initrd.img")
	strategy, plan, _, err := detect(h, 2<<30)
	if err != nil {
		t.Fatal(err)
	}
	if strategy != StrategyLinuxExtract || plan.Family != "dracut-live" {
		t.Fatalf("live ISO must win over the anaconda rule, got %s/%s", strategy, plan.Family)
	}
	if !strings.Contains(plan.Args, "root=live:${ISOURL}") {
		t.Errorf("dracut-live args: %s", plan.Args)
	}
	if plan.RAMLoadMB < 2048 {
		t.Errorf("whole-ISO RAM load must be accounted for, got %d MB", plan.RAMLoadMB)
	}
}

func TestDetectAlpine(t *testing.T) {
	h := makeISO(t, "boot/vmlinuz-lts", "boot/initramfs-lts", "boot/modloop-lts")
	strategy, plan, _, err := detect(h, 200<<20)
	if err != nil {
		t.Fatal(err)
	}
	if strategy != StrategyLinuxExtract || plan.Family != "alpine" {
		t.Fatalf("got %s/%s", strategy, plan.Family)
	}
	if !strings.Contains(plan.Args, "modloop=${CONTENT}/boot/modloop-lts") {
		t.Errorf("alpine args: %s", plan.Args)
	}
}

func TestDetectProxmoxServedOverISCSI(t *testing.T) {
	h := makeISO(t, "boot/linux26", "boot/initrd.img")
	strategy, plan, reason, err := detect(h, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if strategy != StrategyISCSI || plan.Family != "proxmox" {
		t.Fatalf("got %s/%s", strategy, plan.Family)
	}
	if !strings.Contains(reason, "iSCSI") {
		t.Errorf("proxmox reason must mention the virtual CD: %s", reason)
	}
}

func TestDetectStandaloneEFITool(t *testing.T) {
	h := makeISO(t, "EFI/BOOT/BOOTX64.EFI")
	strategy, plan, _, err := detect(h, 20<<20)
	if err != nil {
		t.Fatal(err)
	}
	if strategy != StrategyISCSI || plan.Files["efi"] == "" {
		t.Fatalf("small EFI-app ISO should expose a chainable EFI: %s files=%v", strategy, plan.Files)
	}
}

func TestDetectDebianInstallerServedOverISCSI(t *testing.T) {
	h := makeISO(t, "install.amd/vmlinuz", "install.amd/initrd.gz")
	strategy, plan, _, err := detect(h, 700<<20)
	if err != nil {
		t.Fatal(err)
	}
	if strategy != StrategyISCSI || plan.Family != "debian-installer" {
		t.Fatalf("got %s/%s", strategy, plan.Family)
	}
	if plan.RAMLoadMB != 0 {
		t.Errorf("iSCSI strategy loads nothing into RAM, got %d", plan.RAMLoadMB)
	}
}

func TestDetectWindowsRAMAccounting(t *testing.T) {
	h := makeISO(t, "sources/boot.wim", "sources/install.esd")
	_, plan, _, err := detect(h, 5<<30)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Files["install"] != "sources/install.esd" {
		t.Errorf("install source: %v", plan.Files)
	}
	if plan.RAMLoadMB < 1536 {
		t.Errorf("windows RAM load must include margin, got %d", plan.RAMLoadMB)
	}
}

func TestDetectFallbackISCSI(t *testing.T) {
	h := makeISO(t, "some/random/file.txt")
	strategy, plan, reason, err := detect(h, 100<<20)
	if err != nil {
		t.Fatal(err)
	}
	if strategy != StrategyISCSI || plan.Family != "unknown" {
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
