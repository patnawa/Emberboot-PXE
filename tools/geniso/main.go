// Command geniso writes tiny structurally-valid ISO images for development
// and UI testing: real ISO 9660 files with the marker paths each Boot
// Strategy detector looks for, a few MB in size, not actually bootable.
//
// Usage: go run ./tools/geniso <output-dir>
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kdomanski/iso9660"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: geniso <output-dir>")
		os.Exit(1)
	}
	dir := os.Args[1]
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fatal(err)
	}
	images := map[string][]string{
		"ubuntu-24.04-live-server-amd64.iso": {"casper/vmlinuz", "casper/initrd"},
		"Win11_24H2_English_x64.iso":         {"sources/boot.wim", "sources/install.wim", "boot/bcd", "boot/boot.sdi", "bootmgr"},
		"clonezilla-live-3.2.0.iso":          {"live/vmlinuz", "live/initrd.img", "live/filesystem.squashfs"},
		"mystery-tool.iso":                   {"random/stuff.dat"},
	}
	for name, paths := range images {
		if err := write(filepath.Join(dir, name), paths); err != nil {
			fatal(fmt.Errorf("%s: %w", name, err))
		}
		fmt.Println("wrote", name)
	}
}

func write(path string, files []string) error {
	w, err := iso9660.NewWriter()
	if err != nil {
		return err
	}
	defer w.Cleanup()
	for _, p := range files {
		// A little bulk so sizes look plausible in the UI.
		if err := w.AddFile(strings.NewReader(strings.Repeat(p+"\n", 4096)), p); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return w.WriteTo(f, "EMBERBOOT_TEST")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "geniso:", err)
	os.Exit(1)
}
