package images

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestOpenImageFileSupportsLongWindowsPaths(t *testing.T) {
	dir := filepath.Join(t.TempDir(), strings.Repeat("nested-", 30))
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "test.iso")
	if err := os.WriteFile(path, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := openImageFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

// ReplaceFile is Windows' atomic replacement API for an existing file. Unlike
// MoveFileEx (os.Rename), it supports a destination with shared open readers.
func replacePublishedISO(source, destination string) error {
	src, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	dst, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	p := windows.NewLazySystemDLL("kernel32.dll").NewProc("ReplaceFileW")
	ok, _, err := p.Call(uintptr(unsafe.Pointer(dst)), uintptr(unsafe.Pointer(src)), 0, 0, 0, 0)
	if ok == 0 {
		return err
	}
	return nil
}
