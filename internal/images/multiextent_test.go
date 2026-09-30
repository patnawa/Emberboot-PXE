package images

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func putISOUint32(data []byte, n uint32) {
	binary.LittleEndian.PutUint32(data, n)
	binary.BigEndian.PutUint32(data[4:], n)
}

type mappedISO struct{ chunks map[int64][]byte }

func (r mappedISO) ReadAt(p []byte, off int64) (int, error) {
	for i := range p {
		p[i] = 'A'
	}
	for start, data := range r.chunks {
		lo, hi := max(off, start), min(off+int64(len(p)), start+int64(len(data)))
		if lo < hi {
			copy(p[lo-off:hi-off], data[lo-start:hi-start])
		}
	}
	return len(p), nil
}

func TestMultiExtentBeyondFourGiB(t *testing.T) {
	raw, first, second := multiExtentISO(t)
	oldRoot := int(binary.LittleEndian.Uint32(raw[16*2048+158:])) * 2048
	const rootOffset = int64(4<<30) + 2048
	const firstOffset = int64(8 << 30)
	const secondOffset = int64(12 << 30)
	const firstLength = uint32(4<<30 - 2048)
	putISOUint32(raw[16*2048+158:], uint32(rootOffset/2048))
	putISOUint32(raw[16*2048+80:], uint32((secondOffset+4096)/2048))
	putISOUint32(raw[oldRoot+2:], uint32(rootOffset/2048))
	putISOUint32(raw[oldRoot+int(raw[oldRoot])+2:], uint32(rootOffset/2048))
	putISOUint32(raw[first+2:], uint32(firstOffset/2048))
	putISOUint32(raw[first+10:], firstLength)
	putISOUint32(raw[second+2:], uint32(secondOffset/2048))
	putISOUint32(raw[second+10:], 4096)
	ra := mappedISO{chunks: map[int64][]byte{0: raw, rootOffset: raw[oldRoot : oldRoot+2048], secondOffset: []byte("TAIL")}}
	root, err := readISORoot(ra, secondOffset+4096)
	if err != nil {
		t.Fatal(err)
	}
	tree := isoTreeReader{ra: ra, size: secondOffset + 4096, visited: make(map[int64]bool)}
	if err := tree.readDirectory(root, 0); err != nil {
		t.Fatal(err)
	}
	file := root.children[0]
	if file.size != int64(firstLength)+4096 {
		t.Fatalf("logical size overflow: %d", file.size)
	}
	r := io.NewSectionReader(isoFileReader{ra: ra, file: file}, 0, file.size)
	if _, err := r.Seek(int64(firstLength)-4, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 8)
	if _, err := io.ReadFull(r, got); err != nil || string(got) != "AAAATAIL" {
		t.Fatalf("large-offset read %q: %v", got, err)
	}
}

func TestMultiExtentRockRidgeName(t *testing.T) {
	raw, first, _ := multiExtentISO(t)
	root := int(binary.LittleEndian.Uint32(raw[16*2048+158:])) * 2048
	var directory []byte
	for off := root; raw[off] != 0; off += int(raw[off]) {
		record := append([]byte(nil), raw[off:off+int(raw[off])]...)
		if off == root {
			// SP indicator followed by the RRIP extension declaration.
			record = append(record, []byte{'S', 'P', 7, 1, 0xbe, 0xef, 0}...)
			record = append(record, append([]byte{'E', 'R', 18, 1, 10, 0, 0, 1}, []byte("RRIP_1991A")...)...)
		}
		if off == first {
			name := "large.install.wim"
			record = append(record, append([]byte{'N', 'M', byte(5 + len(name)), 1, 0}, []byte(name)...)...)
		}
		record[0] = byte(len(record))
		directory = append(directory, record...)
	}
	copy(raw[root:root+2048], make([]byte, 2048))
	copy(raw[root:], directory)
	h := openISOBytes(t, raw)
	r, size, err := h.open("LARGE.INSTALL.WIM")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil || size != 2052 || !bytes.HasSuffix(got, []byte("TAIL")) {
		t.Fatalf("Rock Ridge multi-extent read size=%d: %v", size, err)
	}
}

// Use two non-contiguous file records as sections of the same logical file.
// The writer intentionally has no multi-extent support, so patch the records.
func multiExtentISO(t *testing.T) ([]byte, int, int) {
	t.Helper()
	p := writeRuntimeTestISO(t, t.TempDir(), "multi.iso", map[string]string{
		"A.BIN": strings.Repeat("A", 2048), "B.BIN": "TAIL",
	})
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	root := int(binary.LittleEndian.Uint32(raw[16*2048+158:])) * 2048
	var first, second int
	for off := root; off < root+2048 && raw[off] != 0; off += int(raw[off]) {
		n := int(raw[off+32])
		switch strings.ToUpper(string(raw[off+33 : off+33+n])) {
		case "A.BIN;1":
			first = off
		case "B.BIN;1":
			second = off
		}
	}
	if first == 0 || second == 0 || raw[first] != raw[second] {
		t.Fatal("missing fixture records")
	}
	extent := append([]byte(nil), raw[second+2:second+18]...)
	copy(raw[second:second+int(raw[first])], raw[first:first+int(raw[first])])
	copy(raw[second+2:second+18], extent)
	raw[first+25] |= 0x80
	raw[second+25] &^= 0x80
	// Relocate the last section past a gap so treating the file as one
	// contiguous physical extent cannot accidentally pass the regression.
	lastBlock := uint32(len(raw)/2048 + 1)
	raw = append(raw, bytes.Repeat([]byte{'G'}, 4096)...)
	copy(raw[int(lastBlock)*2048:], "TAIL")
	putISOUint32(raw[second+2:], lastBlock)
	putISOUint32(raw[16*2048+80:], uint32(len(raw)/2048))
	return raw, first, second
}

func openISOBytes(t *testing.T, raw []byte) *isoHandle {
	t.Helper()
	p := t.TempDir() + "/fixture.iso"
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	h, err := openISO(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h
}

func TestMultiExtentReadAndSeek(t *testing.T) {
	raw, _, _ := multiExtentISO(t)
	h := openISOBytes(t, raw)
	if _, err := h.validateContents(int64(len(raw)), nil); err != nil {
		t.Fatal(err)
	}
	r, size, err := h.open("a.bin")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Repeat("A", 2048) + "TAIL"
	got, err := io.ReadAll(r)
	if err != nil || size != int64(len(want)) || string(got) != want {
		t.Fatalf("read size=%d, bytes=%d, err=%v; want both extents", size, len(got), err)
	}
	for _, start := range []int64{2046, 2048, 2050, 0} {
		if _, err := r.Seek(start, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(io.LimitReader(r, 6))
		end := min(int(start)+6, len(want))
		if err != nil || string(got) != want[start:end] {
			t.Fatalf("seek %d: %q, %v", start, got, err)
		}
	}
	if got := h.sizeOf("A.BIN"); got != int64(len(want)) {
		t.Fatalf("sizeOf=%d", got)
	}
	req := httptest.NewRequest(http.MethodGet, "/install.wim", nil)
	req.Header.Set("Range", "bytes=2046-2051")
	response := httptest.NewRecorder()
	http.ServeContent(response, req, "install.wim", time.Time{}, r)
	if response.Code != http.StatusPartialContent || response.Body.String() != "AATAIL" || response.Header().Get("Content-Range") != "bytes 2046-2051/2052" {
		t.Fatalf("cross-extent HTTP range: status=%d range=%q body=%q", response.Code, response.Header().Get("Content-Range"), response.Body.String())
	}
}

func TestInvalidMultiExtentChainsAreRejected(t *testing.T) {
	for _, kind := range []string{"unterminated", "different-name", "truncated-last", "unaligned-section"} {
		t.Run(kind, func(t *testing.T) {
			raw, first, second := multiExtentISO(t)
			switch kind {
			case "unterminated":
				raw[second+25] |= 0x80
			case "different-name":
				raw[second+33] = 'z'
			case "truncated-last":
				block := uint32(len(raw)/2048 + 1)
				binary.LittleEndian.PutUint32(raw[second+2:], block)
				binary.BigEndian.PutUint32(raw[second+6:], block)
			case "unaligned-section":
				binary.LittleEndian.PutUint32(raw[first+10:], 2047)
				binary.BigEndian.PutUint32(raw[first+14:], 2047)
			}
			h := openISOBytes(t, raw)
			if _, err := h.validateContents(int64(len(raw)), nil); err == nil {
				t.Fatal("accepted broken multi-extent file")
			}
		})
	}
}
