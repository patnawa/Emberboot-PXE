package images

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/kdomanski/iso9660"
)

const isoBlockSize = 2048

type isoExtent struct{ offset, size, start int64 }

// One logical file can span several consecutive directory records (ECMA-119
// section 6.5). Keep physical offsets and logical sizes in 64 bits, including
// for directories and continuation areas located beyond 4 GiB.
type isoEntry struct {
	name     string
	dir      bool
	size     int64
	extents  []isoExtent
	children []*isoEntry
}

func (e *isoEntry) Name() string { return e.name }
func (e *isoEntry) IsDir() bool  { return e.dir }
func (e *isoEntry) Size() int64  { return e.size }

func decodeISORecord(raw []byte) (*iso9660.DirectoryEntry, error) {
	if len(raw) < 34 || int(raw[0]) != len(raw) || raw[32] == 0 ||
		33+int(raw[32])+int((raw[32]+1)%2) > len(raw) {
		return nil, fmt.Errorf("invalid ISO directory record length")
	}
	d := &iso9660.DirectoryEntry{}
	if err := d.UnmarshalBinary(raw); err != nil {
		return nil, err
	}
	if d.FileUnitSize != 0 || d.InterleaveGap != 0 {
		return nil, fmt.Errorf("interleaved ISO files are unsupported")
	}
	return d, nil
}

func entryFromRecord(d *iso9660.DirectoryEntry, imageSize int64) (*isoEntry, error) {
	offset := (int64(uint32(d.ExtentLocation)) + int64(d.ExtendedAtributeRecordLength)) * isoBlockSize
	size := int64(d.ExtentLength)
	if offset > imageSize || size > imageSize-offset {
		return nil, fmt.Errorf("file %q has an incomplete extent", d.Identifier)
	}
	name := d.Identifier
	isDir := d.FileFlags&2 != 0
	if !isDir {
		name = strings.TrimSuffix(strings.SplitN(name, ";", 2)[0], ".")
	}
	return &isoEntry{name: name, dir: isDir, size: size, extents: []isoExtent{{offset: offset, size: size}}}, nil
}

func readISORoot(ra io.ReaderAt, imageSize int64) (*isoEntry, error) {
	var root *isoEntry
	var block [isoBlockSize]byte
	// A descriptor sequence is tiny in practice. Bound malformed sequences.
	for sector := int64(16); sector < 16+1024; sector++ {
		if _, err := ra.ReadAt(block[:], sector*isoBlockSize); err != nil {
			return nil, err
		}
		if string(block[1:6]) != "CD001" || block[6] != 1 {
			return nil, fmt.Errorf("invalid ISO volume descriptor")
		}
		if block[0] == 1 && root == nil {
			blockSize, err := iso9660.UnmarshalInt16LSBMSB(block[128:132])
			if err != nil || blockSize != isoBlockSize {
				return nil, fmt.Errorf("unsupported ISO logical block size")
			}
			n := int(block[156])
			if n < 34 || 156+n > len(block) {
				return nil, fmt.Errorf("invalid ISO root record")
			}
			d, err := decodeISORecord(block[156 : 156+n])
			if err != nil {
				return nil, err
			}
			root, err = entryFromRecord(d, imageSize)
			if err != nil {
				return nil, err
			}
			if !root.dir || d.FileFlags&0x80 != 0 {
				return nil, fmt.Errorf("invalid ISO root directory")
			}
		}
		if block[0] == 255 {
			if root == nil {
				return nil, fmt.Errorf("ISO has no primary volume")
			}
			return root, nil
		}
	}
	return nil, fmt.Errorf("too many ISO volume descriptors")
}

type isoTreeReader struct {
	ra        io.ReaderAt
	size      int64
	stop      <-chan struct{}
	entries   int
	visited   map[int64]bool
	suspSkip  int
	rockRidge bool
}

func (r *isoTreeReader) readDirectory(dir *isoEntry, depth int) error {
	if depth > 128 || r.visited[dir.extents[0].offset] {
		return fmt.Errorf("cyclic or excessively deep ISO directory")
	}
	if dir.size > 256<<20 {
		return fmt.Errorf("ISO directory exceeds 256 MiB")
	}
	r.visited[dir.extents[0].offset] = true
	var pending *isoEntry
	var pendingID string
	var pendingFlags byte
	var block [isoBlockSize]byte
	for pos := int64(0); pos < dir.size; pos += isoBlockSize {
		select {
		case <-r.stop:
			return errValidationCanceled
		default:
		}
		buf := block[:min(int64(isoBlockSize), dir.size-pos)]
		if _, err := r.ra.ReadAt(buf, dir.extents[0].offset+pos); err != nil {
			return err
		}
		for off := 0; off < len(buf) && buf[off] != 0; {
			n := int(buf[off])
			if off+n > len(buf) {
				return fmt.Errorf("ISO directory record crosses a block boundary")
			}
			d, err := decodeISORecord(buf[off : off+n])
			if err != nil {
				return err
			}
			off += n
			r.entries++
			if r.entries > 1_000_000 {
				return fmt.Errorf("ISO contains more than 1000000 records")
			}
			if d.Identifier == "\x00" || d.Identifier == "\x01" {
				if pending != nil {
					return fmt.Errorf("interrupted ISO multi-extent file")
				}
				if depth == 0 && d.Identifier == "\x00" {
					if err := r.readSUSP(d.SystemUse); err != nil {
						return err
					}
				}
				continue
			}
			e, err := entryFromRecord(d, r.size)
			if err != nil {
				return err
			}
			more := d.FileFlags&0x80 != 0
			if (more || pending != nil) && e.dir {
				return fmt.Errorf("multi-extent directory is invalid")
			}
			if more && (e.size == 0 || e.size%isoBlockSize != 0) {
				return fmt.Errorf("nonfinal ISO file section must fill logical blocks")
			}
			if pending != nil {
				if d.Identifier != pendingID || d.FileFlags&^0x80 != pendingFlags {
					return fmt.Errorf("mismatched ISO multi-extent records")
				}
				if pending.size > r.size-e.size {
					return fmt.Errorf("multi-extent file %q exceeds image size", pending.name)
				}
				x := e.extents[0]
				x.start = pending.size
				pending.extents = append(pending.extents, x)
				pending.size += e.size
				e = pending
			} else {
				if r.rockRidge {
					if len(d.SystemUse) < r.suspSkip {
						return fmt.Errorf("invalid SUSP offset")
					}
					budget := 1 << 20
					entries, err := r.systemUse(d.SystemUse[r.suspSkip:], 0, &budget)
					if err != nil {
						return err
					}
					if name := entries.GetRockRidgeName(); name != "" {
						e.name = name
					}
				}
				if e.name == "" || e.name == "." || e.name == ".." || strings.ContainsAny(e.name, "/\x00") {
					return fmt.Errorf("invalid ISO file name")
				}
			}
			if more {
				pending, pendingID, pendingFlags = e, d.Identifier, d.FileFlags&^0x80
			} else {
				dir.children = append(dir.children, e)
				pending = nil
			}
		}
	}
	if pending != nil {
		return fmt.Errorf("unterminated ISO multi-extent file %q", pending.name)
	}
	for _, child := range dir.children {
		if child.dir {
			if err := r.readDirectory(child, depth+1); err != nil {
				return fmt.Errorf("directory %q: %w", child.name, err)
			}
		} else {
			for _, extent := range child.extents {
				if extent.size == 0 {
					continue
				}
				var last [1]byte
				if _, err := r.ra.ReadAt(last[:], extent.offset+extent.size-1); err != nil {
					return fmt.Errorf("file %q: %w", child.name, err)
				}
			}
		}
	}
	return nil
}

func (r *isoTreeReader) readSUSP(data []byte) error {
	if len(data) < 7 || string(data[:2]) != "SP" {
		return nil
	}
	if data[2] != 7 || data[4] != 0xbe || data[5] != 0xef {
		return fmt.Errorf("invalid SUSP indicator")
	}
	r.suspSkip = int(data[6])
	budget := 1 << 20
	entries, err := r.systemUse(data, 0, &budget)
	if err != nil {
		return err
	}
	extensions, err := entries.GetExtensionRecords()
	if err != nil {
		return err
	}
	for _, ext := range extensions {
		if ext.Identifier == iso9660.RockRidgeIdentifier && ext.Version == 1 {
			r.rockRidge = true
		}
	}
	return nil
}

// Parse bounded SUSP continuation areas before handing validated entries to
// the upstream Rock Ridge name decoder. Cycles and oversized areas fail closed.
func (r *isoTreeReader) systemUse(data []byte, depth int, budget *int) (iso9660.SystemUseEntrySlice, error) {
	if depth > 8 || len(data) > *budget {
		return nil, fmt.Errorf("excessive ISO continuation metadata")
	}
	*budget -= len(data)
	var entries iso9660.SystemUseEntrySlice
	for len(data) >= 4 {
		n := int(data[2])
		if n < 4 || n > len(data) {
			return nil, fmt.Errorf("invalid SUSP entry length")
		}
		e := iso9660.SystemUseEntry(append([]byte(nil), data[:n]...))
		data = data[n:]
		if e.Type() == "ST" {
			break
		}
		if e.Type() == "NM" && n < 5 {
			return nil, fmt.Errorf("invalid Rock Ridge name")
		}
		if e.Type() != "CE" {
			entries = append(entries, e)
			continue
		}
		if n != 28 {
			return nil, fmt.Errorf("invalid SUSP continuation")
		}
		block, e1 := iso9660.UnmarshalUint32LSBMSB(e[4:12])
		offset, e2 := iso9660.UnmarshalUint32LSBMSB(e[12:20])
		length, e3 := iso9660.UnmarshalUint32LSBMSB(e[20:28])
		start := int64(block)*isoBlockSize + int64(offset)
		if e1 != nil || e2 != nil || e3 != nil || int64(length) > int64(*budget) || start > r.size || int64(length) > r.size-start {
			return nil, fmt.Errorf("invalid SUSP continuation extent")
		}
		buf := make([]byte, int(length))
		if _, err := r.ra.ReadAt(buf, start); err != nil {
			return nil, err
		}
		continued, err := r.systemUse(buf, depth+1, budget)
		if err != nil {
			return nil, err
		}
		entries = append(entries, continued...)
	}
	return entries, nil
}

type isoFileReader struct {
	ra   io.ReaderAt
	file *isoEntry
}

func (r isoFileReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative ISO file offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.file.size {
		return 0, io.EOF
	}
	index := sort.Search(len(r.file.extents), func(i int) bool { e := r.file.extents[i]; return e.start+e.size > off })
	total := 0
	for len(p) > 0 && index < len(r.file.extents) {
		e := r.file.extents[index]
		within := off - e.start
		count := min(int64(len(p)), e.size-within)
		n, err := r.ra.ReadAt(p[:count], e.offset+within)
		total += n
		off += int64(n)
		p = p[n:]
		if err != nil {
			return total, err
		}
		if int64(n) != count {
			return total, io.ErrUnexpectedEOF
		}
		index++
	}
	if len(p) > 0 {
		return total, io.EOF
	}
	return total, nil
}
