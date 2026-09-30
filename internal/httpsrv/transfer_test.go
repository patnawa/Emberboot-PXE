package httpsrv

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type transferResponse struct {
	*httptest.ResponseRecorder
	readFromCalls int
	maxBatch      int64
	failAfter     int64
	nestedLimit   bool
}

func (w *transferResponse) ReadFrom(r io.Reader) (int64, error) {
	w.readFromCalls++
	if limit, ok := r.(*io.LimitedReader); ok {
		_, w.nestedLimit = limit.R.(*io.LimitedReader)
	}
	if w.failAfter > 0 {
		r = io.LimitReader(r, w.failAfter)
	}
	n, err := io.Copy(w.ResponseRecorder, r)
	w.maxBatch = max(w.maxBatch, n)
	if w.failAfter > 0 {
		return n, io.ErrClosedPipe
	}
	return n, err
}

func TestTransferReportsProgressDuringServeContent(t *testing.T) {
	data := bytes.Repeat([]byte("payload"), 200000)
	for _, mode := range []string{"readerfrom", "write", "range"} {
		t.Run(mode, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/iso/test.iso", nil)
			want := data
			if mode == "range" {
				r.Header.Set("Range", "bytes=262142-1048577")
				want = data[262142:1048578]
			}
			rw := &transferResponse{ResponseRecorder: httptest.NewRecorder()}
			var response http.ResponseWriter = rw
			if mode == "write" {
				response = rw.ResponseRecorder
			}
			cw := &countingWriter{ResponseWriter: response}
			var last int64
			var calls int
			cw.progress = func() {
				if cw.n <= last || cw.n-last > payloadProgressChunk {
					t.Fatalf("unbounded or empty progress: %d -> %d", last, cw.n)
				}
				last = cw.n
				calls++
			}
			http.ServeContent(cw, r, "test.iso", time.Time{}, bytes.NewReader(data))
			if cw.n != int64(len(want)) || calls < 3 || !bytes.Equal(rw.Body.Bytes(), want) {
				t.Fatalf("bytes=%d callbacks=%d", cw.n, calls)
			}
			if mode != "write" && (rw.readFromCalls < 3 || rw.maxBatch > payloadProgressChunk) {
				t.Fatal("ReaderFrom fast path was not bounded")
			}
			if rw.nestedLimit {
				t.Fatal("nested byte limits hide the source from sendfile")
			}
		})
	}
}

func TestTransferFailureCountsOnlyWrittenBytes(t *testing.T) {
	rw := &transferResponse{ResponseRecorder: httptest.NewRecorder(), failAfter: 1234}
	calls := 0
	cw := &countingWriter{ResponseWriter: rw, progress: func() { calls++ }}
	n, err := cw.ReadFrom(bytes.NewReader(make([]byte, payloadProgressChunk*2)))
	if !errors.Is(err, io.ErrClosedPipe) || n != 1234 || cw.n != n || calls != 1 {
		t.Fatalf("n=%d, tracked=%d, calls=%d, err=%v", n, cw.n, calls, err)
	}
}
