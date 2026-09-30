package sessions

import (
	"testing"
	"time"
)

func TestLongTransferCanFinishAndIdleTransferStalls(t *testing.T) {
	for _, finish := range []bool{true, false} {
		t.Run(map[bool]string{true: "complete", false: "stopped"}[finish], func(t *testing.T) {
			s := testStore(t)
			now := time.Now()
			s.now = func() time.Time { return now }
			id := s.Touch("aa:bb:cc:dd:ee:01", "10.0.0.20", "payload", "large ISO")
			progress := s.TrackTransfer(id)
			for range 20 {
				now = now.Add(time.Minute)
				progress()
				s.markStalled()
			}
			if s.ActiveCount() != 1 {
				t.Fatal("ongoing transfer was marked stalled")
			}
			want := ResultHandoff
			if finish {
				s.FinishID(id, ResultHandoff, "delivered")
			} else {
				now = now.Add(16 * time.Minute)
				s.markStalled()
				progress() // a late write cannot resurrect a terminated session
				want = ResultStalled
			}
			row, err := s.Get(id)
			if err != nil || row.Result != want {
				t.Fatalf("result %+v, %v; want %s", row, err, want)
			}
		})
	}
}

func TestOldTransferDoesNotKeepNewBootAlive(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	const mac = "aa:bb:cc:dd:ee:01"
	id := s.Touch(mac, "10.0.0.20", "payload", "old boot")
	progress := s.TrackTransfer(id)
	s.FinishID(id, ResultHandoff, "delivered")
	newID := s.Touch(mac, "10.0.0.20", "dhcp", "new boot")
	now = now.Add(16 * time.Minute)
	progress()
	s.markStalled()
	row, err := s.Get(newID)
	if err != nil || row.Result != ResultStalled {
		t.Fatalf("old progress affected new boot: %+v %v", row, err)
	}
}
