package dhcpsrv

import (
	"testing"
	"time"
)

func TestDHCPPacketRateAdmissionIsBounded(t *testing.T) {
	s := &Server{}
	now := time.Now()
	for i := 0; i < maxPacketsPerSecond; i++ {
		if !s.admitPacket(now) {
			t.Fatalf("packet %d rejected below rate limit", i+1)
		}
	}
	if s.admitPacket(now) {
		t.Fatal("packet above per-second limit was accepted")
	}
	if !s.admitPacket(now.Add(time.Second)) {
		t.Fatal("rate budget did not reset for the next window")
	}
}
