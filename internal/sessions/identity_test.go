package sessions

import (
	"testing"
	"time"
)

func TestBootIdentitySurvivesObservationExpiryAndHandoff(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	const ip, mac = "10.0.0.20", "aa:bb:cc:dd:ee:01"
	id := s.Touch(mac, ip, "dhcp", "discover")
	binding := s.BindBootIdentity(ip, time.Hour)
	if binding.MAC() != mac || !binding.Authorize() {
		t.Fatal("initial authorization failed")
	}
	s.FinishID(id, ResultHandoff, "iSCSI attached")
	now = now.Add(6 * time.Minute)
	s.pruneIdentities()
	if s.MACForIP(ip) != "" {
		t.Fatal("ordinary identity must still expire")
	}
	s.TouchByIP(ip, "payload", "unrelated HTTP request")
	if !binding.Authorize() {
		t.Fatal("active boot lost its identity after five minutes")
	}
	reattach := s.BindBootIdentity(ip, time.Hour)
	if reattach.MAC() != mac || !reattach.Authorize() {
		t.Fatal("installer could not reattach")
	}
	now = now.Add(55 * time.Minute)
	if binding.Authorize() || reattach.Authorize() {
		t.Fatal("reattach extended the original boot deadline")
	}
	s.pruneIdentities()
	if len(s.ipToMAC) != 0 {
		t.Fatal("expired binding was not reclaimed")
	}
}

func TestBootIdentityRevokedOnReassignmentEvenIfMACReturns(t *testing.T) {
	s := testStore(t)
	const ip, mac = "10.0.0.20", "aa:bb:cc:dd:ee:01"
	s.ObserveIdentity(mac, ip)
	binding := s.BindBootIdentity(ip, time.Hour)
	if !binding.Authorize() {
		t.Fatal("initial authorization failed")
	}
	s.ObserveIdentity("aa:bb:cc:dd:ee:02", ip)
	s.TouchObserved(mac, ip, "dhcp", "older handler finished after reassignment")
	if s.MACForIP(ip) != "aa:bb:cc:dd:ee:02" {
		t.Fatal("late telemetry overwrote DHCP identity")
	}
	if binding.Authorize() {
		t.Fatal("conflicting DHCP observation did not revoke boot identity")
	}
	s.ObserveIdentity(mac, ip)
	if binding.Authorize() {
		t.Fatal("revoked boot identity became valid again")
	}
}

func TestUnapprovedBootIdentityDoesNotExtendObservation(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	const ip = "10.0.0.20"
	s.ObserveIdentity("aa:bb:cc:dd:ee:01", ip)
	_ = s.BindBootIdentity(ip, time.Hour) // policy denied; never authorized
	now = now.Add(6 * time.Minute)
	if b := s.BindBootIdentity(ip, time.Hour); b.MAC() != "" {
		t.Fatal("denied login retained an identity")
	}
	unknown := s.BindBootIdentity(ip, time.Hour)
	if !unknown.Authorize() {
		t.Fatal("unknown identity unexpectedly invalid")
	}
	s.ObserveIdentity("aa:bb:cc:dd:ee:02", ip)
	if unknown.Authorize() {
		t.Fatal("anonymous connection ignored a new known identity")
	}
	now = now.Add(6 * time.Minute)
	s.pruneIdentities()
	if unknown.Authorize() {
		t.Fatal("anonymous binding resurrected after conflicting identity expired")
	}
}
