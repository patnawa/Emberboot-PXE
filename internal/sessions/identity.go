package sessions

import "time"

// BootIdentity binds authorization to one DHCP observation generation. Its
// fixed deadline permits long iSCSI boots and installer reattachment without
// making the general-purpose IP lookup trust stale DHCP information.
type BootIdentity struct {
	store      *Store
	ip, mac    string
	generation uint64
	expires    time.Time
}

func (b *BootIdentity) MAC() string { return b.mac }

// BindBootIdentity captures identity. Only a successful policy check followed
// by Authorize grants the longer boot lifetime. Once the DHCP observation is
// stale, reattachment inherits the existing deadline instead of renewing it.
func (s *Store) BindBootIdentity(ip string, lifetime time.Duration) *BootIdentity {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	b := &BootIdentity{store: s, ip: ip, expires: now.Add(lifetime)}
	identity, ok := s.ipToMAC[ip]
	if ok && now.Sub(identity.LastSeen) > identityTTL && !now.Before(identity.BootUntil) {
		delete(s.ipToMAC, ip)
		ok = false
	}
	if !ok {
		if len(s.ipToMAC) >= maxIPIdentities {
			return b
		}
		// Give anonymous boots a generation too. A later DHCP observation
		// must revoke them permanently, even after that observation expires.
		s.identityGeneration++
		identity = ipIdentity{Generation: s.identityGeneration, LastSeen: now}
		s.ipToMAC[ip] = identity
	}
	b.mac, b.generation = identity.MAC, identity.Generation
	if now.Sub(identity.LastSeen) > identityTTL {
		b.expires = identity.BootUntil
	}
	return b
}

// Authorize must follow every successful current-policy check. Conflicting
// DHCP observations (including denied clients) permanently revoke the binding.
func (b *BootIdentity) Authorize() bool {
	s := b.store
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if !now.Before(b.expires) {
		return false
	}
	identity, ok := s.ipToMAC[b.ip]
	if b.generation == 0 || !ok || identity.Generation != b.generation {
		return false
	}
	if identity.BootUntil.Before(b.expires) {
		identity.BootUntil = b.expires
		s.ipToMAC[b.ip] = identity
	}
	return true
}
