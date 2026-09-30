package sessions

// TrackTransfer returns a progress callback for one exact active session. Call
// it only after payload bytes are written. It updates the janitor's activity
// clock without filling the telemetry queue with per-chunk events, and cannot
// revive a finished session or touch a newer boot by the same client.
func (s *Store) TrackTransfer(id int64) func() {
	s.mu.Lock()
	mac := ""
	for key, current := range s.active {
		if current == id {
			mac = key
			break
		}
	}
	s.mu.Unlock()
	if mac == "" {
		return func() {}
	}
	return func() {
		s.mu.Lock()
		if s.active[mac] == id {
			s.lastAt[mac] = s.now()
		}
		s.mu.Unlock()
	}
}
