package httpsrv

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"emberboot/internal/images"
	"emberboot/internal/rules"
)

// A boot grant is a short-lived, server-signed capability for exactly one
// image and (optionally) its assigned Answer File. Keeping the token in the
// path lets Linux installers append paths below the in-ISO HTTP root without
// losing authorization query parameters.
type bootGrant struct {
	Expires      int64  `json:"e"`
	IP           string `json:"i"`
	MAC          string `json:"m,omitempty"`
	Image        string `json:"g"`
	Digest       string `json:"d"`
	Answer       string `json:"a,omitempty"`
	AnswerDigest string `json:"h,omitempty"`
	Session      int64  `json:"s,omitempty"`
}

const (
	defaultBootGrantTTL = 12 * time.Hour
	maxBootGrantTTL     = 24 * time.Hour
)

var (
	errGrantMalformed = errors.New("malformed boot grant")
	errGrantExpired   = errors.New("expired boot grant")
	errGrantClient    = errors.New("boot grant belongs to another client")
)

var grantEncoding = base64.RawURLEncoding.Strict()

func (s *BootServer) signGrant(g bootGrant) (string, error) {
	if len(s.grantKey) < 32 || g.IP == "" || g.Image == "" || len(g.Digest) != sha256.Size*2 ||
		(g.Answer == "") != (g.AnswerDigest == "") || g.AnswerDigest != "" && len(g.AnswerDigest) != sha256.Size*2 {
		return "", errGrantMalformed
	}
	if g.Expires == 0 {
		g.Expires = time.Now().Add(s.grantTTL()).Unix()
	}
	payload, err := json.Marshal(g)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, s.grantKey)
	_, _ = mac.Write(payload)
	sig := mac.Sum(nil)
	return grantEncoding.EncodeToString(payload) + "." +
		grantEncoding.EncodeToString(sig), nil
}

func (s *BootServer) verifyGrant(token, requestIP string, now time.Time) (bootGrant, error) {
	var g bootGrant
	if len(token) < 32 || len(token) > 2048 {
		return g, errGrantMalformed
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return g, errGrantMalformed
	}
	payload, err := grantEncoding.DecodeString(parts[0])
	if err != nil {
		return g, errGrantMalformed
	}
	sig, err := grantEncoding.DecodeString(parts[1])
	if err != nil {
		return g, errGrantMalformed
	}
	mac := hmac.New(sha256.New, s.grantKey)
	_, _ = mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return g, errGrantMalformed
	}
	if err := json.Unmarshal(payload, &g); err != nil || g.IP == "" || g.Image == "" || len(g.Digest) != sha256.Size*2 ||
		(g.Answer == "") != (g.AnswerDigest == "") || g.AnswerDigest != "" && len(g.AnswerDigest) != sha256.Size*2 {
		return bootGrant{}, errGrantMalformed
	}
	if g.Expires < now.Unix() {
		return bootGrant{}, errGrantExpired
	}
	// Reject impossible lifetimes even if a future code path accidentally
	// signs one. A small skew allowance keeps boundary tests deterministic.
	if g.Expires > now.Add(maxBootGrantTTL+time.Minute).Unix() {
		return bootGrant{}, errGrantMalformed
	}
	requestAddr := net.ParseIP(requestIP)
	grantAddr := net.ParseIP(g.IP)
	if requestAddr == nil || grantAddr == nil || !requestAddr.Equal(grantAddr) {
		return bootGrant{}, errGrantClient
	}
	if g.MAC != "" {
		parsed, err := net.ParseMAC(g.MAC)
		if err != nil {
			return bootGrant{}, errGrantMalformed
		}
		g.MAC = strings.ToLower(parsed.String())
	}
	return g, nil
}

func (s *BootServer) grantTTL() time.Duration {
	if s.d.Cfg != nil {
		if minutes := s.d.Cfg().Security.BootGrantTTLMinutes; minutes > 0 {
			return time.Duration(minutes) * time.Minute
		}
	}
	return defaultBootGrantTTL
}

func grantToken(r *http.Request) string {
	if token := r.PathValue("grant"); token != "" {
		return token
	}
	return r.URL.Query().Get("grant")
}

// requireGrant validates both the cryptographic capability and the current
// policy. A configuration change therefore revokes an otherwise unexpired
// token immediately.
func (s *BootServer) requireGrant(w http.ResponseWriter, r *http.Request, kind, imageName, answerName string) (bootGrant, bool) {
	connIP := clientIP(r)
	g, err := s.verifyGrant(grantToken(r), connIP, time.Now())
	if err != nil || g.Image != imageName || (answerName != "" && g.Answer != answerName) {
		http.Error(w, "boot authorization required", http.StatusForbidden)
		s.count(kind, http.StatusForbidden)
		return bootGrant{}, false
	}

	var clientMAC net.HardwareAddr
	knownMAC := ""
	if s.d.Sessions != nil {
		knownMAC = s.d.Sessions.MACForIP(connIP)
	}
	if g.MAC != "" {
		clientMAC, _ = net.ParseMAC(g.MAC)
		// If DHCP has an authoritative mapping, a grant cannot move between
		// machines that happen to reuse the same source IP.
		if knownMAC != "" {
			if !strings.EqualFold(knownMAC, g.MAC) {
				http.Error(w, "boot authorization required", http.StatusForbidden)
				s.count(kind, http.StatusForbidden)
				return bootGrant{}, false
			}
		}
	} else if knownMAC != "" {
		// If DHCP identity became known after the initial menu request, apply
		// the stronger current MAC policy instead of continuing as unknown.
		clientMAC, _ = net.ParseMAC(knownMAC)
	}
	clientIP := net.ParseIP(connIP)
	decision := rules.Evaluate(s.d.Cfg(), clientMAC, clientIP)
	if decision.Deny || (decision.Menu != nil && !contains(decision.Menu, imageName)) {
		http.Error(w, "boot service denied", http.StatusForbidden)
		s.count(kind, http.StatusForbidden)
		return bootGrant{}, false
	}

	img, ok := s.d.Images.GetVersion(imageName, g.Digest)
	if !ok || img.State != images.StateReady || img.Disabled {
		http.Error(w, "image not available", http.StatusNotFound)
		s.count(kind, http.StatusNotFound)
		return bootGrant{}, false
	}
	iscsiActive := s.d.Cfg().ISCSIActive()
	if s.d.RuntimeISCSIEnabled != nil {
		iscsiActive = *s.d.RuntimeISCSIEnabled
	}
	if img.Strategy == images.StrategyISCSI && !iscsiActive {
		http.Error(w, "iSCSI boot service is disabled", http.StatusServiceUnavailable)
		s.count(kind, http.StatusServiceUnavailable)
		return bootGrant{}, false
	}
	if answerName != "" && effectiveAnswer(img, decision.AnswerFile) != answerName {
		http.Error(w, "answer file not available", http.StatusForbidden)
		s.count(kind, http.StatusForbidden)
		return bootGrant{}, false
	}
	return g, true
}

func effectiveAnswer(img images.Image, override string) string {
	if override != "" {
		return override
	}
	return img.AnswerFile
}

func (g bootGrant) mac() net.HardwareAddr {
	if g.MAC == "" {
		return nil
	}
	mac, _ := net.ParseMAC(g.MAC)
	return mac
}

func (g bootGrant) String() string {
	return fmt.Sprintf("image=%q client=%s", g.Image, g.IP)
}
