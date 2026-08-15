package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const minimalYAML = `
site: test-site
`

func TestParseMinimalAppliesDefaults(t *testing.T) {
	c, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Network.DHCPMode != ModeProxy {
		t.Errorf("default dhcp_mode = %q, want %q", c.Network.DHCPMode, ModeProxy)
	}
	if c.Network.TFTPPort != 69 || c.Network.HTTPPort != 8090 {
		t.Errorf("default ports = %d/%d", c.Network.TFTPPort, c.Network.HTTPPort)
	}
	if c.Sessions.RetentionDays != 90 {
		t.Errorf("default retention = %d, want 90", c.Sessions.RetentionDays)
	}
	if !c.Security.AllowUnknown() {
		t.Error("unknown MACs should be allowed by default")
	}
}

func TestExampleConfigParses(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "emberboot.example.yaml"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}
	if _, err := Parse(data); err != nil {
		t.Fatalf("emberboot.example.yaml must remain valid: %v", err)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	_, err := Parse([]byte("site: x\nsubnett: oops\n"))
	if err == nil {
		t.Fatal("unknown field should be rejected")
	}
}

func TestParseReportsAllErrors(t *testing.T) {
	bad := `
site: ""
network:
  dhcp_mode: banana
  tftp_port: 99999
overrides:
  - name: broken
`
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatal("want error")
	}
	msg := err.Error()
	for _, want := range []string{"site:", "dhcp_mode", "tftp_port", "broken"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should mention %q; got:\n%s", want, msg)
		}
	}
}

func TestOverrideValidation(t *testing.T) {
	good := `
site: s
security:
  allow_unknown_macs: false
overrides:
  - name: lab
    subnet: 10.1.2.0/24
    menu: [clonezilla.iso]
  - mac: "aa:bb:cc:*"
    deny: true
`
	if _, err := Parse([]byte(good)); err != nil {
		t.Fatalf("valid overrides rejected: %v", err)
	}
	bad := `
site: s
overrides:
  - mac: "zz:xx"
`
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("bad MAC glob accepted")
	}
	conflict := `
site: s
overrides:
  - mac: "aa:*"
    deny: true
    menu: [x.iso]
`
	if _, err := Parse([]byte(conflict)); err == nil {
		t.Fatal("deny+menu should conflict")
	}
}

func TestAdvertiseIPMustBeUsableIPv4(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		ok   bool
	}{
		{name: "private IPv4", ip: "192.168.10.15", ok: true},
		{name: "public IPv4", ip: "203.0.113.8", ok: true},
		{name: "IPv6", ip: "2001:db8::1"},
		{name: "unspecified", ip: "0.0.0.0"},
		{name: "multicast", ip: "239.1.2.3"},
		{name: "not an address", ip: "emberboot.local"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte("site: test\nnetwork:\n  advertise_ip: \"" + tt.ip + "\"\n"))
			if tt.ok && err != nil {
				t.Fatalf("valid address rejected: %v", err)
			}
			if !tt.ok && (err == nil || !strings.Contains(err.Error(), "advertise_ip")) {
				t.Fatalf("invalid address should report advertise_ip, got %v", err)
			}
		})
	}
}

func TestDashboardExposureRequiresTLSAndAuth(t *testing.T) {
	loopback := `
site: test
network:
  dashboard_bind: "127.0.0.1:8443"
`
	if _, err := Parse([]byte(loopback)); err != nil {
		t.Fatalf("loopback-only dashboard should not require TLS or auth: %v", err)
	}

	exposed := `
site: test
network:
  dashboard_bind: "0.0.0.0:8443"
`
	_, err := Parse([]byte(exposed))
	if err == nil {
		t.Fatal("exposed unauthenticated HTTP dashboard must be rejected")
	}
	for _, want := range []string{"dashboard_tls_cert", "admin_password_hash"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q; got:\n%s", want, err)
		}
	}

	certPath, keyPath := writeTestTLSKeyPair(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	hardened := `
site: test
network:
  dashboard_bind: "192.168.10.15:8443"
  dashboard_tls_cert: ` + filepath.ToSlash(certPath) + `
  dashboard_tls_key: ` + filepath.ToSlash(keyPath) + `
auth:
  admin_password_hash: "` + string(hash) + `"
`
	if _, err := Parse([]byte(hardened)); err != nil {
		t.Fatalf("TLS + authenticated dashboard rejected: %v", err)
	}
}

func TestDashboardBindAndTLSPairValidation(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "missing port",
			yaml: "site: test\nnetwork:\n  dashboard_bind: localhost\n",
			want: "host:port",
		},
		{
			name: "port out of range",
			yaml: "site: test\nnetwork:\n  dashboard_bind: '127.0.0.1:65536'\n",
			want: "valid port",
		},
		{
			name: "listener conflict",
			yaml: "site: test\nnetwork:\n  dashboard_bind: '127.0.0.1:8090'\n",
			want: "conflicts",
		},
		{
			name: "cert without key",
			yaml: "site: test\nnetwork:\n  dashboard_tls_cert: server.crt\n",
			want: "configured together",
		},
		{
			name: "same cert and key",
			yaml: "site: test\nnetwork:\n  dashboard_tls_cert: server.pem\n  dashboard_tls_key: server.pem\n",
			want: "different files",
		},
		{
			name: "boot TCP listener conflict",
			yaml: "site: test\nnetwork:\n  http_port: 3260\n",
			want: "cannot both",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestAuthenticationCredentialValidation(t *testing.T) {
	bad := `
site: test
auth:
  admin_password_hash: not-bcrypt
  api_tokens:
    - ""
    - sha256:hint:not-a-digest
    - duplicate-legacy-token
    - duplicate-legacy-token
`
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatal("malformed authentication credentials must be rejected")
	}
	for _, want := range []string{"bcrypt", "must not be empty", "malformed SHA-256", "duplicates"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q; got:\n%s", want, err)
		}
	}
}

func TestAPITokenDuplicateDetectionUsesCredentialDigest(t *testing.T) {
	plaintext := "eb_same_credential_secret"
	record := APITokenRecord(plaintext)
	parts := strings.Split(record, ":")
	alteredHint := "sha256:different-hint:" + parts[2]

	for _, tc := range []struct {
		name   string
		tokens string
	}{
		{"different verifier hints", record + "\n    - " + alteredHint},
		{"plaintext and verifier", plaintext + "\n    - " + record},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := "site: test\nauth:\n  api_tokens:\n    - " + tc.tokens + "\n"
			_, err := Parse([]byte(doc))
			if err == nil || !strings.Contains(err.Error(), "duplicates another token credential") {
				t.Fatalf("expected duplicate credential rejection, got %v", err)
			}
		})
	}
}

func TestOperationalBounds(t *testing.T) {
	bad := `
site: test
images:
  min_free_gb: -1
menu:
  timeout_seconds: 3601
alerts:
  failure_spike:
    window_minutes: 10081
    threshold_percent: 101
    min_sessions: -2
sessions:
  retention_days: 3651
  max_size_mb: -1
`
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatal("out-of-range operational settings must be rejected")
	}
	for _, want := range []string{
		"min_free_gb", "timeout_seconds", "window_minutes", "threshold_percent",
		"min_sessions", "retention_days", "max_size_mb",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q; got:\n%s", want, err)
		}
	}
}

func TestSessionDBPathRejectsSQLiteURIMetacharacters(t *testing.T) {
	for _, path := range []string{"data/sessions.db?mode=memory", "data/%2e%2e/escape.db", "data/sessions.db#fragment", ":memory:"} {
		_, err := Parse([]byte("site: test\nsessions:\n  db_path: \"" + path + "\"\n"))
		if err == nil || !(strings.Contains(err.Error(), "URI metacharacters") || strings.Contains(err.Error(), "not persistent")) {
			t.Fatalf("db path %q error = %v", path, err)
		}
	}
}

func TestWebhookAndOverrideRequireUsableNetworkValues(t *testing.T) {
	bad := `
site: test
alerts:
  webhook_url: "https://"
overrides:
  - subnet: 2001:db8::/32
`
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatal("bad webhook and IPv6 DHCP override should be rejected")
	}
	for _, want := range []string{"webhook_url", "IPv4 CIDR"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q; got:\n%s", want, err)
		}
	}
}

func TestISCSIRequiresIPv4Allowlist(t *testing.T) {
	forcedWithoutACL := `
site: test
network:
  iscsi_enabled: true
images:
  attach:
    rescue.iso:
      strategy: iscsi
`
	_, err := Parse([]byte(forcedWithoutACL))
	if err == nil || !strings.Contains(err.Error(), "iscsi_allowed_subnets") {
		t.Fatalf("forced iSCSI without an ACL must be rejected, got %v", err)
	}

	valid := `
site: test
network:
  iscsi_enabled: true
security:
  iscsi_allowed_subnets: [192.168.10.0/24]
images:
  attach:
    rescue.iso:
      strategy: iscsi
`
	if _, err := Parse([]byte(valid)); err != nil {
		t.Fatalf("forced iSCSI with an IPv4 ACL rejected: %v", err)
	}

	badACL := `
site: test
security:
  iscsi_allowed_subnets:
    - 2001:db8::/32
    - not-a-subnet
`
	_, err = Parse([]byte(badACL))
	if err == nil {
		t.Fatal("invalid iSCSI ACL entries must be rejected")
	}
	for _, want := range []string{"IPv4 CIDR", "CIDR notation"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q; got:\n%s", want, err)
		}
	}
}

func writeTestTLSKeyPair(t *testing.T) (string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "emberboot.test"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"emberboot.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestImageAndAnswerReferencesAreSafeBaseNames(t *testing.T) {
	bad := `
site: test
images:
  attach:
    ../escape.iso:
      answer_file: '..\secret.xml'
overrides:
  - subnet: 192.0.2.0/24
    menu: ['..\other.iso']
    answer_file: ../secret.yaml
`
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatal("path-like image and answer references must be rejected")
	}
	for _, want := range []string{"safe .iso base name", "answer_file", "menu image"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q; got:\n%s", want, err)
		}
	}
}

func TestManagerLastKnownGood(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "emberboot.yaml")
	if err := os.WriteFile(path, []byte("site: alpha\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	m, err := NewManager(path, log)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	var rejected error
	m.OnReject(func(err error) { rejected = err })

	// Break the file on disk: reload must fail but keep serving alpha.
	if err := os.WriteFile(path, []byte("site: beta\nbogus_field: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(); err == nil {
		t.Fatal("reload of broken config should error")
	}
	if got := m.Current().Site; got != "alpha" {
		t.Errorf("after rejected reload, site = %q, want alpha (last known good)", got)
	}
	if rejected == nil {
		t.Error("OnReject callback not fired")
	}
	if m.Status().Rejected == "" {
		t.Error("status should record the rejection")
	}

	// Fix the file: reload succeeds, rejection clears.
	if err := os.WriteFile(path, []byte("site: beta\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(); err != nil {
		t.Fatalf("reload of fixed config: %v", err)
	}
	if got := m.Current().Site; got != "beta" {
		t.Errorf("site = %q, want beta", got)
	}
	if m.Status().Rejected != "" {
		t.Error("rejection should clear after successful reload")
	}
}
