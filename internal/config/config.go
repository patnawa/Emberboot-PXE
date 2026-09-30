// Package config defines Emberboot's declarative configuration: the YAML file that,
// together with the image folder, is the entire source of truth (ADR-0002).
//
// Loading is strict (unknown fields are errors) and reloading follows
// Last-Known-Good semantics: an invalid file never replaces a valid running
// configuration.
package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Config is the root of emberboot.yaml.
type Config struct {
	// Site names this instance's physical location, e.g. "bkk-hq".
	Site string `yaml:"site"`

	Network  Network  `yaml:"network"`
	Images   Images   `yaml:"images"`
	Menu     Menu     `yaml:"menu"`
	Security Security `yaml:"security"`
	Auth     Auth     `yaml:"auth"`
	Alerts   Alerts   `yaml:"alerts"`
	Sessions Sessions `yaml:"sessions"`

	// Overrides change what specific Clients see (by MAC or subnet).
	Overrides []Override `yaml:"overrides"`
}

// DHCPMode selects the network posture.
type DHCPMode string

const (
	// ModeProxy answers only the PXE part of DHCP alongside the org's DHCP
	// server (default posture).
	ModeProxy DHCPMode = "proxy"
	// ModeOptions6667 assumes the org's DHCP server points clients at us via
	// options 66/67; we answer only the PXE-port (4011) conversation.
	ModeOptions6667 DHCPMode = "options66-67"
)

type Network struct {
	DHCPMode DHCPMode `yaml:"dhcp_mode"`
	// Interface optionally pins DHCP/TFTP listening to one NIC by name.
	Interface string `yaml:"interface"`
	// AdvertiseIP is the IP clients are told to fetch from. Empty means
	// autodetect the primary outbound interface address.
	AdvertiseIP string `yaml:"advertise_ip"`
	TFTPPort    int    `yaml:"tftp_port"`
	// HTTPPort serves boot payloads to clients. Must be reachable from all
	// client VLANs.
	HTTPPort int `yaml:"http_port"`
	// HTTP stream admission bounds slow/stalled multi-gigabyte responses.
	HTTPMaxStreams      int `yaml:"http_max_streams"`
	HTTPMaxStreamsPerIP int `yaml:"http_max_streams_per_ip"`
	// DashboardBind is the listen address for the dashboard/API, so it can be
	// restricted to a management VLAN, e.g. "10.0.9.5:8443". Empty disables
	// the dashboard.
	DashboardBind string `yaml:"dashboard_bind"`
	// DashboardTLSCert and DashboardTLSKey enable HTTPS for the dashboard/API.
	// They must be configured together. Any non-loopback DashboardBind
	// requires TLS and at least one configured authentication credential.
	DashboardTLSCert string `yaml:"dashboard_tls_cert"`
	DashboardTLSKey  string `yaml:"dashboard_tls_key"`
	// ISCSIPort serves the embedded read-only iSCSI target (virtual CDs for
	// ISOs that cannot netboot otherwise). 0 applies the default 3260.
	ISCSIPort int `yaml:"iscsi_port"`
	// ISCSIEnabled controls whether the optional target listener is started.
	// When omitted, existing configurations remain compatible: an iSCSI ACL
	// enables it, while the secure empty-ACL default leaves it off.
	ISCSIEnabled *bool `yaml:"iscsi_enabled"`
	// ISCSIMaxConnections bounds all discovery and normal connections. The
	// per-IP limit prevents one admitted host from consuming the global pool.
	ISCSIMaxConnections      int `yaml:"iscsi_max_connections"`
	ISCSIMaxConnectionsPerIP int `yaml:"iscsi_max_connections_per_ip"`
}

type Images struct {
	// Dir is the folder admins drop ISOs into.
	Dir string `yaml:"dir"`
	// AnswersDir holds answer files referenced by images/overrides.
	AnswersDir string `yaml:"answers_dir"`
	// MinFreeGB fires the disk-low alert when free space on the image volume
	// drops below this.
	MinFreeGB int `yaml:"min_free_gb"`
	// Attach per-image settings keyed by file name (without directory).
	Attach map[string]ImageSettings `yaml:"attach"`
}

// ImageSettings are optional per-Image knobs keyed by ISO file name.
type ImageSettings struct {
	// DisplayName overrides the menu label derived from the file name.
	DisplayName string `yaml:"display_name"`
	// AnswerFile names a file in answers_dir to offer with this image.
	AnswerFile string `yaml:"answer_file"`
	// Disabled hides a Ready image from all menus without deleting it.
	Disabled bool `yaml:"disabled"`
	// Strategy forces a Boot Strategy (linux-extract|wimboot|memdisk|iscsi),
	// overriding detection. Empty means auto-detect.
	Strategy string `yaml:"strategy"`
	// KernelArgs appends extra kernel command-line arguments (LinuxExtract).
	KernelArgs string `yaml:"kernel_args"`
}

type Menu struct {
	// TimeoutSeconds before the default entry (local boot) is chosen.
	TimeoutSeconds int `yaml:"timeout_seconds"`
	// Title shown at the top of the boot menu.
	Title string `yaml:"title"`
}

type Security struct {
	// AllowUnknownMACs: when false, Clients not matched by any Override get
	// no boot service at all (lockdown).
	AllowUnknownMACs *bool `yaml:"allow_unknown_macs"`
	// ISCSIAllowedSubnets is the IPv4 client allowlist for the embedded iSCSI
	// target. Empty denies every iSCSI connection. The target has no CHAP, so
	// access must be constrained here and by the network firewall.
	ISCSIAllowedSubnets []string `yaml:"iscsi_allowed_subnets"`
	// BootGrantTTLMinutes is the lifetime of signed stage-two download URLs
	// and authorized iSCSI boot identities (including installer reattachment).
	// Long repository-based installs need hours, not minutes; grants remain
	// bound to the client IP, image, current policy, and optional answer file.
	BootGrantTTLMinutes int `yaml:"boot_grant_ttl_minutes"`
}

type Auth struct {
	// AdminPasswordHash is a bcrypt hash for the dashboard login.
	AdminPasswordHash string `yaml:"admin_password_hash"`
	// APITokens are bearer tokens accepted by the REST API.
	APITokens []string `yaml:"api_tokens"`
}

type Alerts struct {
	// WebhookURL receives JSON alert payloads (LINE-Notify-friendly shape).
	WebhookURL string `yaml:"webhook_url"`
	// FailureSpike tunes the boot-failure-rate alert.
	FailureSpike FailureSpike `yaml:"failure_spike"`
}

type FailureSpike struct {
	WindowMinutes    int `yaml:"window_minutes"`
	ThresholdPercent int `yaml:"threshold_percent"`
	// MinSessions suppresses the alert below this many sessions in the
	// window (one flaky NIC is not a spike).
	MinSessions int `yaml:"min_sessions"`
}

type Sessions struct {
	// DBPath is the SQLite file. Disposable cache: deleting it loses history,
	// never breaks booting.
	DBPath        string `yaml:"db_path"`
	RetentionDays int    `yaml:"retention_days"`
	MaxSizeMB     int    `yaml:"max_size_mb"`
}

// Override is a targeting rule: by MAC glob or subnet, restrict/replace the
// menu and/or attach an answer file. First match wins, top to bottom.
type Override struct {
	// Name labels the rule in logs and the dashboard.
	Name string `yaml:"name"`
	// MAC is a glob like "aa:bb:cc:*" (lowercase, ':' separated).
	MAC string `yaml:"mac"`
	// Subnet is a CIDR like "10.1.2.0/24".
	Subnet string `yaml:"subnet"`
	// Menu limits this Client's Boot Menu to these image file names. Empty
	// keeps the global menu.
	Menu []string `yaml:"menu"`
	// AnswerFile overrides the per-image answer file for matched Clients.
	AnswerFile string `yaml:"answer_file"`
	// Deny refuses boot service to matched Clients.
	Deny bool `yaml:"deny"`
}

var macGlobRe = regexp.MustCompile(`^(?:\*|[0-9a-f?]{2}(?::[0-9a-f?]{2}){5}|[0-9a-f?]{2}(?::[0-9a-f?]{2}){0,4}:\*)$`)
var safeFileNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func safeAnswerFile(name string) bool {
	return name == "" || (safeFileNameRe.MatchString(name) && name != "." && name != "..")
}

func safeISOFile(name string) bool {
	if len(name) == 0 || len(name) > 240 || name == "." || name == ".." ||
		name != strings.TrimSpace(name) || !strings.EqualFold(filepath.Ext(name), ".iso") ||
		strings.ContainsAny(name, `/\`) {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

const (
	maxMenuTimeoutSeconds  = 3600
	maxMinFreeGB           = 1_000_000
	maxAlertWindowMinutes  = 7 * 24 * 60
	maxAlertMinSessions    = 1_000_000
	maxRetentionDays       = 10 * 365
	maxSessionDBSizeMB     = 1 << 20
	minBootGrantTTLMinutes = 15
	maxBootGrantTTLMinutes = 24 * 60
	maxISCSIConnections    = 4096
)

// AllowUnknown reports the effective unknown-MAC policy (default allow).
func (s Security) AllowUnknown() bool {
	return s.AllowUnknownMACs == nil || *s.AllowUnknownMACs
}

// ISCSIActive reports the effective optional-listener setting. An explicit
// value wins; otherwise an ACL preserves compatibility with configurations
// written before iscsi_enabled existed.
func (c *Config) ISCSIActive() bool {
	if c.Network.ISCSIEnabled != nil {
		return *c.Network.ISCSIEnabled
	}
	return len(c.Security.ISCSIAllowedSubnets) > 0
}

// ApplyDefaults fills unset fields with production defaults. Called before
// Validate so validation sees the effective config.
func (c *Config) ApplyDefaults() {
	if c.Network.DHCPMode == "" {
		c.Network.DHCPMode = ModeProxy
	}
	if c.Network.TFTPPort == 0 {
		c.Network.TFTPPort = 69
	}
	if c.Network.HTTPPort == 0 {
		c.Network.HTTPPort = 8090
	}
	if c.Network.HTTPMaxStreams == 0 {
		c.Network.HTTPMaxStreams = 600
	}
	if c.Network.HTTPMaxStreamsPerIP == 0 {
		c.Network.HTTPMaxStreamsPerIP = min(8, c.Network.HTTPMaxStreams)
	}
	if c.Network.ISCSIPort == 0 {
		c.Network.ISCSIPort = 3260
	}
	if c.Network.ISCSIMaxConnections == 0 {
		c.Network.ISCSIMaxConnections = 768
	}
	if c.Network.ISCSIMaxConnectionsPerIP == 0 {
		c.Network.ISCSIMaxConnectionsPerIP = min(8, c.Network.ISCSIMaxConnections)
	}
	if c.Images.Dir == "" {
		c.Images.Dir = "images"
	}
	if c.Images.AnswersDir == "" {
		c.Images.AnswersDir = "answers"
	}
	if c.Images.MinFreeGB == 0 {
		c.Images.MinFreeGB = 20
	}
	if c.Menu.TimeoutSeconds == 0 {
		c.Menu.TimeoutSeconds = 30
	}
	if c.Menu.Title == "" {
		c.Menu.Title = "Emberboot Network Boot"
	}
	if c.Alerts.FailureSpike.WindowMinutes == 0 {
		c.Alerts.FailureSpike.WindowMinutes = 10
	}
	if c.Alerts.FailureSpike.ThresholdPercent == 0 {
		c.Alerts.FailureSpike.ThresholdPercent = 20
	}
	if c.Alerts.FailureSpike.MinSessions == 0 {
		c.Alerts.FailureSpike.MinSessions = 10
	}
	if c.Sessions.DBPath == "" {
		c.Sessions.DBPath = filepath.Join("data", "sessions.db")
	}
	if c.Sessions.RetentionDays == 0 {
		c.Sessions.RetentionDays = 90
	}
	if c.Sessions.MaxSizeMB == 0 {
		c.Sessions.MaxSizeMB = 512
	}
	if c.Security.BootGrantTTLMinutes == 0 {
		c.Security.BootGrantTTLMinutes = 12 * 60
	}
}

// Validate checks the whole config and returns every problem found, not just
// the first — a 2am admin deserves the full list.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if strings.TrimSpace(c.Site) == "" {
		add("site: required (name this instance's location, e.g. \"bkk-hq\")")
	}
	switch c.Network.DHCPMode {
	case ModeProxy, ModeOptions6667:
	default:
		add("network.dhcp_mode: %q is not one of %q, %q", c.Network.DHCPMode, ModeProxy, ModeOptions6667)
	}
	if c.Network.AdvertiseIP != "" {
		ip := net.ParseIP(c.Network.AdvertiseIP)
		switch {
		case ip == nil || ip.To4() == nil:
			add("network.advertise_ip: %q is not a valid IPv4 address", c.Network.AdvertiseIP)
		case ip.IsUnspecified():
			add("network.advertise_ip: %q cannot be an unspecified address", c.Network.AdvertiseIP)
		case ip.IsMulticast():
			add("network.advertise_ip: %q cannot be a multicast address", c.Network.AdvertiseIP)
		}
	}
	for name, port := range map[string]int{
		"network.tftp_port":  c.Network.TFTPPort,
		"network.http_port":  c.Network.HTTPPort,
		"network.iscsi_port": c.Network.ISCSIPort,
	} {
		if port < 1 || port > 65535 {
			add("%s: %d is not a valid port", name, port)
		}
	}
	if c.Network.HTTPPort == c.Network.ISCSIPort {
		add("network.http_port and network.iscsi_port: both use TCP and cannot both be %d", c.Network.HTTPPort)
	}
	if c.Network.TFTPPort == 4011 {
		add("network.tftp_port: UDP 4011 is reserved by the PXE listener")
	}
	if c.Network.DHCPMode == ModeProxy && c.Network.TFTPPort == 67 {
		add("network.tftp_port: UDP 67 is reserved by proxyDHCP in proxy mode")
	}
	if n := c.Network.ISCSIMaxConnections; n < 1 || n > maxISCSIConnections {
		add("network.iscsi_max_connections: %d must be 1-%d", n, maxISCSIConnections)
	}
	if n := c.Network.ISCSIMaxConnectionsPerIP; n < 1 || n > c.Network.ISCSIMaxConnections {
		add("network.iscsi_max_connections_per_ip: %d must be 1-%d", n, c.Network.ISCSIMaxConnections)
	}
	if n := c.Network.HTTPMaxStreams; n < 1 || n > 4096 {
		add("network.http_max_streams: %d must be 1-4096", n)
	}
	if n := c.Network.HTTPMaxStreamsPerIP; n < 1 || n > c.Network.HTTPMaxStreams {
		add("network.http_max_streams_per_ip: %d must be 1-%d", n, c.Network.HTTPMaxStreams)
	}
	combinedDescriptorBudget := 2 * c.Network.HTTPMaxStreams
	if c.ISCSIActive() {
		combinedDescriptorBudget += c.Network.ISCSIMaxConnections
	}
	if combinedDescriptorBudget > 7000 {
		add("network HTTP/iSCSI limits: weighted descriptor budget %d exceeds the supported 7000-descriptor service budget", combinedDescriptorBudget)
	}

	hasTLSCert := strings.TrimSpace(c.Network.DashboardTLSCert) != ""
	hasTLSKey := strings.TrimSpace(c.Network.DashboardTLSKey) != ""
	if hasTLSCert != hasTLSKey {
		add("network.dashboard_tls_cert and network.dashboard_tls_key: must be configured together")
	}
	if hasTLSCert && filepath.Clean(c.Network.DashboardTLSCert) == filepath.Clean(c.Network.DashboardTLSKey) {
		add("network.dashboard_tls_cert and network.dashboard_tls_key: must refer to different files")
	}
	if hasTLSCert && hasTLSKey {
		if c.Network.DashboardTLSCert != strings.TrimSpace(c.Network.DashboardTLSCert) ||
			c.Network.DashboardTLSKey != strings.TrimSpace(c.Network.DashboardTLSKey) {
			add("network.dashboard_tls_cert and network.dashboard_tls_key: paths must not have surrounding whitespace")
		} else if pair, err := tls.LoadX509KeyPair(c.Network.DashboardTLSCert, c.Network.DashboardTLSKey); err != nil {
			add("network.dashboard_tls_cert and network.dashboard_tls_key: cannot load matching certificate/key: %v", err)
		} else if len(pair.Certificate) == 0 {
			add("network.dashboard_tls_cert: certificate chain is empty")
		} else if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err != nil {
			add("network.dashboard_tls_cert: cannot parse leaf certificate: %v", err)
		} else if now := time.Now(); now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			add("network.dashboard_tls_cert: leaf certificate is not currently valid (%s to %s)",
				leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))
		}
		if runtime.GOOS != "windows" {
			if info, err := os.Stat(c.Network.DashboardTLSKey); err == nil && info.Mode().Perm()&0o077 != 0 {
				add("network.dashboard_tls_key: private key permissions %04o expose it to other local users; require 0600", info.Mode().Perm())
			}
		}
	}
	if c.Network.DashboardBind != "" {
		host, portText, err := net.SplitHostPort(c.Network.DashboardBind)
		if err != nil {
			add("network.dashboard_bind: %q is not host:port (%v)", c.Network.DashboardBind, err)
		} else {
			port, err := strconv.Atoi(portText)
			if err != nil || port < 1 || port > 65535 {
				add("network.dashboard_bind: %q does not contain a valid port", c.Network.DashboardBind)
			} else if port == c.Network.HTTPPort || port == c.Network.ISCSIPort {
				add("network.dashboard_bind: TCP port %d conflicts with a boot service listener", port)
			}
			if dashboardBindExposed(host) {
				if !hasTLSCert || !hasTLSKey {
					add("network.dashboard_bind: non-loopback dashboards require dashboard_tls_cert and dashboard_tls_key")
				}
				if strings.TrimSpace(c.Auth.AdminPasswordHash) == "" {
					add("network.dashboard_bind: non-loopback dashboards require auth.admin_password_hash (API tokens alone cannot sign in to the browser UI)")
				}
			}
		}
	}
	if hash := strings.TrimSpace(c.Auth.AdminPasswordHash); hash != "" {
		if _, err := bcrypt.Cost([]byte(hash)); err != nil {
			add("auth.admin_password_hash: not a valid bcrypt password hash")
		}
	}
	seenTokens := make(map[string]struct{}, len(c.Auth.APITokens))
	for i, token := range c.Auth.APITokens {
		where := fmt.Sprintf("auth.api_tokens[%d]", i)
		if strings.TrimSpace(token) == "" {
			add("%s: must not be empty", where)
			continue
		}
		credential, err := apiTokenCredentialKey(token)
		if err != nil {
			add("%s: %v", where, err)
			continue
		}
		if _, exists := seenTokens[credential]; exists {
			add("%s: duplicates another token credential", where)
		}
		seenTokens[credential] = struct{}{}
	}
	if c.Images.MinFreeGB < 0 || c.Images.MinFreeGB > maxMinFreeGB {
		add("images.min_free_gb: %d must be 0-%d", c.Images.MinFreeGB, maxMinFreeGB)
	}
	if strings.ContainsAny(c.Sessions.DBPath, "?%#\x00") {
		add("sessions.db_path: must not contain URI metacharacters ?, %%, or #")
	}
	if strings.EqualFold(strings.TrimSpace(c.Sessions.DBPath), ":memory:") {
		add("sessions.db_path: SQLite :memory: is not persistent and is not allowed")
	}
	forcedISCSI := false
	for iso, s := range c.Images.Attach {
		if !safeISOFile(iso) {
			add("images.attach[%s]: key must be a safe .iso base name", iso)
		}
		if !safeAnswerFile(s.AnswerFile) {
			add("images.attach[%s].answer_file: %q is not a safe base name", iso, s.AnswerFile)
		}
		switch s.Strategy {
		case "", "linux-extract", "wimboot", "memdisk", "iscsi":
			forcedISCSI = forcedISCSI || s.Strategy == "iscsi"
		default:
			add("images.attach[%s].strategy: %q is not one of linux-extract, wimboot, memdisk, iscsi", iso, s.Strategy)
		}
	}
	seenISCSISubnets := make(map[string]struct{}, len(c.Security.ISCSIAllowedSubnets))
	for i, subnet := range c.Security.ISCSIAllowedSubnets {
		ip, network, err := net.ParseCIDR(subnet)
		where := fmt.Sprintf("security.iscsi_allowed_subnets[%d]", i)
		if err != nil {
			add("%s: %q is not CIDR notation (%v)", where, subnet, err)
			continue
		}
		if ip.To4() == nil {
			add("%s: %q is not an IPv4 CIDR", where, subnet)
			continue
		}
		canonical := network.String()
		if _, duplicate := seenISCSISubnets[canonical]; duplicate {
			add("%s: %q duplicates another allowed subnet", where, subnet)
		}
		seenISCSISubnets[canonical] = struct{}{}
	}
	if forcedISCSI && !c.ISCSIActive() {
		add("network.iscsi_enabled: must be true when an image forces the iscsi strategy")
	}
	if c.ISCSIActive() && len(c.Security.ISCSIAllowedSubnets) == 0 {
		add("security.iscsi_allowed_subnets: at least one subnet is required when iSCSI is enabled")
	}
	if ttl := c.Security.BootGrantTTLMinutes; ttl < minBootGrantTTLMinutes || ttl > maxBootGrantTTLMinutes {
		add("security.boot_grant_ttl_minutes: %d must be %d-%d", ttl, minBootGrantTTLMinutes, maxBootGrantTTLMinutes)
	}
	if c.Alerts.WebhookURL != "" {
		u, err := url.Parse(c.Alerts.WebhookURL)
		if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
			add("alerts.webhook_url: %q is not an http(s) URL", c.Alerts.WebhookURL)
		}
	}
	if t := c.Menu.TimeoutSeconds; t < 1 || t > maxMenuTimeoutSeconds {
		add("menu.timeout_seconds: %d must be 1-%d", t, maxMenuTimeoutSeconds)
	}
	if w := c.Alerts.FailureSpike.WindowMinutes; w < 1 || w > maxAlertWindowMinutes {
		add("alerts.failure_spike.window_minutes: %d must be 1-%d", w, maxAlertWindowMinutes)
	}
	if p := c.Alerts.FailureSpike.ThresholdPercent; p < 1 || p > 100 {
		add("alerts.failure_spike.threshold_percent: %d must be 1-100", p)
	}
	if n := c.Alerts.FailureSpike.MinSessions; n < 1 || n > maxAlertMinSessions {
		add("alerts.failure_spike.min_sessions: %d must be 1-%d", n, maxAlertMinSessions)
	}
	if d := c.Sessions.RetentionDays; d < 1 || d > maxRetentionDays {
		add("sessions.retention_days: %d must be 1-%d", d, maxRetentionDays)
	}
	if size := c.Sessions.MaxSizeMB; size < 1 || size > maxSessionDBSizeMB {
		add("sessions.max_size_mb: %d must be 1-%d", size, maxSessionDBSizeMB)
	}
	for i, o := range c.Overrides {
		where := fmt.Sprintf("overrides[%d]", i)
		if o.Name != "" {
			where = fmt.Sprintf("overrides[%d] (%s)", i, o.Name)
		}
		if o.MAC == "" && o.Subnet == "" {
			add("%s: needs a mac or subnet to match on", where)
		}
		if o.MAC != "" && !macGlobRe.MatchString(strings.ToLower(o.MAC)) {
			add("%s: mac %q is not a MAC glob like \"aa:bb:cc:*\"", where, o.MAC)
		}
		if o.MAC != "" && c.Security.AllowUnknown() && (o.Deny || o.Menu != nil) {
			add("%s: MAC deny/menu rules require security.allow_unknown_macs: false; otherwise a client can hide its MAC and use the unknown-client policy", where)
		}
		if o.Subnet != "" {
			ip, _, err := net.ParseCIDR(o.Subnet)
			if err != nil {
				add("%s: subnet %q is not CIDR notation (%v)", where, o.Subnet, err)
			} else if ip.To4() == nil {
				add("%s: subnet %q is not an IPv4 CIDR", where, o.Subnet)
			}
		}
		if o.Deny && (len(o.Menu) > 0 || o.AnswerFile != "") {
			add("%s: deny cannot be combined with menu or answer_file", where)
		}
		if !safeAnswerFile(o.AnswerFile) {
			add("%s: answer_file %q is not a safe base name", where, o.AnswerFile)
		}
		for _, imageName := range o.Menu {
			if !safeISOFile(imageName) {
				add("%s: menu image %q is not a safe .iso base name", where, imageName)
			}
		}
	}
	return errors.Join(errs...)
}

// dashboardBindExposed reports whether a listener host can accept traffic
// from outside this machine. Empty and wildcard hosts are deliberately
// treated as exposed.
func dashboardBindExposed(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}
