// Package config defines Emberboot's declarative configuration: the YAML file that,
// together with the image folder, is the entire source of truth (ADR-0002).
//
// Loading is strict (unknown fields are errors) and reloading follows
// Last-Known-Good semantics: an invalid file never replaces a valid running
// configuration.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
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
	// DashboardBind is the listen address for the dashboard/API, so it can be
	// restricted to a management VLAN, e.g. "10.0.9.5:8443". Empty disables
	// the dashboard.
	DashboardBind string `yaml:"dashboard_bind"`
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
	// Strategy forces a Boot Strategy (linux-extract|wimboot|memdisk),
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

var macGlobRe = regexp.MustCompile(`^[0-9a-f?*]{1,2}(:[0-9a-f?*]{1,2}){0,5}\*?$|^\*$`)

// AllowUnknown reports the effective unknown-MAC policy (default allow).
func (s Security) AllowUnknown() bool {
	return s.AllowUnknownMACs == nil || *s.AllowUnknownMACs
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
}

// Validate checks the whole config and returns every problem found, not just
// the first — a 2am admin deserves the full list.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if c.Site == "" {
		add("site: required (name this instance's location, e.g. \"bkk-hq\")")
	}
	switch c.Network.DHCPMode {
	case ModeProxy, ModeOptions6667:
	default:
		add("network.dhcp_mode: %q is not one of %q, %q", c.Network.DHCPMode, ModeProxy, ModeOptions6667)
	}
	if c.Network.AdvertiseIP != "" && net.ParseIP(c.Network.AdvertiseIP) == nil {
		add("network.advertise_ip: %q is not a valid IP", c.Network.AdvertiseIP)
	}
	for name, port := range map[string]int{
		"network.tftp_port": c.Network.TFTPPort,
		"network.http_port": c.Network.HTTPPort,
	} {
		if port < 1 || port > 65535 {
			add("%s: %d is not a valid port", name, port)
		}
	}
	if c.Network.DashboardBind != "" {
		if _, _, err := net.SplitHostPort(c.Network.DashboardBind); err != nil {
			add("network.dashboard_bind: %q is not host:port (%v)", c.Network.DashboardBind, err)
		}
	}
	for iso, s := range c.Images.Attach {
		switch s.Strategy {
		case "", "linux-extract", "wimboot", "memdisk":
		default:
			add("images.attach[%s].strategy: %q is not one of linux-extract, wimboot, memdisk", iso, s.Strategy)
		}
	}
	if c.Alerts.WebhookURL != "" {
		if u, err := url.Parse(c.Alerts.WebhookURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			add("alerts.webhook_url: %q is not an http(s) URL", c.Alerts.WebhookURL)
		}
	}
	if p := c.Alerts.FailureSpike.ThresholdPercent; p < 1 || p > 100 {
		add("alerts.failure_spike.threshold_percent: %d must be 1-100", p)
	}
	if c.Sessions.RetentionDays < 1 {
		add("sessions.retention_days: must be >= 1")
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
		if o.Subnet != "" {
			if _, _, err := net.ParseCIDR(o.Subnet); err != nil {
				add("%s: subnet %q is not CIDR notation (%v)", where, o.Subnet, err)
			}
		}
		if o.Deny && (len(o.Menu) > 0 || o.AnswerFile != "") {
			add("%s: deny cannot be combined with menu or answer_file", where)
		}
	}
	return errors.Join(errs...)
}
