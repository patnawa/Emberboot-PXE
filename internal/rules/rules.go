// Package rules evaluates Overrides: given a Client's MAC and IP, decide
// whether it may boot and what it should see. Shared by the DHCP responder
// (deny) and the HTTP menu builder (menu/answer file).
package rules

import (
	"net"
	"strings"

	"emberboot/internal/config"
)

// Decision is the outcome of matching a Client against config.
type Decision struct {
	// Deny: give this Client no boot service at all.
	Deny bool
	// RuleName is the matched Override's name, "" if none matched.
	RuleName string
	// Menu restricts the Boot Menu to these image file names; nil = global.
	Menu []string
	// AnswerFile overrides per-image answer files for this Client.
	AnswerFile string
}

// Evaluate applies the first matching Override (top to bottom). Unmatched
// Clients are allowed or denied by security.allow_unknown_macs.
func Evaluate(cfg *config.Config, mac net.HardwareAddr, ip net.IP) Decision {
	macStr := strings.ToLower(mac.String())
	for _, o := range cfg.Overrides {
		if !matches(o, macStr, ip) {
			continue
		}
		name := o.Name
		if name == "" {
			name = "unnamed"
		}
		return Decision{
			Deny:       o.Deny,
			RuleName:   name,
			Menu:       o.Menu,
			AnswerFile: o.AnswerFile,
		}
	}
	return Decision{Deny: !cfg.Security.AllowUnknown()}
}

func matches(o config.Override, mac string, ip net.IP) bool {
	if o.MAC != "" && !macGlobMatch(strings.ToLower(o.MAC), mac) {
		return false
	}
	if o.Subnet != "" {
		_, cidr, err := net.ParseCIDR(o.Subnet)
		if err != nil || ip == nil || !cidr.Contains(ip) {
			return false
		}
	}
	return true
}

// macGlobMatch matches a MAC against a glob where '*' spans any suffix and
// '?' matches one hex digit, e.g. "aa:bb:cc:*", "aa:?b:*".
func macGlobMatch(pattern, mac string) bool {
	pi, mi := 0, 0
	for pi < len(pattern) {
		switch pattern[pi] {
		case '*':
			return true // '*' only ends patterns in our grammar
		case '?':
			if mi >= len(mac) || mac[mi] == ':' {
				return false
			}
			pi++
			mi++
		default:
			if mi >= len(mac) || pattern[pi] != mac[mi] {
				return false
			}
			pi++
			mi++
		}
	}
	return mi == len(mac)
}
