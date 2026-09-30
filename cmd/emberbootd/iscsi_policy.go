package main

import (
	"net"
	"slices"
	"time"

	"emberboot/internal/config"
	"emberboot/internal/images"
	"emberboot/internal/rules"
	"emberboot/internal/sessions"
)

func iscsiTargetPolicy(cfg func() *config.Config, store *sessions.Store, imageForTarget func(string) (images.Image, bool)) func(net.IP) func(string) bool {
	return func(ip net.IP) func(string) bool {
		if ip == nil {
			return func(string) bool { return false }
		}
		identity := store.BindBootIdentity(ip.String(), time.Duration(cfg().Security.BootGrantTTLMinutes)*time.Minute)
		mac, _ := net.ParseMAC(identity.MAC())
		return func(suffix string) bool {
			img, ok := imageForTarget(suffix)
			if !ok {
				return false
			}
			decision := rules.Evaluate(cfg(), mac, ip)
			return !decision.Deny && (decision.Menu == nil || slices.Contains(decision.Menu, img.FileName)) && identity.Authorize()
		}
	}
}
