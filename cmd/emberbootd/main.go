// Command emberbootd is the Emberboot daemon: proxyDHCP + TFTP (iPXE only) +
// HTTP boot services with a read-mostly ops dashboard. Crash-only: all
// durable truth lives in the config file and image folder; restarting is
// always safe.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"emberboot/internal/alerts"
	"emberboot/internal/config"
	"emberboot/internal/crashmark"
	"emberboot/internal/dhcpsrv"
	"emberboot/internal/httpsrv"
	"emberboot/internal/images"
	"emberboot/internal/logging"
	"emberboot/internal/metrics"
	"emberboot/internal/netutil"
	"emberboot/internal/sessions"
	"emberboot/internal/tftpsrv"
)

var version = "dev" // overridden via -ldflags at release build

func main() {
	if len(os.Args) > 1 && os.Args[1] == "hash-password" {
		hashPassword()
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "emberbootd:", err)
		os.Exit(1)
	}
}

// hashPassword generates the bcrypt hash for auth.admin_password_hash.
func hashPassword() {
	fmt.Fprint(os.Stderr, "Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reading password:", err)
		os.Exit(1)
	}
	hash, err := bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hashing:", err)
		os.Exit(1)
	}
	fmt.Println(string(hash))
}

// createStarterConfig writes a minimal working config on first run, so a
// fresh install (double-clicked on a new machine) comes up serving instead of
// erroring. An existing file is never touched.
func createStarterConfig(path string, log *slog.Logger) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	site, _ := os.Hostname()
	site = strings.ToLower(site)
	if site == "" {
		site = "site-1"
	}
	starter := fmt.Sprintf(`# Emberboot configuration — created automatically on first run.
# Every option is documented in emberboot.example.yaml. This file
# hot-reloads: edits apply within a second, and an invalid edit is rejected
# while the last good configuration keeps serving.

site: %s

network:
  dhcp_mode: proxy            # coexists with your existing DHCP server
  dashboard_bind: "0.0.0.0:8443"

images:
  dir: images                 # drop ISOs here
  answers_dir: answers
`, site)
	if err := os.WriteFile(path, []byte(starter), 0o644); err != nil {
		return fmt.Errorf("create starter config: %w", err)
	}
	log.Info("no config file found; created a starter config", "path", path, "site", site)
	return nil
}

func run() error {
	configPath := flag.String("config", "emberboot.yaml", "path to config file")
	logLevel := flag.String("log-level", "info", "debug|info|warn|error")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("emberbootd", version)
		return nil
	}

	start := time.Now()
	// One JSON handler wrapped in a ring buffer: stdout for supervision,
	// the ring for the dashboard's diagnostics view.
	ring := logging.NewRing(slog.NewJSONHandler(os.Stdout,
		&slog.HandlerOptions{Level: logging.ParseLevel(*logLevel)}))
	boot := slog.New(ring)
	if err := createStarterConfig(*configPath, boot); err != nil {
		return err
	}
	mgr, err := config.NewManager(*configPath, boot)
	if err != nil {
		return err
	}
	cfg := mgr.Current()
	log := slog.New(ring).With("site", cfg.Site)
	log.Info("emberbootd starting", "version", version, "config", *configPath)

	// Advertise IP: what DHCP tells clients to fetch from.
	advertise := net.ParseIP(cfg.Network.AdvertiseIP)
	if advertise == nil {
		advertise, err = netutil.OutboundIP()
		if err != nil {
			return fmt.Errorf("cannot autodetect advertise IP: %w (set network.advertise_ip)", err)
		}
	}
	advertise = advertise.To4()
	httpBase := fmt.Sprintf("http://%s", net.JoinHostPort(advertise.String(), strconv.Itoa(cfg.Network.HTTPPort)))
	log.Info("network identity", "advertise_ip", advertise.String(), "http_base", httpBase,
		"dhcp_mode", string(cfg.Network.DHCPMode))

	m := metrics.New()
	notifier := alerts.New(log, func() (string, string) {
		c := mgr.Current()
		return c.Site, c.Alerts.WebhookURL
	})
	notifierFire := func(kind alerts.Kind, key, msg string, details map[string]string) {
		m.AlertsFired.WithLabelValues(string(kind)).Inc()
		notifier.Fire(kind, key, msg, details)
	}

	// Crash detection: marker armed before services start.
	wasUnclean, disarm, err := crashmark.Arm(filepath.Dir(cfg.Sessions.DBPath))
	if err != nil {
		return fmt.Errorf("crash marker: %w", err)
	}
	if wasUnclean {
		notifierFire(alerts.CrashRestart, "", "service restarted after an unclean exit", nil)
	}

	// Config reload wiring: metrics + alert on rejection.
	mgr.OnChange(func(*config.Config) { m.ConfigReloads.WithLabelValues("ok").Inc() })
	mgr.OnReject(func(err error) {
		m.ConfigReloads.WithLabelValues("rejected").Inc()
		notifierFire(alerts.ConfigRejected, "", "config reload rejected; serving last known good",
			map[string]string{"error": err.Error()})
	})

	// Boot Session store.
	store, err := sessions.Open(cfg.Sessions.DBPath, log)
	if err != nil {
		return fmt.Errorf("sessions: %w", err)
	}
	defer store.Close()
	store.OnFinish(func(result string) { m.Sessions.WithLabelValues(result).Inc() })
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for range t.C {
			m.SessionsActive.Set(float64(store.ActiveCount()))
		}
	}()

	ctx, stopAll := context.WithCancel(context.Background())
	defer stopAll()

	go store.Janitor(ctx, cfg.Sessions.RetentionDays, cfg.Sessions.MaxSizeMB,
		func() sessions.SpikeConfig {
			fs := mgr.Current().Alerts.FailureSpike
			return sessions.SpikeConfig{
				Window:      time.Duration(fs.WindowMinutes) * time.Minute,
				ThresholdPc: fs.ThresholdPercent,
				MinSessions: fs.MinSessions,
			}
		},
		func(failed, total int) {
			notifierFire(alerts.FailureSpike, "",
				fmt.Sprintf("boot failure spike: %d of %d sessions failed", failed, total),
				map[string]string{"failed": strconv.Itoa(failed), "total": strconv.Itoa(total)})
		})

	// Image manager.
	imgMgr := images.NewManager(log, mgr.Current, m, notifier)
	if err := imgMgr.Start(ctx); err != nil {
		return err
	}
	mgr.OnChange(func(*config.Config) { imgMgr.OnConfigChange() })

	// Config file watcher.
	watchStop := make(chan struct{})
	defer close(watchStop)
	if err := mgr.Watch(watchStop); err != nil {
		return err
	}

	errc := make(chan error, 4)

	// DHCP (proxyDHCP and/or PXE port 4011) + rogue detection.
	dhcpServer, err := dhcpsrv.New(dhcpsrv.Deps{
		Log:         log,
		Cfg:         mgr.Current,
		Metrics:     m,
		Alerts:      notifier,
		Sessions:    store,
		AdvertiseIP: advertise,
		HTTPBase:    httpBase,
	})
	if err != nil {
		return err
	}
	go func() { errc <- fmt.Errorf("dhcp: %w", dhcpServer.Serve()) }()
	defer dhcpServer.Close()

	// TFTP: embedded iPXE only.
	tftpServer := tftpsrv.New(tftpsrv.Deps{Log: log, Metrics: m, Sessions: store, HTTPBase: httpBase})
	go func() {
		errc <- fmt.Errorf("tftp: %w", tftpServer.Serve(":"+strconv.Itoa(cfg.Network.TFTPPort)))
	}()
	defer tftpServer.Shutdown()

	// Boot HTTP.
	bootHTTP := httpsrv.NewBoot(httpsrv.BootDeps{
		Log: log, Cfg: mgr.Current, Images: imgMgr, Metrics: m, Sessions: store,
	}, ":"+strconv.Itoa(cfg.Network.HTTPPort))
	go func() { errc <- fmt.Errorf("boot http: %w", bootHTTP.Serve()) }()
	defer bootHTTP.Close()

	// Dashboard/API (optional).
	if bind := cfg.Network.DashboardBind; bind != "" {
		api := httpsrv.NewAPI(httpsrv.APIDeps{
			Log: log, Cfg: mgr, Images: imgMgr, Sessions: store, Alerts: notifier,
			Metrics: m, Version: version, StartTime: start,
			AdvertiseIP: advertise.String(), HTTPBase: httpBase,
			LogRing: ring, RogueActive: dhcpServer.RogueDetectionActive,
		}, bind)
		go func() { errc <- fmt.Errorf("dashboard: %w", api.Serve()) }()
		defer api.Close()
		log.Info("dashboard listening", "addr", bind)
	}

	log.Info("emberbootd ready",
		"tftp_port", cfg.Network.TFTPPort, "http_port", cfg.Network.HTTPPort)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case s := <-sig:
		log.Info("shutting down", "signal", s.String())
		disarm() // clean exit: no crash alert next start
		return nil
	case err := <-errc:
		// A dead listener is fatal by design (crash-only): supervision
		// restarts us, and the crash marker fires the alert.
		return err
	}
}
