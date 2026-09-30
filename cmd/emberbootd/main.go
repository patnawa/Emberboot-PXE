// Command emberbootd is the Emberboot daemon: proxyDHCP + TFTP (iPXE only) +
// HTTP boot services with a read-mostly ops dashboard. Crash-only: all
// durable truth lives in the config file and image folder; restarting is
// always safe.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
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
	"emberboot/internal/iscsisrv"
	"emberboot/internal/logging"
	"emberboot/internal/metrics"
	"emberboot/internal/netutil"
	"emberboot/internal/sessions"
	"emberboot/internal/tftpsrv"
)

var version = "dev" // overridden via -ldflags at release build

func main() {
	if len(os.Args) > 1 && os.Args[1] == "hash-password" {
		if err := hashPassword(); err != nil {
			fmt.Fprintln(os.Stderr, "hash-password:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "emberbootd:", err)
		os.Exit(1)
	}
}

const (
	minAdminPasswordBytes = 12
	maxAdminPasswordBytes = 72
)

// hashPassword reads and confirms a password before printing the bcrypt hash
// used by auth.admin_password_hash.
func hashPassword() error {
	fmt.Fprint(os.Stderr, "Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	fmt.Fprint(os.Stderr, "Confirm password: ")
	confirmation, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("read password confirmation: %w", err)
	}
	hash, err := hashAdminPassword(pw, confirmation)
	if err != nil {
		return err
	}
	fmt.Println(string(hash))
	return nil
}

func hashAdminPassword(password, confirmation []byte) ([]byte, error) {
	if len(password) < minAdminPasswordBytes {
		return nil, fmt.Errorf("password must be at least %d UTF-8 bytes", minAdminPasswordBytes)
	}
	if len(password) > maxAdminPasswordBytes {
		return nil, fmt.Errorf("password must be at most %d UTF-8 bytes", maxAdminPasswordBytes)
	}
	if !bytes.Equal(password, confirmation) {
		return nil, fmt.Errorf("password confirmation does not match")
	}
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	return hash, nil
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
  # First-run management is local-only. Set a password and TLS certificate
  # before changing this to a management-VLAN address.
  dashboard_bind: "127.0.0.1:8443"

images:
  dir: images                 # drop ISOs here
  answers_dir: answers
`, site)
	if err := os.WriteFile(path, []byte(starter), 0o600); err != nil {
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
	if migrated, err := httpsrv.MigrateLegacyAPITokens(mgr); err != nil {
		return fmt.Errorf("secure legacy API tokens: %w", err)
	} else if migrated > 0 {
		boot.Info("migrated plaintext API tokens to one-way verifiers", "count", migrated)
	}
	cfg := mgr.Current()
	runtimeCfg := *cfg // immutable restart-bound listener/path snapshot
	runtimeISCSIEnabled := runtimeCfg.ISCSIActive()
	if err := config.ValidateRuntimePathTopology(*configPath, &runtimeCfg); err != nil {
		return fmt.Errorf("unsafe runtime path layout: %w", err)
	}
	if err := secureRegularFile(*configPath, 0o600); err != nil {
		return fmt.Errorf("secure config file: %w", err)
	}
	if cfg.Network.DashboardTLSCert != "" {
		if _, err := tls.LoadX509KeyPair(cfg.Network.DashboardTLSCert, cfg.Network.DashboardTLSKey); err != nil {
			return fmt.Errorf("dashboard TLS certificate/key: %w", err)
		}
	}
	grantKey, err := loadOrCreateSecret(filepath.Join(filepath.Dir(runtimeCfg.Sessions.DBPath), "boot-grant.key"))
	if err != nil {
		return fmt.Errorf("boot authorization key: %w", err)
	}
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
	if advertise == nil {
		return fmt.Errorf("network.advertise_ip must be an IPv4 address")
	}
	httpBase := fmt.Sprintf("http://%s", net.JoinHostPort(advertise.String(), strconv.Itoa(cfg.Network.HTTPPort)))
	log.Info("network identity", "advertise_ip", advertise.String(), "http_base", httpBase,
		"dhcp_mode", string(cfg.Network.DHCPMode))

	m := metrics.New()
	notifier := alerts.New(log, func() (string, string) {
		c := mgr.Current()
		return c.Site, c.Alerts.WebhookURL
	})
	notifier.OnAccepted(func(kind alerts.Kind) {
		m.AlertsFired.WithLabelValues(string(kind)).Inc()
	})
	notifierFire := func(kind alerts.Kind, key, msg string, details map[string]string) {
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
	cleanExit := false
	// This defer was registered before service cleanup defers, so it runs
	// last. A hung/failed teardown is never recorded as a clean stop.
	defer func() {
		if recovered := recover(); recovered != nil {
			panic(recovered) // keep the crash marker armed on teardown panic
		}
		if cleanExit {
			disarm()
		}
	}()

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
	store.OnDrop(func(operation string) { m.SessionTelemetryDropped.WithLabelValues(operation).Inc() })
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
	defer imgMgr.Close()
	mgr.OnChange(func(*config.Config) { imgMgr.OnConfigChange() })

	// Config file watcher.
	watchStop := make(chan struct{})
	defer close(watchStop)
	if err := mgr.Watch(watchStop); err != nil {
		return err
	}

	errc := make(chan error, 8)

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

	// The optional iSCSI target starts only when explicitly enabled (or when
	// a legacy config has an ACL). Direct target access receives the same
	// current deny/menu policy as signed HTTP boot paths.
	if runtimeISCSIEnabled {
		iscsiServer := iscsisrv.New(iscsisrv.Deps{
			Log: log, Provider: imgMgr, AdvertiseIP: advertise.String(),
			Port:                runtimeCfg.Network.ISCSIPort,
			MaxConnections:      runtimeCfg.Network.ISCSIMaxConnections,
			MaxConnectionsPerIP: runtimeCfg.Network.ISCSIMaxConnectionsPerIP,
			AllowSourceIP: func(ip net.IP) bool {
				for _, cidr := range mgr.Current().Security.ISCSIAllowedSubnets {
					_, network, parseErr := net.ParseCIDR(cidr)
					if parseErr == nil && network.Contains(ip) {
						return true
					}
				}
				return false
			},
			NewTargetPolicy: iscsiTargetPolicy(mgr.Current, store, imgMgr.ImageForTarget),
			OnAttach: func(clientIP, target string) {
				id := store.TouchByIP(clientIP, "payload", "attached iSCSI virtual CD "+target)
				store.FinishID(id, sessions.ResultHandoff,
					"iSCSI virtual CD attached; handing control to the client (OS boot not confirmed)")
				log.Info("iscsi attach", "client", clientIP, "target", target)
			},
		})
		go func() { errc <- fmt.Errorf("iscsi: %w", iscsiServer.Serve()) }()
		defer iscsiServer.Close()
		log.Info("iSCSI target enabled", "port", runtimeCfg.Network.ISCSIPort,
			"max_connections", runtimeCfg.Network.ISCSIMaxConnections,
			"max_per_ip", runtimeCfg.Network.ISCSIMaxConnectionsPerIP)
	} else {
		log.Info("iSCSI target disabled; no listener opened")
	}

	// Boot HTTP. Its grant key is durable so installer stage-two URLs remain
	// valid across service restarts/upgrades.
	bootHTTP, err := httpsrv.NewBoot(httpsrv.BootDeps{
		Log: log, Cfg: mgr.Current, Images: imgMgr, Metrics: m, Sessions: store,
		GrantKey: grantKey, RuntimeISCSIPort: runtimeCfg.Network.ISCSIPort,
		RuntimeISCSIEnabled:        &runtimeISCSIEnabled,
		RuntimeAnswersDir:          runtimeCfg.Images.AnswersDir,
		RuntimeHTTPMaxStreams:      runtimeCfg.Network.HTTPMaxStreams,
		RuntimeHTTPMaxStreamsPerIP: runtimeCfg.Network.HTTPMaxStreamsPerIP,
	}, ":"+strconv.Itoa(cfg.Network.HTTPPort))
	if err != nil {
		return err
	}
	go func() { errc <- fmt.Errorf("boot http: %w", bootHTTP.Serve()) }()
	defer bootHTTP.Close()

	// Dashboard/API (optional).
	if bind := cfg.Network.DashboardBind; bind != "" {
		api := httpsrv.NewAPI(httpsrv.APIDeps{
			Log: log, Cfg: mgr, Images: imgMgr, Sessions: store, Alerts: notifier,
			Metrics: m, Version: version, StartTime: start,
			AdvertiseIP: advertise.String(), HTTPBase: httpBase,
			RuntimeConfig: &runtimeCfg,
			LogRing:       ring, RogueActive: dhcpServer.RogueDetectionActive,
		}, bind)
		if cfg.Network.DashboardTLSCert != "" {
			go func() {
				errc <- fmt.Errorf("dashboard: %w", api.ServeTLS(cfg.Network.DashboardTLSCert, cfg.Network.DashboardTLSKey))
			}()
		} else {
			go func() { errc <- fmt.Errorf("dashboard: %w", api.Serve()) }()
		}
		defer api.Close()
		log.Info("dashboard listening", "addr", bind, "tls", cfg.Network.DashboardTLSCert != "")
	}

	log.Info("emberbootd ready",
		"tftp_port", cfg.Network.TFTPPort, "http_port", cfg.Network.HTTPPort)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case s := <-sig:
		log.Info("shutting down", "signal", s.String())
		cleanExit = true
		return nil
	case err := <-errc:
		// A dead listener is fatal by design (crash-only): supervision
		// restarts us, and the crash marker fires the alert.
		return err
	}
}

// loadOrCreateSecret returns a durable, owner-only 32-byte secret. A fully
// written/fsynced temporary inode is hard-linked into place atomically, so a
// concurrent first start can never observe a zero-length or partial key.
func loadOrCreateSecret(path string) ([]byte, error) {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return nil, fmt.Errorf("secure secret directory: %w", err)
	}
	for {
		data, exists, err := readSecretFile(path)
		if err != nil {
			return nil, err
		}
		if exists {
			if len(data) == 32 {
				return data, nil
			}
			return nil, fmt.Errorf("%s has %d bytes, want 32", path, len(data))
		}

		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		published, err := publishSecretCandidate(parent, path, key)
		if err != nil {
			return nil, err
		}
		if published {
			return key, nil
		}
	}
}

func publishSecretCandidate(parent, path string, key []byte) (published bool, retErr error) {
	f, err := os.CreateTemp(parent, ".boot-grant-key-*")
	if err != nil {
		return false, err
	}
	tmp := f.Name()
	defer func() {
		_ = f.Close()
		_ = os.Remove(tmp)
	}()
	if err := f.Chmod(0o600); err != nil {
		return false, err
	}
	if _, err := io.Copy(f, bytes.NewReader(key)); err != nil {
		return false, err
	}
	if err := f.Sync(); err != nil {
		return false, err
	}
	if err := f.Close(); err != nil {
		return false, err
	}
	if err := os.Link(tmp, path); err != nil {
		if os.IsExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("publish secret: %w", err)
	}
	if err := syncDirectory(parent); err != nil {
		return false, fmt.Errorf("sync published secret: %w", err)
	}
	if err := os.Remove(tmp); err != nil {
		return false, err
	}
	if err := syncDirectory(parent); err != nil {
		return false, err
	}
	return true, nil
}

func readSecretFile(path string) ([]byte, bool, error) {
	pathInfo, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return nil, true, fmt.Errorf("%s must be a regular non-symlink file", path)
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil {
		return nil, true, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return nil, true, fmt.Errorf("%s changed while it was opened", path)
	}
	if err := f.Chmod(0o600); err != nil {
		return nil, true, fmt.Errorf("secure %s: %w", path, err)
	}
	data, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil {
		return nil, true, err
	}
	return data, true, nil
}

func secureRegularFile(path string, mode os.FileMode) error {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular non-symlink file", path)
	}
	return os.Chmod(path, mode)
}

func syncDirectory(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
