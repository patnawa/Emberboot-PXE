package config

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

// ValidateRuntimePathTopology checks relationships that cannot be validated
// from YAML alone because the config file path is part of the trust boundary.
// Management writes call this before committing so a change cannot be
// reported as valid only to make the next restart fail.
func ValidateRuntimePathTopology(configPath string, cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	canonical := func(path string) (string, error) {
		abs, err := filepath.Abs(path)
		if err != nil {
			return "", err
		}
		abs = filepath.Clean(abs)
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			abs = resolved
		} else if resolvedParent, parentErr := filepath.EvalSymlinks(filepath.Dir(abs)); parentErr == nil {
			abs = filepath.Join(resolvedParent, filepath.Base(abs))
		}
		if runtime.GOOS == "windows" {
			abs = strings.ToLower(abs)
		}
		return filepath.Clean(abs), nil
	}
	resolve := func(name, path string) (string, error) {
		p, err := canonical(path)
		if err != nil {
			return "", fmt.Errorf("%s: %w", name, err)
		}
		return p, nil
	}
	imageDir, err := resolve("images.dir", cfg.Images.Dir)
	if err != nil {
		return err
	}
	answersDir, err := resolve("images.answers_dir", cfg.Images.AnswersDir)
	if err != nil {
		return err
	}
	dbPath, err := resolve("sessions.db_path", cfg.Sessions.DBPath)
	if err != nil {
		return err
	}
	stateDir := filepath.Dir(dbPath)
	if base := strings.ToLower(filepath.Base(dbPath)); base == ".running" || base == "boot-grant.key" {
		return fmt.Errorf("sessions.db_path uses reserved state file name %q", filepath.Base(dbPath))
	}
	dirs := map[string]string{
		"images.dir": imageDir, "images.answers_dir": answersDir, "sessions state directory": stateDir,
	}
	seenDirs := map[string]string{}
	for name, path := range dirs {
		if previous, exists := seenDirs[path]; exists {
			return fmt.Errorf("%s and %s resolve to the same directory %s", previous, name, path)
		}
		seenDirs[path] = name
	}

	files := map[string]string{
		"config":           configPath,
		"sessions.db_path": cfg.Sessions.DBPath,
		"boot grant key":   filepath.Join(filepath.Dir(cfg.Sessions.DBPath), "boot-grant.key"),
		"crash marker":     filepath.Join(filepath.Dir(cfg.Sessions.DBPath), ".running"),
	}
	if cfg.Network.DashboardTLSCert != "" {
		files["dashboard TLS certificate"] = cfg.Network.DashboardTLSCert
		files["dashboard TLS key"] = cfg.Network.DashboardTLSKey
	}
	seenFiles := map[string]string{}
	for name, raw := range files {
		path, err := resolve(name, raw)
		if err != nil {
			return err
		}
		if previous, exists := seenFiles[path]; exists {
			return fmt.Errorf("%s and %s resolve to the same file %s", previous, name, path)
		}
		seenFiles[path] = name
		if filepath.Dir(path) == answersDir {
			return fmt.Errorf("%s is inside images.answers_dir and could be replaced through answer management", name)
		}
	}
	return nil
}
