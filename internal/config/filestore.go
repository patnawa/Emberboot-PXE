package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/goccy/go-yaml"
)

// This file implements ADR-0004: the management UI edits the config *file*.
// Structured patches load the YAML as an order-preserving document, apply
// path mutations, and the result is only written (atomically) if the whole
// document passes the same validation as a hand edit.

// PatchOp is one mutation: set Value at Path, or delete Path.
type PatchOp struct {
	Path   []string `json:"path"`
	Value  any      `json:"value,omitempty"`
	Delete bool     `json:"delete,omitempty"`
}

// RawBytes returns the config file as it is on disk.
func (m *Manager) RawBytes() ([]byte, error) {
	return readConfigFile(m.path)
}

// SaveRaw validates a complete replacement document and, if valid, writes it
// atomically and reloads. Invalid content is rejected with the parse error
// and the file is untouched.
func (m *Manager) SaveRaw(data []byte) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	return m.saveRawLocked(data)
}

func (m *Manager) saveRawLocked(data []byte) error {
	normalized, cfg, migrated, err := normalizeConfigAPITokens(data)
	if err != nil {
		return err
	}
	if err := ValidateRuntimePathTopology(m.path, cfg); err != nil {
		return err
	}
	if err := writeConfigAtomic(m.path, normalized); err != nil {
		return err
	}
	if migrated > 0 {
		m.log.Info("migrated plaintext API tokens to one-way verifiers", "count", migrated)
	}
	return m.reloadLocked()
}

// writeConfigAtomic durably replaces a validated config document with private
// permissions. Callers must hold Manager.writeMu when the target belongs to a
// live manager.
func writeConfigAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".emberboot-config-*")
	if err != nil {
		return fmt.Errorf("create config temp file: %w", err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("secure config temp file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync config: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	if err := syncConfigDir(dir); err != nil {
		return fmt.Errorf("sync config directory: %w", err)
	}
	ok = true
	return nil
}

func syncConfigDir(dir string) error {
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

// normalizeConfigAPITokens validates data and replaces legacy plaintext API
// tokens before the document is allowed to reach disk through a manager write.
// Re-rendering is limited to the migration case; ordinary raw saves retain the
// caller's formatting exactly.
func normalizeConfigAPITokens(data []byte) ([]byte, *Config, int, error) {
	cfg, err := Parse(data)
	if err != nil {
		return nil, nil, 0, err
	}
	tokens, changed := NormalizeLegacyAPITokens(cfg.Auth.APITokens)
	if changed == 0 {
		return data, cfg, 0, nil
	}
	var doc yaml.MapSlice
	if err := yaml.UnmarshalWithOptions(data, &doc, yaml.UseOrderedMap()); err != nil {
		return nil, nil, 0, fmt.Errorf("parse config for token migration: %w", err)
	}
	doc = setPath(doc, []string{"auth", "api_tokens"}, tokens)
	out, err := yaml.Marshal(doc)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("render config after token migration: %w", err)
	}
	normalized, err := Parse(out)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("validate config after token migration: %w", err)
	}
	return out, normalized, changed, nil
}

// Patch applies structured mutations to the file. The document keeps its key
// order; only touched paths change. Comments in rewritten output are not
// preserved (ADR-0004).
func (m *Manager) Patch(ops []PatchOp) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	data, err := readConfigFile(m.path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var doc yaml.MapSlice
	if err := yaml.UnmarshalWithOptions(data, &doc, yaml.UseOrderedMap()); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	for _, op := range ops {
		if len(op.Path) == 0 {
			return fmt.Errorf("patch op with empty path")
		}
		if op.Delete {
			doc = deletePath(doc, op.Path)
		} else {
			doc = setPath(doc, op.Path, op.Value)
		}
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("render config: %w", err)
	}
	return m.saveRawLocked(out)
}

// UpdateAPITokens atomically performs a read-modify-write of the token list.
// The callback runs while the config write lock is held and receives a copy;
// it must not retain the slice or call another Manager write method.
func (m *Manager) UpdateAPITokens(update func(current []string) ([]string, error)) error {
	if update == nil {
		return fmt.Errorf("API token update callback is nil")
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	data, err := readConfigFile(m.path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return err
	}
	next, err := update(append([]string(nil), cfg.Auth.APITokens...))
	if err != nil {
		return err
	}
	if slices.Equal(next, cfg.Auth.APITokens) {
		return nil
	}
	var doc yaml.MapSlice
	if err := yaml.UnmarshalWithOptions(data, &doc, yaml.UseOrderedMap()); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	doc = setPath(doc, []string{"auth", "api_tokens"}, append([]string(nil), next...))
	out, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("render config: %w", err)
	}
	return m.saveRawLocked(out)
}

// setPath sets value at path, creating intermediate maps as needed.
func setPath(doc yaml.MapSlice, path []string, value any) yaml.MapSlice {
	key := path[0]
	for i, item := range doc {
		if fmt.Sprint(item.Key) != key {
			continue
		}
		if len(path) == 1 {
			doc[i].Value = value
		} else {
			child, _ := item.Value.(yaml.MapSlice)
			doc[i].Value = setPath(child, path[1:], value)
		}
		return doc
	}
	// Key absent: append.
	if len(path) == 1 {
		return append(doc, yaml.MapItem{Key: key, Value: value})
	}
	return append(doc, yaml.MapItem{Key: key, Value: setPath(nil, path[1:], value)})
}

// deletePath removes the entry at path; missing paths are a no-op.
func deletePath(doc yaml.MapSlice, path []string) yaml.MapSlice {
	key := path[0]
	for i, item := range doc {
		if fmt.Sprint(item.Key) != key {
			continue
		}
		if len(path) == 1 {
			return append(doc[:i], doc[i+1:]...)
		}
		if child, ok := item.Value.(yaml.MapSlice); ok {
			doc[i].Value = deletePath(child, path[1:])
		}
		return doc
	}
	return doc
}

// Redacted returns the effective config as a YAML-keyed map for the UI, with
// secrets removed.
func (m *Manager) Redacted() (map[string]any, error) {
	cfg := *m.Current()
	cfg.Auth = Auth{} // never ship secrets to the browser
	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := yaml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	delete(out, "auth")
	return out, nil
}
