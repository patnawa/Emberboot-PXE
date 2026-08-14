package config

import (
	"fmt"
	"os"

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
	return os.ReadFile(m.path)
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
	if _, err := Parse(data); err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Rename(tmp, m.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("write config: %w", err)
	}
	return m.Reload()
}

// Patch applies structured mutations to the file. The document keeps its key
// order; only touched paths change. Comments in rewritten output are not
// preserved (ADR-0004).
func (m *Manager) Patch(ops []PatchOp) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	data, err := os.ReadFile(m.path)
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
