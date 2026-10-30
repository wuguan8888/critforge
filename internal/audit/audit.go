// Package audit is CritForge's append-only audit spine.
//
// It writes structured entries to PostgreSQL when DATABASE_URL is configured,
// otherwise it appends to a JSONL file. Entries are never mutated or deleted.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Entry is one append-only audit record.
type Entry struct {
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Scope     string    `json:"scope"`
	Detail    string    `json:"detail,omitempty"`
}

// Sink receives audit entries.
type Sink interface {
	Write(Entry) error
}

// JSONLSink appends entries to a JSONL file.
type JSONLSink struct{ Path string }

// Write appends e as one JSON line.
func (j JSONLSink) Write(e Entry) error {
	f, err := os.OpenFile(j.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	return nil
}

// Default returns the configured sink. DB wiring is an M1+ concern; M0 uses JSONL.
func Default() Sink {
	path := os.Getenv("CRITFORGE_AUDIT_LOG")
	if path == "" {
		path = "critforge-audit.jsonl"
	}
	return JSONLSink{Path: path}
}

// Record is a convenience helper that stamps the time and writes one entry.
func Record(s Sink, actor, action, scope, detail string) error {
	return s.Write(Entry{
		Timestamp: time.Now().UTC(),
		Actor:     actor,
		Action:    action,
		Scope:     scope,
		Detail:    detail,
	})
}
