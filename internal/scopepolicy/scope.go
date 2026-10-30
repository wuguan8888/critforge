package scopepolicy

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Severity is an ordered vulnerability severity level.
type Severity string

const (
	SeverityInfo     Severity = "Info"
	SeverityLow      Severity = "Low"
	SeverityMedium   Severity = "Medium"
	SeverityHigh     Severity = "High"
	SeverityCritical Severity = "Critical"
)

var severityRank = map[Severity]int{
	SeverityInfo: 0, SeverityLow: 1, SeverityMedium: 2, SeverityHigh: 3, SeverityCritical: 4,
}

// Meets reports whether s is at or above the gate threshold.
func (s Severity) Meets(threshold Severity) bool {
	return severityRank[s] >= severityRank[threshold]
}

// ModelRouting maps a logical agent role to a model identifier.
type ModelRouting struct {
	Planner  string `yaml:"planner"`
	Worker   string `yaml:"worker"`
	Verifier string `yaml:"verifier"`
}

// Scope is the first-class authorization object for a CritForge engagement.
type Scope struct {
	Project       string       `yaml:"project"`
	Allowlist     []string     `yaml:"allowlist"`
	Denylist      []string     `yaml:"denylist"`
	SeverityGate  Severity     `yaml:"severity_gate"`
	ModelRouting  ModelRouting `yaml:"model_routing"`
	AuthorizedBy  string       `yaml:"authorized_by"`
	Authorization string       `yaml:"authorization_reference"`
}

// Load reads and validates a scope.yaml file.
func Load(path string) (*Scope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scope: %w", err)
	}
	var s Scope
	if err := yaml.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("parse scope: %w", err)
	}
	if s.SeverityGate == "" {
		s.SeverityGate = SeverityHigh // default gate
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// ErrEmptyScope is returned when no authorized targets are configured.
var ErrEmptyScope = errors.New("authorization gate: scope allowlist is empty; CritForge refuses to run")

// Validate enforces the authorization gate.
func (s *Scope) Validate() error {
	hasTarget := false
	for _, a := range s.Allowlist {
		if strings.TrimSpace(a) != "" {
			hasTarget = true
			break
		}
	}
	if !hasTarget {
		return ErrEmptyScope
	}
	if _, ok := severityRank[s.SeverityGate]; !ok {
		return fmt.Errorf("invalid severity_gate %q", s.SeverityGate)
	}
	if strings.TrimSpace(s.AuthorizedBy) == "" {
		return errors.New("authorization gate: authorized_by must be set")
	}
	return nil
}

// InScope reports whether target is authorized (on allowlist and not denied).
func (s *Scope) InScope(target string) bool {
	for _, d := range s.Denylist {
		if strings.EqualFold(strings.TrimSpace(d), target) {
			return false
		}
	}
	for _, a := range s.Allowlist {
		if strings.EqualFold(strings.TrimSpace(a), target) {
			return true
		}
	}
	return false
}
