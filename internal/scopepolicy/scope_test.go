package scopepolicy

import "testing"

func TestEmptyScopeRefuses(t *testing.T) {
	s := &Scope{SeverityGate: SeverityHigh, AuthorizedBy: "x"}
	if err := s.Validate(); err == nil {
		t.Fatal("expected empty scope to be refused")
	}
}

func TestInScopeAndDenylist(t *testing.T) {
	s := &Scope{
		Allowlist:    []string{"example.com"},
		Denylist:     []string{"secret.example.com"},
		SeverityGate: SeverityHigh,
		AuthorizedBy: "tester",
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("valid scope rejected: %v", err)
	}
	if !s.InScope("example.com") {
		t.Error("example.com should be in scope")
	}
	if s.InScope("secret.example.com") {
		t.Error("denylisted host must not be in scope")
	}
	if s.InScope("evil.test") {
		t.Error("unlisted host must not be in scope")
	}
}

func TestSeverityGate(t *testing.T) {
	if !SeverityCritical.Meets(SeverityHigh) {
		t.Error("Critical should meet High gate")
	}
	if SeverityMedium.Meets(SeverityHigh) {
		t.Error("Medium must not pass High gate")
	}
}
