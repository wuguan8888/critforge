"""FN/FP regression calibration for secret-pattern detection (synthetic only)."""
from critforge.github_recon import _scan_text
from tests.fixtures.secret_pattern_samples import NEGATIVE, POSITIVE

MAX_FN_RATE = 0.0
MAX_FP_RATE = 0.2


def _types(line):
    return {h.secret_type for h in _scan_text("synthetic/samples", "sample.txt", line) if h.kind == "secret"}


def test_false_negative_rate_within_budget():
    missed = [t for t, line in POSITIVE if t not in _types(line)]
    assert len(missed) / len(POSITIVE) <= MAX_FN_RATE, missed


def test_false_positive_rate_within_budget():
    fps = [l for l in NEGATIVE if _types(l)]
    assert len(fps) / len(NEGATIVE) <= MAX_FP_RATE, fps


def test_evidence_never_contains_full_value():
    for _, line in POSITIVE:
        for h in _scan_text("s/s", "f", line):
            assert "x" * 20 not in h.evidence_redacted
            assert "0" * 20 not in h.evidence_redacted
