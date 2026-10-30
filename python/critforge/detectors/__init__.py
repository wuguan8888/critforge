"""M3 Vulnerability detection framework (black-box, methodology only).

Detectors consume ProbeResult *signals* (already gathered by the engine) and
emit Finding records. They do NOT send payloads, open sockets, or attack
targets. Where a real detector would need an offensive payload, the method
is left as a NotImplementedError stub with a clear docstring.

Categories: injection, xss, auth_flaw, misconfig.
Plugin surface: MatcherSpec + evidence_hook + confidence_for on Detector base.
"""
from .base import Detector, DetectorRegistry, MatcherSpec, SignalBundle
from .injection import InjectionDetector
from .xss import XSSDetector
from .auth import AuthFlawDetector
from .misconfig import MisconfigDetector
from .real_safe import real_safe_detectors


def default_registry() -> DetectorRegistry:
    r = DetectorRegistry()
    for d in (
        InjectionDetector(),
        XSSDetector(),
        AuthFlawDetector(),
        MisconfigDetector(),
    ):
        r.register(d)
    return r


def lab_safe_registry() -> DetectorRegistry:
    """Real safe detectors for authorized local-lab range tests.

    Intentionally excludes skeleton detectors that share the same signal keys
    (would double-count and inflate false positives).
    """
    r = DetectorRegistry()
    for d in real_safe_detectors():
        r.register(d)
    return r


__all__ = [
    "Detector",
    "DetectorRegistry",
    "MatcherSpec",
    "SignalBundle",
    "InjectionDetector",
    "XSSDetector",
    "AuthFlawDetector",
    "MisconfigDetector",
    "default_registry",
    "lab_safe_registry",
    "real_safe_detectors",
]
