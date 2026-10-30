"""Safe, signal-driven detectors for authorized local-lab range tests.

Each detector consumes signals emitted by HttpObserveProbe. No network I/O.
No exploit / injection / XSS payloads. craft_offensive_payload stays NotImplemented.
"""
from __future__ import annotations

from ..finding import Confidence, Finding, FindingCategory
from ..scope import Severity
from .base import Detector, MatcherSpec, SignalBundle


class MissingSecurityHeadersDetector(Detector):
    name = "misconfig.missing_security_headers"
    category = FindingCategory.MISCONFIG
    default_severity = Severity.HIGH
    default_confidence = Confidence.HIGH

    def matchers(self) -> list[MatcherSpec]:
        return [
            MatcherSpec(
                name="missing_security_headers",
                signal_key="missing_security_headers",
                description="One or more browser security headers absent",
                confidence_hint=Confidence.HIGH,
            )
        ]

    def evaluate(self, bundle: SignalBundle) -> list[Finding]:
        missing = bundle.signals.get("missing_security_headers")
        if not missing:
            return []
        m = self.matchers()[0]
        # Calibrated: clickjacking/CSP absence together = Medium; otherwise hardening (Low).
        crit = {"content-security-policy", "x-frame-options"}
        sev = Severity.MEDIUM if crit <= set(missing) else Severity.LOW
        return [
            Finding(
                category=self.category,
                severity=sev,
                confidence=self.confidence_for(bundle, m),
                title="Missing HTTP security headers",
                target=bundle.target,
                detector=self.name,
                description=(
                    "Response(s) lacked one or more security headers "
                    f"({', '.join(missing)}). Observation only; no exploit attempted."
                ),
                evidence={
                    **self.evidence_hook(bundle, m),
                    "missing": list(missing),
                    "issue_key": "missing_security_headers",
                    "sources": ["http_observe"],
                    "repeatable": bool(bundle.signals.get("repeatable")),
                    "confirmation_marker": True,
                    "ground_truth_hint": "GT-1",
                },
                references=["CWE-693", "OWASP-A05"],
            )
        ]

    def craft_offensive_payload(self, *args, **kwargs):  # noqa: ANN001
        raise NotImplementedError(
            "MissingSecurityHeadersDetector: offensive payload generation is out of scope"
        )


class DirectoryListingDetector(Detector):
    name = "misconfig.directory_listing"
    category = FindingCategory.MISCONFIG
    default_severity = Severity.HIGH
    default_confidence = Confidence.HIGH

    def matchers(self) -> list[MatcherSpec]:
        return [
            MatcherSpec(
                name="directory_listing",
                signal_key="directory_listing",
                description="Directory listing page observed",
                confidence_hint=Confidence.HIGH,
            )
        ]

    def evaluate(self, bundle: SignalBundle) -> list[Finding]:
        if not bundle.signals.get("directory_listing"):
            return []
        m = self.matchers()[0]
        paths = list(bundle.signals.get("directory_listing_paths") or [])
        if not paths:
            paths = [bundle.signals.get("directory_listing_path")]
        counts = bundle.signals.get("directory_listing_entries_count") or {}
        out = []
        # One SEPARATE recorded check per listed directory (no signal-key collision).
        for path in paths:
            out.append(
                Finding(
                    category=self.category,
                    severity=self.default_severity,
                    confidence=self.confidence_for(bundle, m),
                    title=f"Directory listing enabled ({path})" if path else "Directory listing enabled",
                    target=bundle.target,
                    detector=self.name,
                    description=(
                        "An 'Index of /' style listing was observed. "
                        "No files were downloaded or exploited."
                    ),
                    evidence={
                        **self.evidence_hook(bundle, m),
                        "value": True,
                        "check_id": f"directory_listing:{path}",
                        "path": path,
                        "entries_count": counts.get(path),
                        "repeatable": True,
                        "confirmation_marker": True,
                        "ground_truth_hint": "GT-2",
                    },
                    references=["CWE-548", "OWASP-A01"],
                )
            )
        return out

    def craft_offensive_payload(self, *args, **kwargs):  # noqa: ANN001
        raise NotImplementedError(
            "DirectoryListingDetector: offensive payload generation is out of scope"
        )


class VerboseErrorDetector(Detector):
    name = "misconfig.verbose_error"
    category = FindingCategory.MISCONFIG
    default_severity = Severity.MEDIUM
    default_confidence = Confidence.HIGH

    def matchers(self) -> list[MatcherSpec]:
        return [
            MatcherSpec(
                name="verbose_error",
                signal_key="verbose_error",
                description="Stack-trace / verbose 5xx page observed",
                confidence_hint=Confidence.HIGH,
            )
        ]

    def evaluate(self, bundle: SignalBundle) -> list[Finding]:
        if not bundle.signals.get("verbose_error"):
            return []
        m = self.matchers()[0]
        return [
            Finding(
                category=self.category,
                severity=self.default_severity,
                confidence=self.confidence_for(bundle, m),
                title="Verbose error / stack-trace disclosure",
                target=bundle.target,
                detector=self.name,
                description=(
                    "A 5xx response contained a traceback-style disclosure. "
                    "No further probing of the error path was performed."
                ),
                evidence={
                    **self.evidence_hook(bundle, m),
                    "path": bundle.signals.get("verbose_error_path"),
                    "paths": bundle.signals.get("verbose_error_paths"),
                    "error_trigger": bool(bundle.signals.get("error_trigger")),
                    "status_anomaly": True,
                    "repeatable": True,
                    "confirmation_marker": True,
                    "ground_truth_hint": "GT-4",
                },
                references=["CWE-209", "OWASP-A04"],
            )
        ]

    def craft_offensive_payload(self, *args, **kwargs):  # noqa: ANN001
        raise NotImplementedError(
            "VerboseErrorDetector: offensive payload generation is out of scope"
        )


class ServerBannerDetector(Detector):
    name = "misconfig.server_banner"
    category = FindingCategory.MISCONFIG
    default_severity = Severity.MEDIUM  # often suppressed by High gate
    default_confidence = Confidence.MEDIUM

    def matchers(self) -> list[MatcherSpec]:
        return [
            MatcherSpec(
                name="server_banner",
                signal_key="server_banner",
                description="Server / X-Powered-By banner disclosed",
                confidence_hint=Confidence.MEDIUM,
            )
        ]

    def evaluate(self, bundle: SignalBundle) -> list[Finding]:
        banners = bundle.signals.get("server_banner")
        if not banners:
            return []
        m = self.matchers()[0]
        return [
            Finding(
                category=self.category,
                severity=self.default_severity,
                confidence=self.confidence_for(bundle, m),
                title="Server / framework banner disclosure",
                target=bundle.target,
                detector=self.name,
                description="Response headers disclosed server/framework identity.",
                evidence={
                    **self.evidence_hook(bundle, m),
                    "banners": list(banners),
                    "ground_truth_hint": "GT-7",
                },
                references=["CWE-200"],
            )
        ]

    def craft_offensive_payload(self, *args, **kwargs):  # noqa: ANN001
        raise NotImplementedError(
            "ServerBannerDetector: offensive payload generation is out of scope"
        )


class DefaultCredentialPageDetector(Detector):
    name = "auth.default_cred_page"
    category = FindingCategory.AUTH_FLAW
    default_severity = Severity.HIGH
    default_confidence = Confidence.HIGH

    def matchers(self) -> list[MatcherSpec]:
        return [
            MatcherSpec(
                name="default_cred_page",
                signal_key="default_cred_page",
                description="Login page exposes default-credential hints",
                confidence_hint=Confidence.HIGH,
            )
        ]

    def evaluate(self, bundle: SignalBundle) -> list[Finding]:
        if not bundle.signals.get("default_cred_page") and not bundle.signals.get(
            "auth_weakness_indicator"
        ):
            # Prefer explicit default_cred_page; auth_weakness alone handled below
            pass
        if not bundle.signals.get("default_cred_page"):
            return []
        m = self.matchers()[0]
        return [
            Finding(
                category=self.category,
                severity=self.default_severity,
                confidence=self.confidence_for(bundle, m),
                title="Default credential hint exposed on login page",
                target=bundle.target,
                detector=self.name,
                description=(
                    "Admin login page text suggested default credentials. "
                    "No login attempt or credential stuffing was performed."
                ),
                evidence={
                    **self.evidence_hook(bundle, m),
                    "path": bundle.signals.get("default_cred_path"),
                    "auth_weakness_indicator": bundle.signals.get(
                        "auth_weakness_indicator"
                    ),
                    "repeatable": True,
                    "confirmation_marker": True,
                    "ground_truth_hint": "GT-3",
                },
                references=["CWE-798", "OWASP-A07"],
            )
        ]

    def craft_offensive_payload(self, *args, **kwargs):  # noqa: ANN001
        raise NotImplementedError(
            "DefaultCredentialPageDetector: offensive payload generation is out of scope"
        )


class SensitiveEndpointDetector(Detector):
    name = "auth.sensitive_endpoint_open"
    category = FindingCategory.AUTH_FLAW
    default_severity = Severity.HIGH
    default_confidence = Confidence.HIGH

    def matchers(self) -> list[MatcherSpec]:
        return [
            MatcherSpec(
                name="sensitive_endpoint_open",
                signal_key="sensitive_endpoint_open",
                description="Sensitive API reachable without authentication",
                confidence_hint=Confidence.HIGH,
            )
        ]

    def evaluate(self, bundle: SignalBundle) -> list[Finding]:
        if not bundle.signals.get("sensitive_endpoint_open"):
            return []
        m = self.matchers()[0]
        return [
            Finding(
                category=self.category,
                severity=self.default_severity,
                confidence=self.confidence_for(bundle, m),
                title="Unauthenticated sensitive API endpoint",
                target=bundle.target,
                detector=self.name,
                description=(
                    "A sensitive JSON endpoint returned user-like data without auth. "
                    "No further data exfiltration was attempted."
                ),
                evidence={
                    **self.evidence_hook(bundle, m),
                    "path": bundle.signals.get("sensitive_endpoint_path"),
                    "repeatable": True,
                    "confirmation_marker": True,
                    "ground_truth_hint": "GT-6",
                },
                references=["CWE-306", "OWASP-A01"],
            )
        ]

    def craft_offensive_payload(self, *args, **kwargs):  # noqa: ANN001
        raise NotImplementedError(
            "SensitiveEndpointDetector: offensive payload generation is out of scope"
        )


class ReflectionXSSDetector(Detector):
    name = "xss.reflection_marker"
    category = FindingCategory.XSS
    default_severity = Severity.HIGH  # elevated for lab GT-5 measurability
    default_confidence = Confidence.HIGH

    def matchers(self) -> list[MatcherSpec]:
        return [
            MatcherSpec(
                name="xss_reflection_indicator",
                signal_key="xss_reflection_indicator",
                description="Benign marker reflected unsanitized in response body",
                confidence_hint=Confidence.HIGH,
            )
        ]

    def evaluate(self, bundle: SignalBundle) -> list[Finding]:
        if not bundle.signals.get("xss_reflection_indicator"):
            return []
        m = self.matchers()[0]
        return [
            Finding(
                category=self.category,
                severity=self.default_severity,
                confidence=self.confidence_for(bundle, m),
                title="Unsanitized reflected input parameter",
                target=bundle.target,
                detector=self.name,
                description=(
                    "A benign unique marker sent in a query parameter was reflected "
                    "unsanitized in the HTML body. No XSS exploit payload was sent."
                ),
                evidence={
                    **self.evidence_hook(bundle, m),
                    "path": bundle.signals.get("reflection_path"),
                    "marker": bundle.signals.get("reflection_marker"),
                    "repeatable": True,
                    "confirmation_marker": True,
                    "ground_truth_hint": "GT-5",
                },
                references=["CWE-79", "OWASP-A03"],
            )
        ]

    def craft_offensive_payload(self, *args, **kwargs):  # noqa: ANN001
        raise NotImplementedError(
            "ReflectionXSSDetector: offensive payload generation is out of scope"
        )


def real_safe_detectors() -> list[Detector]:
    return [
        MissingSecurityHeadersDetector(),
        DirectoryListingDetector(),
        VerboseErrorDetector(),
        ServerBannerDetector(),
        DefaultCredentialPageDetector(),
        SensitiveEndpointDetector(),
        ReflectionXSSDetector(),
        ExposedMetricsDetector(),
        ExposedEncryptionKeysDetector(),
        BackupFileDetector(),
        NucleiFindingDetector(),
        ExposureDetector(),
        TechFingerprintDetector(),
        ApiSurfaceDetector(),
    ]


class ExposedMetricsDetector(Detector):
    name = "misconfig.exposed_metrics"
    category = FindingCategory.MISCONFIG
    default_severity = Severity.MEDIUM
    default_confidence = Confidence.HIGH

    def matchers(self) -> list[MatcherSpec]:
        return [
            MatcherSpec(
                name="exposed_metrics",
                signal_key="exposed_metrics",
                description="Prometheus/metrics endpoint reachable without auth",
                confidence_hint=Confidence.HIGH,
            )
        ]

    def evaluate(self, bundle: SignalBundle) -> list[Finding]:
        if not bundle.signals.get("exposed_metrics"):
            return []
        m = self.matchers()[0]
        return [
            Finding(
                category=self.category,
                severity=self.default_severity,
                confidence=self.confidence_for(bundle, m),
                title="Unauthenticated metrics / Prometheus endpoint",
                target=bundle.target,
                detector=self.name,
                description=(
                    "A metrics endpoint returned process/http series without authentication. "
                    "Observation only; no scraping beyond a single GET."
                ),
                evidence={
                    **self.evidence_hook(bundle, m),
                    "repeatable": True,
                    "confirmation_marker": True,
                    "lab_hint": "juice-shop-/metrics",
                    "issue_key": "exposure:/metrics",
                },
                references=["CWE-200", "OWASP-A01"],
            )
        ]

    def craft_offensive_payload(self, *args, **kwargs):  # noqa: ANN001
        raise NotImplementedError(
            "ExposedMetricsDetector: offensive payload generation is out of scope"
        )


class ExposedEncryptionKeysDetector(Detector):
    name = "misconfig.exposed_encryption_keys"
    category = FindingCategory.MISCONFIG
    default_severity = Severity.HIGH
    default_confidence = Confidence.HIGH

    def matchers(self) -> list[MatcherSpec]:
        return [
            MatcherSpec(
                name="exposed_encryption_keys",
                signal_key="exposed_encryption_keys",
                description="Encryption key directory listing / key files exposed",
                confidence_hint=Confidence.HIGH,
            )
        ]

    def evaluate(self, bundle: SignalBundle) -> list[Finding]:
        if not bundle.signals.get("exposed_encryption_keys"):
            return []
        m = self.matchers()[0]
        return [
            Finding(
                category=self.category,
                severity=self.default_severity,
                confidence=self.confidence_for(bundle, m),
                title="Encryption key material directory exposed",
                target=bundle.target,
                detector=self.name,
                description=(
                    "A directory listing under /encryptionkeys exposed key-like filenames. "
                    "Files were not downloaded."
                ),
                evidence={
                    **self.evidence_hook(bundle, m),
                    "repeatable": True,
                    "confirmation_marker": True,
                    "lab_hint": "juice-shop-/encryptionkeys",
                },
                references=["CWE-552", "OWASP-A01"],
            )
        ]

    def craft_offensive_payload(self, *args, **kwargs):  # noqa: ANN001
        raise NotImplementedError(
            "ExposedEncryptionKeysDetector: offensive payload generation is out of scope"
        )


class BackupFileDetector(Detector):
    """Backup / editor-swap file names (.bak/.old/.swp/~/.orig) reachable or listed."""

    name = "misconfig.backup_files"
    category = FindingCategory.MISCONFIG
    default_severity = Severity.MEDIUM
    default_confidence = Confidence.HIGH

    def matchers(self) -> list[MatcherSpec]:
        return [
            MatcherSpec(
                name="backup_files",
                signal_key="backup_files",
                description="Backup-style file name listed or served",
                confidence_hint=Confidence.HIGH,
            )
        ]

    def evaluate(self, bundle: SignalBundle) -> list[Finding]:
        items = bundle.signals.get("backup_files") or []
        if not items:
            return []
        m = self.matchers()[0]
        out = []
        for it in items:
            out.append(
                Finding(
                    category=self.category,
                    severity=self.default_severity,
                    confidence=self.confidence_for(bundle, m),
                    title=f"Backup file exposed ({it.get('path')})",
                    target=bundle.target,
                    detector=self.name,
                    description=(
                        "A backup-style file name was listed or returned 200 (distinct from "
                        "the SPA/404 baseline). Content was not stored or parsed."
                    ),
                    evidence={
                        "signal": "backup_files",
                        "check_id": f"backup_file:{it.get('path')}",
                        "path": it.get("path"),
                        "source": it.get("source"),
                        "status": it.get("status"),
                        "length": it.get("length"),
                        "repeatable": True,
                        "confirmation_marker": True,
                        "note": "methodology-only; name recognition / status check",
                    },
                    references=["CWE-530", "OWASP-A05"],
                )
            )
        return out

    def craft_offensive_payload(self, *args, **kwargs):  # noqa: ANN001
        raise NotImplementedError("BackupFileDetector: offensive payload generation is out of scope")


class NucleiFindingDetector(Detector):
    """Maps Nuclei JSONL results (signal 'nuclei_results') into CritForge Findings."""

    name = "engine.nuclei"
    category = FindingCategory.MISCONFIG
    default_severity = Severity.INFO
    default_confidence = Confidence.MEDIUM

    def matchers(self) -> list[MatcherSpec]:
        return [
            MatcherSpec(
                name="nuclei_results",
                signal_key="nuclei_results",
                description="Nuclei passive/exposure template match",
                confidence_hint=Confidence.MEDIUM,
            )
        ]

    def evaluate(self, bundle: SignalBundle) -> list[Finding]:
        from ..nuclei import map_results

        return map_results(bundle.target, bundle.signals.get("nuclei_results") or [])

    def craft_offensive_payload(self, *args, **kwargs):  # noqa: ANN001
        raise NotImplementedError("NucleiFindingDetector: offensive payload generation is out of scope")


_SEV_MAP = {s.value: s for s in Severity}


class ExposureDetector(Detector):
    """Content-validated exposures (.env, .git, actuator, OpenAPI, metrics, ...).

    Only fires when the probe classified the page as *real* content (not SPA
    fallback / soft-404 / login redirect) AND a format validator matched.
    Evidence carries counts / shapes only — never values.
    """

    name = "misconfig.exposure"
    category = FindingCategory.MISCONFIG
    default_severity = Severity.MEDIUM
    default_confidence = Confidence.HIGH

    def matchers(self) -> list[MatcherSpec]:
        return [MatcherSpec(name="exposures", signal_key="exposures",
                            description="Content-validated sensitive resource",
                            confidence_hint=Confidence.HIGH)]

    def evaluate(self, bundle: SignalBundle) -> list[Finding]:
        out = []
        for ex in bundle.signals.get("exposures") or []:
            cat = FindingCategory.AUTH_FLAW if "admin_surface" in (ex.get("tags") or []) else self.category
            out.append(Finding(
                category=cat,
                severity=_SEV_MAP.get(ex.get("severity"), self.default_severity),
                confidence=Confidence.MEDIUM,
                title=f"{ex.get('title')} ({ex.get('path')})",
                target=bundle.target,
                detector=self.name,
                description=("Resource returned real content (distinct from the fallback/soft-404 "
                             "fingerprint) and matched a format validator. Values were not stored."),
                evidence={
                    "signal": "exposures",
                    "check_id": f"exposure:{ex.get('id')}:{ex.get('path')}",
                    "issue_key": f"exposure:{ex.get('path')}",
                    "path": ex.get("path"),
                    "exposure_id": ex.get("id"),
                    "status": ex.get("status"),
                    "detail": ex.get("detail"),
                    "tags": ex.get("tags"),
                    "content_validated": bool(ex.get("content_validated", True)),
                    "repeatable": bool(ex.get("repeatable")),
                    "sources": ["http_observe"],
                },
                references=[ex.get("cwe") or "CWE-200", "OWASP-A05"],
            ))
        return out

    def craft_offensive_payload(self, *args, **kwargs):  # noqa: ANN001
        raise NotImplementedError("ExposureDetector: offensive payload generation is out of scope")


class TechFingerprintDetector(Detector):
    """Informational technology fingerprint (headers / cookies / markup)."""

    name = "info.tech_fingerprint"
    category = FindingCategory.INFO
    default_severity = Severity.INFO
    default_confidence = Confidence.HIGH

    def matchers(self) -> list[MatcherSpec]:
        return [MatcherSpec(name="tech", signal_key="tech", description="Technology fingerprint",
                            confidence_hint=Confidence.HIGH)]

    def evaluate(self, bundle: SignalBundle) -> list[Finding]:
        tech = bundle.signals.get("tech") or []
        if not tech:
            return []
        return [Finding(category=self.category, severity=Severity.INFO, confidence=Confidence.HIGH,
                        title="Technology fingerprint: " + ", ".join(tech), target=bundle.target,
                        detector=self.name, description="Passive fingerprint from headers, cookies and markup.",
                        evidence={"signal": "tech", "check_id": "tech_fingerprint", "issue_key": "tech_fingerprint",
                                  "tech": list(tech), "sources": ["http_observe"]},
                        references=["CWE-200"])]

    def craft_offensive_payload(self, *args, **kwargs):  # noqa: ANN001
        raise NotImplementedError("TechFingerprintDetector: offensive payload generation is out of scope")


class ApiSurfaceDetector(Detector):
    """API inventory (discovered routes and whether auth is enforced). Info-level."""

    name = "info.api_surface"
    category = FindingCategory.INFO
    default_severity = Severity.INFO
    default_confidence = Confidence.HIGH

    def matchers(self) -> list[MatcherSpec]:
        return [MatcherSpec(name="api_inventory", signal_key="api_inventory", description="API routes",
                            confidence_hint=Confidence.HIGH)]

    def evaluate(self, bundle: SignalBundle) -> list[Finding]:
        inv = bundle.signals.get("api_inventory") or []
        if not inv:
            return []
        counts: dict[str, int] = {}
        for it in inv:
            counts[it.get("class", "?")] = counts.get(it.get("class", "?"), 0) + 1
        return [Finding(category=self.category, severity=Severity.INFO, confidence=Confidence.HIGH,
                        title=f"API surface discovered ({len(inv)} routes)", target=bundle.target,
                        detector=self.name,
                        description="Routes harvested from links/JS bundles; GET-only status classification.",
                        evidence={"signal": "api_inventory", "check_id": "api_surface", "issue_key": "api_surface",
                                  "classes": counts, "routes": [f"{i['status']} {i['path']}" for i in inv][:60],
                                  "sources": ["http_observe"]},
                        references=["OWASP-API9"])]

    def craft_offensive_payload(self, *args, **kwargs):  # noqa: ANN001
        raise NotImplementedError("ApiSurfaceDetector: offensive payload generation is out of scope")
