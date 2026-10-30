"""M1 target parsing.

Parse a target input string (URL, hostname, or IPv4/IPv6, with optional port
and path) into a structured, normalized Target. Malformed input raises
TargetParseError — it is never silently accepted.

This module performs NO network access, DNS resolution, scanning, or probing.
It is pure string parsing/normalization.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit


class TargetParseError(ValueError):
    """Raised when a target input string cannot be parsed."""


# Hostname label rules (RFC 1123): letters/digits/hyphen, 1-63 chars per label,
# not starting/ending with hyphen. Underscores are rejected.
_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class Target:
    """A normalized parse of a target input string."""

    raw: str
    scheme: Optional[str]   # "http"/"https"/None if not supplied
    host: str               # normalized: lowercased hostname, or canonical IP
    port: Optional[int]     # explicit or scheme-default, else None
    path: str               # "" if none
    is_ip: bool
    ip_version: Optional[int]  # 4, 6, or None


def _validate_hostname(host: str) -> None:
    if len(host) > 253:
        raise TargetParseError(f"hostname too long: {host!r}")
    labels = host.split(".")
    for label in labels:
        if not _LABEL_RE.match(label):
            raise TargetParseError(f"invalid hostname label {label!r} in {host!r}")


def _parse_host_token(host: str) -> tuple[str, bool, Optional[int]]:
    """Return (normalized_host, is_ip, ip_version). Raises on invalid host."""
    if host == "":
        raise TargetParseError("empty host")
    # IPv6 literal (urlsplit strips the surrounding brackets from .hostname)
    try:
        ip = ipaddress.ip_address(host)
        return (ip.compressed.lower(), True, ip.version)
    except ValueError:
        pass
    normalized = host.lower().rstrip(".")
    if normalized == "":
        raise TargetParseError("empty host")
    _validate_hostname(normalized)
    return (normalized, False, None)


def parse(raw: str) -> Target:
    """Parse raw into a Target. Raises TargetParseError on malformed input."""
    if raw is None:
        raise TargetParseError("target is None")
    s = raw.strip()
    if s == "":
        raise TargetParseError("empty target")
    if any(c.isspace() for c in s):
        raise TargetParseError(f"target contains whitespace: {raw!r}")

    # Bare IP literal (esp. IPv6, which urlsplit would misread as host:port).
    had_scheme_early = bool(re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", s))
    if not had_scheme_early:
        try:
            ip = ipaddress.ip_address(s)
            return Target(
                raw=raw, scheme=None, host=ip.compressed.lower(),
                port=None, path="", is_ip=True, ip_version=ip.version,
            )
        except ValueError:
            pass

    # Ensure urlsplit can find authority. If there's no scheme, add a sentinel
    # one so host/port parse consistently, then drop it.
    had_scheme = bool(re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", s))
    work = s if had_scheme else "//" + s

    try:
        parts = urlsplit(work)
    except ValueError as e:
        raise TargetParseError(f"malformed target {raw!r}: {e}") from e

    scheme = parts.scheme.lower() if had_scheme and parts.scheme else None
    if scheme is not None and scheme not in _DEFAULT_PORTS:
        raise TargetParseError(f"unsupported scheme {scheme!r} in {raw!r}")

    host_raw = parts.hostname
    if not host_raw:
        raise TargetParseError(f"no host found in {raw!r}")

    host, is_ip, ip_version = _parse_host_token(host_raw)

    try:
        port = parts.port
    except ValueError as e:
        raise TargetParseError(f"invalid port in {raw!r}: {e}") from e
    if port is None and scheme in _DEFAULT_PORTS:
        port = _DEFAULT_PORTS[scheme]

    path = parts.path or ""

    return Target(
        raw=raw,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        is_ip=is_ip,
        ip_version=ip_version,
    )
