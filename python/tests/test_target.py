import pytest

from critforge.target import parse, TargetParseError


def test_parse_plain_hostname():
    t = parse("example.com")
    assert t.host == "example.com"
    assert t.scheme is None
    assert t.port is None
    assert not t.is_ip


def test_parse_url_with_scheme_path():
    t = parse("https://Sub.Example.com/admin/login")
    assert t.scheme == "https"
    assert t.host == "sub.example.com"
    assert t.port == 443  # scheme default
    assert t.path == "/admin/login"
    assert not t.is_ip


def test_parse_host_with_explicit_port():
    t = parse("http://example.com:8080/x")
    assert t.port == 8080
    assert t.scheme == "http"


def test_parse_ipv4():
    t = parse("10.0.0.5")
    assert t.is_ip and t.ip_version == 4
    assert t.host == "10.0.0.5"


def test_parse_ipv4_with_port():
    t = parse("10.0.0.5:443")
    assert t.is_ip and t.port == 443


def test_parse_ipv6_bracketed_url():
    t = parse("http://[2001:db8::1]:8443/p")
    assert t.is_ip and t.ip_version == 6
    assert t.host == "2001:db8::1"
    assert t.port == 8443


def test_parse_ipv6_bare():
    t = parse("2001:db8::1")
    # bare IPv6 is ambiguous w/ ports; our parser treats it as an IPv6 literal
    assert t.is_ip and t.ip_version == 6


def test_trailing_dot_normalized():
    t = parse("Example.COM.")
    assert t.host == "example.com"


@pytest.mark.parametrize("bad", ["", "   ", "has space.com", "http://", "ftp://example.com",
                                  "exa_mple.com", "http://example.com:99999", "-bad.com",
                                  "bad-.com", "http://:80/"])
def test_malformed_inputs_rejected(bad):
    with pytest.raises(TargetParseError):
        parse(bad)
