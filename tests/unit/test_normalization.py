import pytest
from app.services.normalization import normalize


@pytest.mark.parametrize("kind,value,canonical", [
    ("domain", " EXAMPLE.COM. ", "example.com"),
    ("domain", "bücher.example", "xn--bcher-kva.example"),
    ("ipv4", "192.0.2.1", "192.0.2.1"),
    ("ipv6", "2001:0DB8:0:0:0:0:0:1", "2001:db8::1"),
    ("url", "HTTPS://EXAMPLE.COM:443#section", "https://example.com/"),
    ("url", "http://[2001:0db8::1]:8080/a?b=2&a=1", "http://[2001:db8::1]:8080/a?b=2&a=1"),
    ("url", "https://bücher.example/Path?X=Y", "https://xn--bcher-kva.example/Path?X=Y"),
    ("organization", "  Example   COMPANY ", "example company"),
    ("username", " CaseSensitive ", "CaseSensitive"),
    ("email", "User@EXAMPLE.COM", "User@example.com"),
])
def test_deterministic_and_idempotent(kind, value, canonical):
    result = normalize(kind, value)
    assert result[1] == canonical
    assert normalize(kind, value) == result
    assert normalize(kind, canonical)[1] == canonical


@pytest.mark.parametrize("kind,value", [
    ("domain", "bad..example"), ("domain", "example.com.."), ("domain", "-bad.example"),
    ("domain", "192.0.2.1"), ("domain", "https://example.com"),
    ("ipv4", "2001:db8::1"), ("ipv4", "999.1.1.1"), ("ipv4", "192.000.2.1"),
    ("ipv6", "192.0.2.1"), ("ipv6", "fe80::1%eth0"),
    ("url", "file:///etc/passwd"), ("url", "https://user:password@example.com"),
    ("url", "https://example.com:99999"), ("url", "https://example.com/%zz"),
    ("url", "https://example.com\\evil"), ("url", "https://example.com/with space"),
    ("email", "a..b@example.com"), ("email", "a@@example.com"),
    ("username", "two words"), ("organization", "   "),
    ("domain", "example.com\n"), ("username", "hidden\u202etext"), ("unknown", "example.com"),
])
def test_invalid_values_fail(kind, value):
    with pytest.raises(ValueError):
        normalize(kind, value)
