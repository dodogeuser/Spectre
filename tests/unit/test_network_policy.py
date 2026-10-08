import asyncio
import socket
import time

import pytest

from app.config import Settings
from app.security.rate_limit import HostRateLimiter
from app.security.url_policy import NetworkPolicyError, public_address, resolve_public, validate_url
from app.services.http_client import ControlledHttpClient, HttpResult, PinnedHTTPSConnection, ResponseLimitError, exchange


@pytest.mark.parametrize("url", [
    "http://example.com", "file:///secret", "ftp://example.com", "https://localhost", "https://a.localhost",
    "https://127.0.0.1", "https://10.0.0.1", "https://172.16.0.1", "https://192.168.0.1",
    "https://169.254.169.254", "https://100.100.100.200", "https://[::1]", "https://[fe80::1]",
    "https://[::ffff:127.0.0.1]", "https://224.0.0.1", "https://0.0.0.0", "https://user:pass@example.com",
    "https://example.com:8443", "https://example.com:0", "https://168.63.129.16",
    "https://example.com\\@127.0.0.1", "https://example.com\n", "https://metadata.internal",
])
def test_disallowed_urls(url):
    with pytest.raises(NetworkPolicyError):
        validate_url(url)


def test_dns_mixed_and_alternate_ip_spelling(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("8.8.8.8", 443)), (2, 1, 6, "", ("127.0.0.1", 443))])
    with pytest.raises(NetworkPolicyError):
        resolve_public("example.com", 443)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 443))])
    with pytest.raises(NetworkPolicyError):
        resolve_public(validate_url("https://2130706433").host, 443)


def settings(**kwargs):
    return Settings(_env_file=None, collector_host_interval_seconds=0.1, **kwargs)


def test_redirect_private_and_mixed_dns_never_connect():
    calls = []
    def transport(destination, address, deadline, limit):
        calls.append((destination.host, address))
        return HttpResult(destination.url, {"status": 302, "headers": {"location": "https://169.254.169.254/latest"}}, b"")
    client = ControlledHttpClient(settings(), HostRateLimiter(), resolver=lambda *a: ("8.8.8.8",), transport=transport)
    with pytest.raises(NetworkPolicyError):
        asyncio.run(client.get("https://example.com"))
    assert calls == [("example.com", "8.8.8.8")]
    calls.clear()
    client.resolver = lambda *a: ("8.8.8.8", "10.0.0.1")
    with pytest.raises(NetworkPolicyError):
        asyncio.run(client.get("https://example.com"))
    assert calls == []


def test_retry_ceiling_and_deadline():
    attempts = []
    def fail(*args):
        attempts.append(1)
        raise OSError("fixture")
    client = ControlledHttpClient(settings(collector_retries=2), HostRateLimiter(), resolver=lambda *a: ("8.8.8.8",), transport=fail)
    with pytest.raises(OSError):
        asyncio.run(client.get("https://example.com"))
    assert len(attempts) == 3
    def slow_resolve(*args):
        time.sleep(0.4)
        return ("8.8.8.8",)
    client = ControlledHttpClient(settings(collector_timeout_seconds=0.1), HostRateLimiter(), resolver=slow_resolve, transport=fail)
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        asyncio.run(client.get("https://example.com"))
    assert time.monotonic() - start < 0.35
    assert len(attempts) == 3


def test_rate_limit_and_redirect_ceiling():
    limiter = HostRateLimiter()
    deadline = time.monotonic() + 2
    assert limiter.reserve("a.example", 0.1, deadline) == 0
    assert limiter.reserve("a.example", 0.1, deadline) > 0
    assert limiter.reserve("b.example", 0.1, deadline) == 0
    with pytest.raises(TimeoutError):
        limiter.reserve("a.example", 0.1, time.monotonic())
    calls = []
    def redirect(destination, *args):
        calls.append(1)
        return HttpResult(destination.url, {"status": 302, "headers": {"location": "/again"}}, b"")
    client = ControlledHttpClient(settings(collector_max_redirects=1), HostRateLimiter(), resolver=lambda *a: ("8.8.8.8",), transport=redirect)
    with pytest.raises(NetworkPolicyError):
        asyncio.run(client.get("https://example.com"))
    assert len(calls) == 2


def test_pinned_connection_preserves_tls_hostname(monkeypatch):
    connected, tls = [], []
    class FakeSocket:
        def close(self):
            pass
    raw = FakeSocket()
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: connected.append(address) or raw)
    connection = PinnedHTTPSConnection(validate_url("https://example.com"), "8.8.8.8", 1)
    class TLS:
        def wrap_socket(self, sock, server_hostname):
            tls.append(server_hostname)
            return sock
    connection._context = TLS()
    connection.connect()
    assert connected == [("8.8.8.8", 443)]
    assert tls == ["example.com"]
    connection.close()


def test_provider_media_type_and_backoff_stay_inside_network_policy():
    calls = []
    limiter = HostRateLimiter()
    def unavailable(destination, *args):
        calls.append(destination.accept)
        return HttpResult(destination.url, {"status": 429, "headers": {"retry-after": "120"}}, b"quota")
    client = ControlledHttpClient(settings(), limiter, resolver=lambda *a: ("8.8.8.8",), transport=unavailable)
    assert asyncio.run(client.get("https://example.com", accept="application/dns-message")).metadata["status"] == 429
    assert calls == ["application/dns-message"]
    with pytest.raises(TimeoutError):
        asyncio.run(client.get("https://example.com"))
    with pytest.raises(NetworkPolicyError):
        asyncio.run(client.get("https://example.com", accept="arbitrary/header"))
    assert len(calls) == 1


@pytest.mark.parametrize("mode", ["declared", "streamed", "compressed"])
def test_real_exchange_limits(monkeypatch, mode):
    from app.services import http_client
    sent = []
    class Response:
        status = 200
        def getheaders(self):
            return []
        def getheader(self, key, default=None):
            return {"Content-Length": "2048" if mode == "declared" else None,
                    "Content-Encoding": "gzip" if mode == "compressed" else "identity"}.get(key, default)
        def read1(self, size):
            return b"x" * size
    class Connection:
        sock = None
        def __init__(self, *a):
            pass
        def request(self, *a, **k):
            sent.append(k["headers"])
        def getresponse(self):
            return Response()
        def close(self):
            sent.append("closed")
    monkeypatch.setattr(http_client, "PinnedHTTPSConnection", Connection)
    with pytest.raises(ResponseLimitError):
        exchange(validate_url("https://example.com"), "8.8.8.8", time.monotonic() + 1, 1024)
    assert sent[0]["User-Agent"].startswith("SPECTRE/")
    assert sent[0]["Accept-Encoding"] == "identity"
    assert sent[-1] == "closed"


@pytest.mark.parametrize("location", ["https://127.0.0.1/", "http://example.net/", "https://169.254.169.254/", "https://private.example/"])
def test_web_redirect_policy_blocks_before_second_request(location):
    calls = []
    def resolver(host,port):
        return ("10.0.0.1",) if host == "private.example" else ("8.8.8.8",)
    def transport(destination,*args):
        calls.append(destination.url)
        return HttpResult(destination.url,{"status":302,"headers":{"location":location}},b"")
    client=ControlledHttpClient(settings(),HostRateLimiter(),resolver=resolver,transport=transport)
    with pytest.raises(NetworkPolicyError):
        asyncio.run(client.get("https://example.com/",accept="text/html,application/xhtml+xml"))
    assert len(calls)==1


def test_web_binary_aborts_before_body_read(monkeypatch):
    from dataclasses import replace
    from app.services import http_client
    class Response:
        status=200
        def getheaders(self): return [("Content-Type","application/pdf")]
        def read1(self,size): raise AssertionError("Binary body must not be read")
    class Connection:
        def __init__(self,*a): pass
        def request(self,*a,**kwargs):
            assert kwargs["headers"]["Accept"] == "text/html,application/xhtml+xml"
            assert "Cookie" not in kwargs["headers"] and "Authorization" not in kwargs["headers"]
        def getresponse(self): return Response()
        def close(self): pass
    monkeypatch.setattr(http_client,"PinnedHTTPSConnection",Connection)
    with pytest.raises(http_client.UnsupportedContentError):
        exchange(replace(validate_url("https://example.com/"),accept="text/html,application/xhtml+xml"),"8.8.8.8",time.monotonic()+1,1024)


def test_public_web_redirect_retains_chain_and_never_submits_data():
    calls=[]
    def transport(destination,*args):
        calls.append(destination)
        if len(calls)==1:
            return HttpResult(destination.url,{"status":302,"headers":{"location":"https://example.net/final"}},b"")
        return HttpResult(destination.url,{"status":200,"headers":{"content-type":"text/html"}},b"<title>Final</title>")
    client=ControlledHttpClient(settings(),HostRateLimiter(),resolver=lambda *a:("8.8.8.8",),transport=transport)
    result=asyncio.run(client.get("https://example.com/",accept="text/html,application/xhtml+xml"))
    assert result.source_ref=="https://example.net/final" and len(calls)==2
    assert result.metadata["redirects"][0]["status"]==302
    assert all(call.accept=="text/html,application/xhtml+xml" for call in calls)
