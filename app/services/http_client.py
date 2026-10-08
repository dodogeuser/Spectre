"""Bounded HTTPS transport using validated, pinned IPs and original-host TLS."""
import asyncio
import base64
import http.client
import socket
import ssl
import time
import threading
from concurrent.futures import Future
from dataclasses import dataclass, replace
from urllib.parse import urljoin

from app.config import Settings
from app.version import VERSION as APP_VERSION
from app.security.rate_limit import HostRateLimiter
from app.security.url_policy import Destination, NetworkPolicyError, resolve_public, validate_url


@dataclass(frozen=True)
class HttpResult:
    source_ref: str
    metadata: dict
    body: bytes


class ResponseLimitError(ValueError):
    pass


class UnsupportedContentError(ResponseLimitError):
    pass


_workers = threading.BoundedSemaphore(8)


async def bounded_call(function, *args, deadline):
    # Daemon workers avoid asyncio.run waiting indefinitely for OS DNS calls.
    # Slots remain occupied until timed-out workers actually exit.
    if not _workers.acquire(blocking=False):
        raise NetworkPolicyError("Network worker capacity exhausted")
    future = Future()
    def work():
        try:
            if future.set_running_or_notify_cancel():
                try:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Request deadline exceeded")
                    future.set_result(function(*args))
                except BaseException as exc:
                    future.set_exception(exc)
        finally:
            _workers.release()
    threading.Thread(target=work, daemon=True).start()
    return await asyncio.wait_for(asyncio.wrap_future(future), timeout=max(0.001, deadline - time.monotonic()))


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, destination: Destination, address: str, timeout: float):
        super().__init__(destination.host, destination.port, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        # The transport never re-resolves the hostname after validation.
        raw = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def exchange(destination: Destination, address: str, deadline: float, max_bytes: int) -> HttpResult:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Request deadline exceeded")
    connection = PinnedHTTPSConnection(destination, address, remaining)
    try:
        connection.request("GET", destination.path, headers={
            "User-Agent": "SPECTRE/" + APP_VERSION + " (authorized research)",
            "Accept": destination.accept,
            "Accept-Encoding": "identity",
        })
        response = connection.getresponse()
        headers = {key.lower(): value for key, value in response.getheaders() if key.lower() in {
            "content-type", "content-length", "content-encoding", "location", "etag", "last-modified", "retry-after",
            "server", "strict-transport-security", "content-security-policy", "content-security-policy-report-only",
            "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy"}}
        if any(len(value) > 8192 for value in headers.values()):
            raise ResponseLimitError("Selected header size exceeds policy")
        if destination.accept == "text/html,application/xhtml+xml" and response.status in {301, 302, 303, 307, 308}:
            # A page redirect needs headers only; never download its incidental body.
            return HttpResult(destination.url, {"status": response.status, "headers": headers, "resolved_ip": address, "bytes": 0}, b"")
        if destination.accept == "text/html,application/xhtml+xml" and response.status not in {301, 302, 303, 307, 308}:
            media = headers.get("content-type", "").split(";", 1)[0].lower().strip()
            allowed = {"text/html", "application/xhtml+xml"} if response.status == 200 else {"text/html", "application/xhtml+xml", "text/plain", "application/json"}
            if media not in allowed:
                raise UnsupportedContentError("Non-HTML or binary response blocked")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise ResponseLimitError("Compressed responses are not accepted")
        length = response.getheader("Content-Length")
        if length is not None and (not length.isdigit() or int(length) > max_bytes):
            raise ResponseLimitError("Response size exceeds policy")
        body = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Request deadline exceeded")
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            chunk = response.read1(min(65536, max_bytes + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > max_bytes:
                raise ResponseLimitError("Response size exceeds policy")
        return HttpResult(destination.url, {"status": response.status, "headers": headers,
                          "resolved_ip": address, "bytes": len(body)}, bytes(body))
    finally:
        connection.close()


class ControlledHttpClient:
    def __init__(self, settings: Settings, limiter: HostRateLimiter, *, resolver=resolve_public, transport=exchange):
        self.settings, self.limiter = settings, limiter
        self.resolver, self.transport = resolver, transport

    async def get(self, url: str, *, accept: str = "application/json", host_interval: float = 0) -> HttpResult:
        if accept not in {"application/json", "application/rdap+json", "application/dns-message", "text/html,application/xhtml+xml"}:
            raise NetworkPolicyError("Unsupported response format")
        deadline = time.monotonic() + self.settings.collector_timeout_seconds
        current = url
        history = []
        for redirect in range(self.settings.collector_max_redirects + 1):
            destination = replace(validate_url(current), accept=accept)
            addresses = await bounded_call(self.resolver, destination.host, destination.port, deadline=deadline)
            from app.security.url_policy import public_address
            if not addresses:
                raise NetworkPolicyError("Destination has no addresses")
            addresses = tuple(public_address(address) for address in addresses)
            result = None
            for attempt in range(self.settings.collector_retries + 1):
                delay = self.limiter.reserve(destination.host, max(self.settings.collector_host_interval_seconds, host_interval), deadline)
                await asyncio.sleep(delay)
                try:
                    result = await bounded_call(self.transport, destination, addresses[0], deadline,
                                                self.settings.collector_max_response_bytes, deadline=deadline)
                    if len(result.body) > self.settings.collector_max_response_bytes:
                        raise ResponseLimitError("Response size exceeds policy")
                    if result.metadata["status"] in {429, 503}:
                        retry_after = result.metadata.get("headers", {}).get("retry-after", "")
                        seconds = min(86400, int(retry_after)) if retry_after.isdigit() else 3600 if result.metadata["status"] == 429 else 60
                        self.limiter.defer(destination.host, max(60, seconds))
                    break
                except (OSError, http.client.HTTPException):
                    if attempt == self.settings.collector_retries or time.monotonic() >= deadline:
                        raise
            if result.metadata["status"] not in {301, 302, 303, 307, 308}:
                if history:
                    return replace(result, metadata={**result.metadata, "redirects": history})
                return result
            location = result.metadata.get("headers", {}).get("location")
            if not location or redirect == self.settings.collector_max_redirects:
                raise NetworkPolicyError("Redirect limit or missing destination")
            history.append({"url": destination.url, "status": result.metadata["status"], "location": location, "resolved_ip": addresses[0]})
            current = urljoin(destination.url, location)
        raise NetworkPolicyError("Redirect limit exceeded")


def raw_response(result: HttpResult) -> dict:
    return {"metadata": result.metadata, "body_base64": base64.b64encode(result.body).decode("ascii")}
