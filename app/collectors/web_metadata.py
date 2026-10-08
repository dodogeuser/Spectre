"""One guarded GET, inert HTML parsing and informational header observations."""
import codecs
from html.parser import HTMLParser
from typing import Protocol
from urllib.parse import urlsplit

from app.collectors.base import Collector, CollectorResult
from app.collectors.domain_support import evidence
from app.security.url_policy import validate_url
from app.services.http_client import ControlledHttpClient, HttpResult, UnsupportedContentError

SECURITY_HEADERS = ("strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy")
SELECTED_HEADERS = frozenset(SECURITY_HEADERS + ("content-type", "server", "content-security-policy-report-only", "etag", "last-modified", "retry-after"))


class PageProvider(Protocol):
    name: str
    async def fetch(self, client: ControlledHttpClient, url: str) -> HttpResult: ...


class PublicPage:
    name = "Direct public HTTPS page / declared response headers"
    async def fetch(self, client, url):
        return await client.get(url, accept="text/html,application/xhtml+xml")


class TitleParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_title, self.closed, self.parts = False, False, []
        self.length = 0
    def handle_starttag(self, tag, attrs):
        if tag == "title" and not self.closed:
            self.in_title = True
    def handle_endtag(self, tag):
        if tag == "title" and self.in_title:
            self.in_title, self.closed = False, True
    def handle_data(self, value):
        if self.in_title and self.length < 1000:
            part = value[:1000 - self.length]
            self.parts.append(part)
            self.length += len(part)


def parse_page(response, requested):
    status = response.metadata["status"]
    headers = {key: value for key, value in response.metadata.get("headers", {}).items() if key in SELECTED_HEADERS}
    media = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    allowed = {"text/html", "application/xhtml+xml"} if status == 200 else {"text/html", "application/xhtml+xml", "text/plain", "application/json"}
    if media not in allowed or response.body.startswith((b"%PDF-", b"PK\x03\x04", b"\x89PNG", b"\xff\xd8\xff", b"MZ")):
        raise UnsupportedContentError("Binary or unsupported response blocked")
    parsed = {"requested_url": requested, "final_url": response.source_ref, "http_status": status,
        "headers": headers, "server_hint": headers.get("server"), "title": None, "findings": [],
        "caveat": "One unauthenticated response only. Declared headers are hints; missing headers are not proof of vulnerability."}
    if status != 200:
        parsed["availability"] = "rate_limited" if status == 429 else "negative_http_response" if status in {404, 410} else "unavailable"
        return parsed
    content_type = headers.get("content-type", "")
    if content_type.split(";", 1)[0].strip().lower() not in {"text/html", "application/xhtml+xml"}:
        raise UnsupportedContentError("Non-HTML response")
    charset = "utf-8"
    for part in content_type.split(";")[1:]:
        key, _, value = part.strip().partition("=")
        if key.lower() == "charset":
            charset = value.strip('"\'')
    try:
        # Restrict HTML decoding to common text encodings, never arbitrary codecs.
        encoding = codecs.lookup(charset).name
        if encoding not in {"utf-8", "ascii", "iso8859-1", "cp1252", "utf-16", "utf-16-le", "utf-16-be"}:
            raise LookupError("Unsupported text encoding")
        text = response.body.decode(encoding, errors="strict")
        if "\x00" in text:
            raise UnsupportedContentError("Binary text response blocked")
        parser = TitleParser()
        parser.feed(text)
        parser.close()
        parsed["title"] = " ".join("".join(parser.parts).split()) or None
        partial = parser.in_title or parser.length >= 1000
    except UnsupportedContentError:
        raise
    except (UnicodeError, LookupError, ValueError):
        parsed.update(availability="partial", parse_note="HTML text could not be decoded/parsed under the bounded text policy.")
        return parsed
    parsed["availability"] = "partial" if partial else "observed"
    if partial:
        parsed["parse_note"] = "Title was unclosed or reached the 1,000-character limit; interpretation is partial."
        return parsed
    parsed["title_state"] = "observed" if parsed["title"] else "no_title_observed"
    for header in SECURITY_HEADERS:
        if not headers.get(header):
            parsed["findings"].append({"severity": "informational", "header": header,
                "observation": "Header not present in this response; applicability and equivalent protections require review."})
    return parsed


class WebMetadataCollector(Collector):
    name, version = "web_metadata", "1.0.0"
    supported_types = frozenset({"url"})
    def __init__(self, provider: PageProvider | None = None):
        self.provider = provider or PublicPage()
    async def collect(self, target, context):
        validate_url(target.normalized_value)  # Same HTTPS/public-literal policy as transport.
        response = await self.provider.fetch(context.http, target.normalized_value)
        parsed = parse_page(response, target.normalized_value)
        item = evidence(response, "web_metadata", self.provider.name, {"status": "ok" if response.metadata["status"] == 200 else "error", **parsed})
        unavailable = parsed["availability"] in {"rate_limited", "unavailable"}
        return CollectorResult(evidence=[item], status="failed" if unavailable else "completed",
            error_code="provider_http_error" if unavailable else None,
            warnings=[parsed.get("parse_note", "Unavailable response is not a confirmed negative finding.")] if unavailable or parsed["availability"] == "partial" else [])
