import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
import base64

import dns.message
import dns.rrset

from app.services.http_client import HttpResult


def load():
    return json.loads((Path(__file__).parent / "fixtures/ip_intelligence.json").read_text(encoding="utf-8"))


class IPFixtureHTTP:
    def __init__(self, mode=None, status=200, fail_at=None):
        self.calls, self.mode, self.status, self.fail_at = [], mode, status, fail_at

    async def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        fail = self.fail_at is None or len(self.calls) == self.fail_at
        if self.mode == "timeout" and fail:
            raise TimeoutError("Synthetic timeout")
        if self.mode == "network_policy" and fail:
            from app.security.url_policy import NetworkPolicyError
            raise NetworkPolicyError("Synthetic policy rejection")
        data = load()
        content_type = "application/json"
        if "/dns-query" in url:
            encoded = parse_qs(urlsplit(url).query)["dns"][0]
            query = dns.message.from_wire(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
            assert query.question[0].rdtype == 12
            answer = dns.message.make_response(query)
            answer.answer.append(dns.rrset.from_text(query.question[0].name.to_text(), 300, "IN", "PTR", *data["ptr_names"]))
            body, content_type = answer.to_wire(), "application/dns-message"
        elif "data.iana.org" in url:
            body = json.dumps(data["bootstrap"]).encode()
        elif "/ip/" in url:
            document = data["rdap"]
            if ":" in urlsplit(url).path:
                document.update(ipVersion="v6", startAddress="2001:4860::", endAddress="2001:4860:ffff:ffff:ffff:ffff:ffff:ffff")
            body = json.dumps(document).encode()
        else:
            document = data["routing"] if "network-info" in url else data["prefix"]
            if ":" in parse_qs(urlsplit(url).query)["resource"][0]:
                document["data"]["prefix" if "network-info" in url else "resource"] = "2001:4860::/32"
            body = json.dumps(document).encode()
        if self.mode == "malformed" and fail:
            body = b"malformed fixture"
        return HttpResult(url, {"status": self.status if fail else 200, "headers": {"content-type": content_type},
                               "synthetic_fixture": True, "bytes": len(body)}, body)
