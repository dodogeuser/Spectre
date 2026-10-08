import base64
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import dns.message
import dns.rdatatype
import dns.rrset

from app.services.http_client import HttpResult

FIXTURES = Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FIXTURES / ("domain_" + name + ".json")).read_text(encoding="utf-8"))


class FixtureHTTP:
    def __init__(self, *, bad=None, http_status=200):
        self.calls = []
        self.bad, self.http_status = bad, http_status

    async def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.bad == "timeout":
            raise TimeoutError("Synthetic timeout")
        parts = urlsplit(url)
        if parts.path == "/dns-query":
            encoded = parse_qs(parts.query)["dns"][0]
            query = dns.message.from_wire(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
            message = dns.message.make_response(query)
            kind = dns.rdatatype.to_text(query.question[0].rdtype)
            for record in load("dns")["records"]:
                if record["type"] == kind:
                    message.answer.append(dns.rrset.from_text(record["owner"], 300, "IN", kind, record["data"]))
            body = message.to_wire()
            mime = "application/dns-message"
        elif parts.path.endswith("dns.json"):
            body, mime = json.dumps(load("bootstrap")).encode(), "application/json"
        elif "/domain/" in parts.path:
            body, mime = json.dumps(load("rdap")).encode(), "application/rdap+json"
        else:
            body, mime = json.dumps(load("ct")).encode(), "application/json"
        if self.bad == "malformed":
            body = b"{not-a-response"
        return HttpResult(url, {"status": self.http_status, "headers": {"content-type": mime}, "synthetic_fixture": True}, body)
