import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype

from app.collectors.base import Collector, CollectorResult
from app.collectors.domain_support import safe_parse
from app.collectors.providers import CloudflareDNS
from app.services.normalization import domain, normalize
from app.security.url_policy import NetworkPolicyError


def parse_dns(response, query):
    if response.metadata.get("headers", {}).get("content-type", "").split(";", 1)[0].lower() != "application/dns-message":
        raise ValueError("Unexpected DNS media type")
    try:
        message = dns.message.from_wire(response.body, ignore_trailing=False)
    except dns.exception.DNSException as exc:
        raise ValueError("Malformed DNS wire response") from exc
    if not query.is_response(message) or not message.flags & dns.flags.QR or message.flags & dns.flags.TC:
        raise ValueError("DNS response does not match query")
    status = dns.rcode.to_text(message.rcode())
    if status not in {"NOERROR", "NXDOMAIN"}:
        return {"rcode": status, "records": [], "dns_error": True}
    records = []
    for rrset in message.answer:
        kind = dns.rdatatype.to_text(rrset.rdtype)
        if kind not in DNSCollector.record_types:
            continue
        owner = domain(rrset.name.to_text())
        for item in rrset:
            if len(records) >= 300:
                raise ValueError("DNS record limit exceeded")
            record = {"owner": owner, "record_type": kind, "ttl": rrset.ttl}
            if kind in {"A", "AAAA"}:
                record["value"] = normalize("ipv4" if kind == "A" else "ipv6", item.address)[1]
            elif kind in {"NS", "CNAME", "MX"}:
                dns_name = (item.exchange if kind == "MX" else item.target).to_text()
                record["value"] = "." if kind == "MX" and dns_name == "." else domain(dns_name)
                if kind == "MX":
                    record["priority"] = item.preference
            else:
                record["value"] = "".join(part.decode("utf-8", errors="replace") for part in item.strings)
            records.append(record)
    return {"query_type": dns.rdatatype.to_text(query.question[0].rdtype), "rcode": status, "records": records}


class DNSCollector(Collector):
    name, version = "dns", "1.0.0"
    supported_types = frozenset({"domain"})
    record_types = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")

    def __init__(self, provider=None):
        self.provider = provider or CloudflareDNS()

    async def collect(self, target, context):
        name = domain(target.normalized_value)
        items, warnings, failure = [], [], None
        for kind in self.record_types:
            try:
                query, response = await self.provider.query(context.http, name, kind)
            except (TimeoutError, OSError, NetworkPolicyError) as exc:
                failure = "timeout" if isinstance(exc, TimeoutError) else "network_policy" if isinstance(exc, NetworkPolicyError) else "collector_error"
                warnings.append(f"{kind}: request unavailable ({failure}); remaining record queries were not attempted.")
                break
            item, error = safe_parse(response, "dns", self.provider.name, lambda result: parse_dns(result, query))
            items.append(item)
            if item.parsed_json.get("dns_error"):
                error = "dns_error"
            if error:
                failure = error
                warnings.append(f"{kind}: provider observation unavailable ({error}).")
        return CollectorResult(evidence=items, warnings=warnings, status="failed" if failure else "completed", error_code=failure)
