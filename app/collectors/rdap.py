from app.collectors.base import Collector, CollectorResult
from app.collectors.domain_support import json_body, safe_parse
from app.collectors.providers import IanaRDAP
from app.security.url_policy import validate_url
from app.security.url_policy import NetworkPolicyError
from app.services.normalization import domain


def select_service(response, name):
    document = json_body(response)
    services = document["services"]
    if not isinstance(services, list):
        raise ValueError("Invalid bootstrap")
    tld = name.rsplit(".", 1)[-1]
    for service in services:
        if not isinstance(service, list) or len(service) != 2 or not all(isinstance(part, list) for part in service):
            raise ValueError("Invalid bootstrap service")
        if tld in service[0]:
            for base in service[1]:
                try:
                    validate_url(base)
                except ValueError:
                    continue
                if "?" not in base and "#" not in base:
                    return {"selected_base": base, "tld": tld}
    return {"selected_base": None, "tld": tld}


def parse_rdap(response, name):
    document = json_body(response)
    if not isinstance(document, dict) or document.get("objectClassName") != "domain" or domain(document["ldhName"]) != name:
        raise ValueError("RDAP response does not match domain")
    status = document.get("status", [])
    events = document.get("events", [])
    nameservers = document.get("nameservers", [])
    if not isinstance(status, list) or not all(isinstance(item, str) and len(item) < 500 for item in status):
        raise ValueError("Invalid RDAP status")
    if not isinstance(events, list) or not isinstance(nameservers, list) or len(events) > 100 or len(nameservers) > 100:
        raise ValueError("RDAP list limit")
    parsed_events = []
    for event in events:
        action, date = event["eventAction"], event["eventDate"]
        if not isinstance(action, str) or not isinstance(date, str) or len(action) > 100 or len(date) > 100:
            raise ValueError("Invalid RDAP event")
        parsed_events.append({"action": action, "date": date})
    parsed_ns = [domain(item["ldhName"]) for item in nameservers]
    handle = document.get("handle", "")
    if not isinstance(handle, str) or len(handle) > 500:
        raise ValueError("Invalid RDAP handle")
    return {"domain": name, "handle": handle, "statuses": status, "events": parsed_events, "nameservers": parsed_ns}


class RDAPCollector(Collector):
    name, version = "rdap", "1.0.0"
    supported_types = frozenset({"domain"})

    def __init__(self, provider=None):
        self.provider = provider or IanaRDAP()

    async def collect(self, target, context):
        name = domain(target.normalized_value)
        response = await self.provider.discover(context.http)
        bootstrap, error = safe_parse(response, "rdap_bootstrap", self.provider.name, lambda result: select_service(result, name))
        if error or not bootstrap.parsed_json.get("selected_base"):
            return CollectorResult(evidence=[bootstrap], status="failed", error_code=error or "bootstrap_unavailable",
                                   warnings=["No usable authoritative HTTPS RDAP bootstrap service."])
        try:
            response = await self.provider.lookup(context.http, bootstrap.parsed_json["selected_base"], name)
        except (TimeoutError, OSError, NetworkPolicyError) as exc:
            error = "timeout" if isinstance(exc, TimeoutError) else "network_policy" if isinstance(exc, NetworkPolicyError) else "collector_error"
            return CollectorResult(evidence=[bootstrap], status="failed", error_code=error,
                                   warnings=["Authoritative RDAP request unavailable; bootstrap evidence retained."])
        item, error = safe_parse(response, "rdap", self.provider.name, lambda result: parse_rdap(result, name))
        return CollectorResult(evidence=[bootstrap, item], status="failed" if error else "completed", error_code=error,
                               warnings=["RDAP provider observation unavailable; missing data does not prove an unregistered domain."] if error else [])
