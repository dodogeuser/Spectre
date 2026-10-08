"""Passive IP observations. All remote work uses the injected guarded client."""
import ipaddress
from datetime import datetime

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype

from app.collectors.base import Collector, CollectorResult
from app.collectors.domain_support import ProviderUnavailableError, json_body, safe_parse
from app.collectors.ip_providers import DefaultReverseDNS, IanaNetworkRDAP, RIPEstatRouting, ReverseDNSProvider, NetworkRDAPProvider, RoutingProvider
from app.security.url_policy import NetworkPolicyError, public_address, validate_url
from app.services.normalization import domain


def seed(target):
    # Reject nonpublic seeds even though the provider destination is public.
    return ipaddress.ip_address(public_address(target.normalized_value))


def failure_code(exc):
    return "timeout" if isinstance(exc, TimeoutError) else "network_policy" if isinstance(exc, NetworkPolicyError) else "collector_error"


def failed(items, code, warning):
    return CollectorResult(evidence=items, status="failed", error_code=code, warnings=[warning + " Unavailable intelligence is not a confirmed negative finding."])


def parse_ptr(response, query):
    if response.metadata.get("headers", {}).get("content-type", "").split(";", 1)[0].lower() != "application/dns-message":
        raise ValueError("Unexpected DNS media type")
    try:
        answer = dns.message.from_wire(response.body, ignore_trailing=False)
    except dns.exception.DNSException as exc:
        raise ValueError("Malformed PTR response") from exc
    if not query.is_response(answer) or not answer.flags & dns.flags.QR or answer.flags & dns.flags.TC:
        raise ValueError("PTR response does not match query")
    rcode = dns.rcode.to_text(answer.rcode())
    if rcode not in {"NOERROR", "NXDOMAIN"}:
        return {"rcode": rcode, "records": [], "dns_error": True, "availability": "unavailable"}
    # Follow only CNAME records already in this one received DNS answer.
    owners = {query.question[0].name}
    for _ in range(8):
        previous = len(owners)
        for rrset in answer.answer:
            if rrset.rdtype == dns.rdatatype.CNAME and rrset.name in owners:
                owners.update(item.target for item in rrset)
        if len(owners) == previous:
            break
    records = []
    for rrset in answer.answer:
        if rrset.rdtype == dns.rdatatype.PTR and rrset.name in owners:
            for item in rrset:
                if len(records) >= 100:
                    raise ValueError("PTR record limit")
                records.append({"name": domain(item.target.to_text()), "ttl": rrset.ttl})
    if rcode == "NXDOMAIN" and records:
        raise ValueError("Contradictory NXDOMAIN response")
    return {"rcode": rcode, "records": records, "availability": "observed" if records else "no_ptr_observed",
            "caveat": "A resolver response only; PTR does not prove ownership or a live service."}


def select_ip_service(response, address):
    services = json_body(response)["services"]
    if not isinstance(services, list) or len(services) > 10000:
        raise ValueError("Invalid IP bootstrap")
    best, base, match = -1, None, None
    for service in services:
        if not isinstance(service, list) or len(service) != 2 or not all(isinstance(part, list) for part in service):
            raise ValueError("Invalid bootstrap service")
        for value in service[0]:
            network = ipaddress.ip_network(value, strict=True)
            if network.version != address.version or address not in network or network.prefixlen <= best:
                continue
            selected = None
            for candidate in service[1]:
                if not isinstance(candidate, str):
                    raise ValueError("Invalid service URL")
                try:
                    validate_url(candidate)
                except ValueError:
                    continue
                if "?" not in candidate and "#" not in candidate:
                    selected = candidate
                    break
            if selected:
                best, base, match = network.prefixlen, selected, str(network)
    return {"selected_base": base, "matched_prefix": match, "ip": str(address)}


def bounded_text(value, limit=500):
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError("Invalid provider text")
    return value


def observation_date(value):
    value = bounded_text(value, 100)
    if datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is None:
        raise ValueError("Observation date requires timezone")
    return value


def rdap_organizations(entities, depth=0):
    if not isinstance(entities, list) or len(entities) > 100 or depth > 2:
        raise ValueError("RDAP entity limit")
    organizations = []
    for item in entities:
        roles = item.get("roles", [])
        if not isinstance(roles, list) or len(roles) > 20 or not all(isinstance(role, str) for role in roles):
            raise ValueError("Invalid entity roles")
        card = item.get("vcardArray")
        if card is not None:
            if not isinstance(card, list) or len(card) != 2 or card[0] != "vcard" or not isinstance(card[1], list) or len(card[1]) > 100:
                raise ValueError("Invalid RDAP vCard")
            # Do not normalize personal contact/email/telephone/address fields.
            for property in card[1]:
                if not isinstance(property, list) or len(property) != 4:
                    raise ValueError("Invalid vCard property")
                if property[0] == "org":
                    value = property[3]
                    if isinstance(value, list):
                        if len(value) > 10:
                            raise ValueError("Organization component limit")
                        value = " / ".join(bounded_text(part) for part in value)
                    organizations.append({"name": bounded_text(value), "roles": roles})
            # An explicit vCard kind=org permits its formatted organization name.
            # Never normalize an individual's formatted name as an organization.
            if not any(prop[0] == "org" for prop in card[1]) and any(prop[0] == "kind" and prop[3] == "org" for prop in card[1]):
                for prop in card[1]:
                    if prop[0] == "fn":
                        organizations.append({"name": bounded_text(prop[3]), "roles": roles})
                        break
        # Bound recursion; retain deeper entities in raw evidence only.
        if depth < 2:
            organizations.extend(rdap_organizations(item.get("entities", []), depth + 1))
        if len(organizations) > 100:
            raise ValueError("Organization limit")
    return organizations


def parse_network_rdap(response, address):
    data = json_body(response)
    if not isinstance(data, dict) or data.get("objectClassName") != "ip network":
        raise ValueError("Expected RDAP IP network")
    start, end = ipaddress.ip_address(bounded_text(data["startAddress"], 45)), ipaddress.ip_address(bounded_text(data["endAddress"], 45))
    if start.version != address.version or end.version != address.version or not start <= address <= end:
        raise ValueError("Allocation does not contain seed")
    if data.get("ipVersion") != f"v{address.version}":
        raise ValueError("IP version mismatch")
    statuses, events = data.get("status", []), data.get("events", [])
    if not isinstance(statuses, list) or len(statuses) > 100 or not isinstance(events, list) or len(events) > 100:
        raise ValueError("RDAP list limit")
    normalized_events = [{"action": bounded_text(event["eventAction"], 100), "date": observation_date(event["eventDate"])} for event in events]
    country = bounded_text(data.get("country", ""), 2)
    if country and (not country.isascii() or not country.isalpha() or len(country) != 2):
        raise ValueError("Invalid registration country")
    return {"ip": str(address), "start_address": str(start), "end_address": str(end),
            "handle": bounded_text(data.get("handle", "")), "name": bounded_text(data.get("name", "")),
            "allocation_type": bounded_text(data.get("type", "")), "registration_country": country.upper(),
            "statuses": [bounded_text(item) for item in statuses], "events": normalized_events,
            "organizations": rdap_organizations(data.get("entities", [])),
            "caveat": "Registration metadata is not proof of current operator or physical geolocation."}


def ripe_data(response, call):
    document = json_body(response)
    if isinstance(document, dict) and document.get("status") in {"error", "maintenance"}:
        raise ProviderUnavailableError("Provider reports unavailable data")
    if document.get("status") != "ok" or document.get("data_call_name") != call or not isinstance(document.get("data"), dict):
        raise ValueError("Invalid RIPEstat envelope")
    return document, document["data"]


def asn_number(value):
    if isinstance(value, bool) or not isinstance(value, (int, str)) or not str(value).isdigit() or not 1 <= int(value) <= 4294967295:
        raise ValueError("Invalid ASN")
    return int(value)


def parse_routing(response, address):
    document, data = ripe_data(response, "network-info")
    prefix, asns = data.get("prefix"), data["asns"]
    if not isinstance(asns, list) or len(asns) > 32:
        raise ValueError("ASN list limit")
    if prefix is None:
        if asns:
            raise ValueError("ASN without prefix")
        normalized_prefix = None
    else:
        network = ipaddress.ip_network(prefix, strict=True)
        if network.version != address.version or address not in network:
            raise ValueError("Routing prefix outside seed")
        normalized_prefix = str(network)
    return {"ip": str(address), "prefix": normalized_prefix, "asns": sorted({asn_number(value) for value in asns}),
            "availability": "observed" if asns else "no_route_observed",
            "provider_time": bounded_text(document.get("time", ""), 100),
            "caveat": "RIPE RIS visibility and snapshot only; no observation does not prove globally unrouted."}


def parse_prefix(response, prefix, asns):
    document, data = ripe_data(response, "prefix-overview")
    if str(ipaddress.ip_network(data["resource"], strict=True)) != prefix:
        raise ValueError("Prefix overview mismatch")
    holders = data["asns"]
    if not isinstance(holders, list) or len(holders) > 32 or not isinstance(data.get("announced"), bool):
        raise ValueError("Invalid prefix overview")
    parsed = []
    for item in holders:
        number = asn_number(item["asn"])
        # Sources can change between requests; do not attribute an unrelated ASN.
        if number in asns:
            parsed.append({"asn": number, "holder": bounded_text(item.get("holder") or "")})
    return {"prefix": prefix, "holders": parsed, "announced_by_provider": data["announced"],
            "availability": "observed" if {item["asn"] for item in parsed if item["holder"]} == set(asns) else "partial_holder_metadata",
            "query_time": bounded_text(data.get("query_time", ""), 100),
            "caveat": "Provider routing/holder observation; not a claim of target ownership."}


class ReverseDNSCollector(Collector):
    name, version = "reverse_dns", "1.0.0"
    supported_types = frozenset({"ipv4", "ipv6"})

    def __init__(self, provider: ReverseDNSProvider | None = None):
        self.provider = provider or DefaultReverseDNS()

    async def collect(self, target, context):
        address = seed(target)
        query, response = await self.provider.query(context.http, address.reverse_pointer, "PTR")
        item, error = safe_parse(response, "reverse_dns", self.provider.name, lambda result: {"ip": str(address), **parse_ptr(result, query)})
        if item.parsed_json.get("dns_error"):
            error = "dns_error"
        return failed([item], error, "PTR source unavailable.") if error else CollectorResult(evidence=[item])


class NetworkRDAPCollector(Collector):
    name, version = "ip_rdap", "1.0.0"
    supported_types = frozenset({"ipv4", "ipv6"})

    def __init__(self, provider: NetworkRDAPProvider | None = None):
        self.provider = provider or IanaNetworkRDAP()

    async def collect(self, target, context):
        address = seed(target)
        response = await self.provider.discover(context.http, address.version)
        bootstrap, error = safe_parse(response, "ip_rdap_bootstrap", self.provider.name, lambda result: select_ip_service(result, address))
        if error or not bootstrap.parsed_json.get("selected_base"):
            return failed([bootstrap], error or "bootstrap_unavailable", "No usable authoritative IP RDAP service.")
        try:
            response = await self.provider.lookup(context.http, bootstrap.parsed_json["selected_base"], str(address))
        except (TimeoutError, OSError, NetworkPolicyError) as exc:
            return failed([bootstrap], failure_code(exc), "Network RDAP lookup unavailable; bootstrap retained.")
        item, error = safe_parse(response, "ip_rdap", self.provider.name, lambda result: parse_network_rdap(result, address))
        return failed([bootstrap, item], error, "Network RDAP source unavailable.") if error else CollectorResult(evidence=[bootstrap, item])


class ASNCollector(Collector):
    name, version = "ip_asn", "1.0.0"
    supported_types = frozenset({"ipv4", "ipv6"})

    def __init__(self, provider: RoutingProvider | None = None):
        self.provider = provider or RIPEstatRouting()

    async def collect(self, target, context):
        address = seed(target)
        response = await self.provider.network(context.http, str(address))
        item, error = safe_parse(response, "ip_asn", self.provider.name, lambda result: parse_routing(result, address))
        if error:
            return failed([item], error, "ASN/prefix source unavailable.")
        prefix, asns = item.parsed_json["prefix"], item.parsed_json["asns"]
        if not prefix or not asns:
            return CollectorResult(evidence=[item], warnings=["No route observed by this provider; this is not a global negative finding."])
        try:
            response = await self.provider.overview(context.http, prefix)
        except (TimeoutError, OSError, NetworkPolicyError) as exc:
            return failed([item], failure_code(exc), "Partial routing result: holder lookup unavailable; routing evidence retained.")
        holder, error = safe_parse(response, "ip_asn_holder", self.provider.name, lambda result: parse_prefix(result, prefix, asns))
        if error:
            return failed([item, holder], error, "Partial routing result: holder source unavailable.")
        return CollectorResult(evidence=[item, holder], warnings=["Partial holder metadata; unmatched/missing holder names are not ownership findings."] if holder.parsed_json["availability"] == "partial_holder_metadata" else [])
