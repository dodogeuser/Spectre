"""Deterministic, stored-evidence-only correlation; no collector or AI dependencies."""
import hashlib
import ipaddress
import re
from collections import defaultdict
from urllib.parse import urljoin

from sqlalchemy import select

from app.db.models import CollectorRun, Entity, Evidence, Relationship, Target
from app.security.url_policy import validate_url
from app.services.domain_entities import domain_write_lock
from app.services.evidence import canonical_bytes
from app.services.normalization import domain, normalize

VERSION = "1.0.0"
RULES = {
    "resolves_to": (0.95, "observed", "DNS A/AAAA answer"),
    "nameserver": (0.95, "observed", "DNS NS answer"),
    "mail_server": (0.95, "observed", "DNS MX answer"),
    "alias_of": (0.95, "observed", "DNS CNAME answer"),
    "registration_nameserver": (0.9, "observed", "RDAP declared nameserver"),
    "certificate_names": (0.9, "observed", "CT certificate concrete DNS name"),
    "certificate_observed_on": (0.9, "observed", "CT name association only; not a served certificate"),
    "subdomain_of": (0.95, "derived", "Concrete DNS suffix relative to evidence seed"),
    "ptr_observed": (0.95, "observed", "Resolver PTR answer; not ownership"),
    "announced_by": (0.85, "derived", "Seed contained in provider prefix with observed origin ASN"),
    "registered_to": (0.8, "observed", "IP RDAP explicit registrant organization; registration only"),
    "redirects_to": (0.95, "observed", "Stored HTTP redirect response"),
    "active_connects_to": (1.0,"observed","Active operation used a resolver-validated pinned public address; not ownership"),
    "exposes_service": (1.0,"observed","Authorized capture accepted a TCP connection at this exact host/port"),
    "presents_certificate": (1.0,"observed","Certificate fingerprint presented by the verified live TLS service"),
}


def canonical(kind, value):
    if not isinstance(value, str) or not value or len(value) > 4000:
        raise ValueError("Invalid entity value")
    if kind in {"domain", "subdomain"}:
        return domain(value)
    if kind == "ip":
        return str(ipaddress.ip_address(value))
    if kind == "asn":
        number = value.upper().removeprefix("AS")
        if not number.isascii() or not number.isdigit() or not 1 <= int(number) <= 4294967295:
            raise ValueError("Invalid ASN")
        return "AS" + str(int(number))
    if kind == "certificate":
        if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise ValueError("Invalid certificate hash")
        return value.lower()
    if kind in {"organization", "url"}:
        return normalize(kind, value)[1]
    if kind=="service":
        from urllib.parse import urlsplit
        parts=urlsplit(value)
        if parts.scheme!='tcp' or parts.port not in {80,443} or parts.username or parts.password or parts.path or parts.query or parts.fragment:
            raise ValueError('Invalid stored service entity')
        return f'tcp://{domain(parts.hostname)}:{parts.port}'
    raise ValueError("Unsupported entity type")


def plan(item, run):
    """Validate a whole evidence item before any database mutation."""
    p = item.parsed_json
    if not isinstance(p, dict) or p.get("status") != "ok" or p.get("dns_error"):
        return [], []
    seed = run.target_snapshot["normalized_value"]
    nodes, edges = set(), set()
    def node(kind, value):
        result = (kind, canonical(kind, value))
        nodes.add(result)
        return result
    def edge(left, right, relation):
        if left != right:
            edges.add((left, right, relation))
    def host(value):
        value = domain(value)
        result = node("domain", value)
        if run.target_snapshot["type"] == "domain":
            root = domain(seed)
            if value != root and value.endswith("." + root):
                # One canonical DNS node; subdomain is an evidence-relative role.
                nodes.add(("subdomain", value))
                edge(result, node("domain", root), "subdomain_of")
        return result
    source = item.source_type
    if source in {'active_http','active_validation','active_manual','active_tls','active_service'}:
        from app.active.projection import plan as active_plan
        return active_plan(item,run)
    expected = {"dns": ("dns", "domain"), "rdap": ("rdap", "domain"), "ct": ("ct", "domain"), "reverse_dns": ("reverse_dns", "ip"), "ip_rdap": ("ip_rdap", "ip"), "ip_asn": ("ip_asn", "ip"), "web_metadata": ("web_metadata", "url")}
    if source not in expected:
        return [], []
    collector, target_type = expected[source]
    if run.collector != collector or (run.target_snapshot["type"] not in {"ipv4", "ipv6"} if target_type == "ip" else run.target_snapshot["type"] != target_type):
        raise ValueError("Source/run mismatch")
    if source == "dns":
        host(seed)
        if p["rcode"] not in {"NOERROR", "NXDOMAIN"}:
            return [], []
        if p.get("rcode") == "NXDOMAIN" and p["records"]:
            raise ValueError("Contradictory negative DNS response")
        for record in p["records"]:
            left = host(record["owner"])
            kind, value = record["record_type"], record["value"]
            if kind in {"A", "AAAA"}:
                address = ipaddress.ip_address(value)
                if address.version != (4 if kind == "A" else 6):
                    raise ValueError("Address version mismatch")
                edge(left, node("ip", str(address)), "resolves_to")
            elif kind in {"NS", "MX", "CNAME"} and value != ".":
                edge(left, host(value), {"NS": "nameserver", "MX": "mail_server", "CNAME": "alias_of"}[kind])
    elif source == "rdap":
        if domain(p["domain"]) != domain(seed):
            raise ValueError("Registration seed mismatch")
        for value in p["nameservers"]:
            edge(host(seed), host(value), "registration_nameserver")
    elif source == "ct":
        host(seed)
        for cert in p["certificates"]:
            certificate = node("certificate", cert["sha256"])
            for value in cert["dns_names"]:
                name = host(value)
                edge(certificate, name, "certificate_observed_on")
    elif source == "reverse_dns":
        if canonical("ip", p["ip"]) != canonical("ip", seed):
            raise ValueError("PTR seed mismatch")
        for ptr in p["records"]:
            edge(node("ip", seed), host(ptr["name"]), "ptr_observed")
    elif source == "ip_asn":
        address = ipaddress.ip_address(seed)
        if canonical("ip", p["ip"]) != str(address):
            raise ValueError("ASN seed mismatch")
        if p.get("availability") != "observed":
            return [], []
        network = ipaddress.ip_network(p["prefix"], strict=True)
        if address not in network:
            raise ValueError("Prefix outside seed")
        for number in p["asns"]:
            if isinstance(number, bool):
                raise ValueError("Invalid ASN")
            edge(node("ip", seed), node("asn", str(number)), "announced_by")
    elif source == "ip_rdap":
        address = ipaddress.ip_address(seed)
        if canonical("ip", p["ip"]) != str(address) or not ipaddress.ip_address(p["start_address"]) <= address <= ipaddress.ip_address(p["end_address"]):
            raise ValueError("Allocation outside seed")
        for organization in p["organizations"]:
            org = node("organization", organization["name"])
            if "registrant" in organization["roles"]:
                edge(node("ip", seed), org, "registered_to")
    elif source == "web_metadata":
        if p.get("availability") != "observed" or p.get("http_status") != 200:
            return [], []
        if canonical("url", p["requested_url"]) != canonical("url", seed):
            raise ValueError("Page seed mismatch")
        current = canonical("url", seed)
        node("url", current)
        for hop in item.raw_json.get("metadata", {}).get("redirects", []):
            if canonical("url", hop["url"]) != current or hop["status"] not in {301, 302, 303, 307, 308}:
                raise ValueError("Invalid redirect chain")
            next_url = canonical("url", urljoin(current, hop["location"]))
            validate_url(current)
            validate_url(next_url)
            edge(node("url", current), node("url", next_url), "redirects_to")
            current = next_url
        if canonical("url", p["final_url"]) != current:
            raise ValueError("Incomplete redirect chain")
    if len(nodes) > 1000 or len(edges) > 2000:
        raise ValueError("Correlation item limit")
    return sorted(nodes), sorted(edges)


def correlate(db, case_id, after=0):
    rows = db.execute(select(Evidence, CollectorRun, Target).join(CollectorRun, Evidence.run_id == CollectorRun.id).join(Target, CollectorRun.target_id == Target.id).where(Target.case_id == case_id, Evidence.id > after).order_by(Evidence.id).limit(501)).all()
    report = {"version": VERSION, "processed": 0, "skipped": [], "entities_created": 0, "supports_created": 0, "has_more": len(rows) > 500, "next_after": after}
    with domain_write_lock:
        # Serialize against collection writers and other correlation requests, including other processes on MySQL.
        if db.get_bind().dialect.name == "mysql":
            from app.db.models import Case
            db.execute(select(Case.id).where(Case.id == case_id).with_for_update()).all()
        for item, run, target in rows[:500]:
            report["next_after"] = item.id
            if target.archived or target.scope_status == "excluded" or run.target_snapshot.get("scope_status") not in {"passive_allowed", "active_authorized"}:
                report["skipped"].append({"evidence_id": item.id, "reason": "scope_or_archive"})
                continue
            try:
                if item.sha256 != hashlib.sha256(canonical_bytes(item.raw_json)).hexdigest():
                    raise ValueError("Hash mismatch")
                nodes, edges = plan(item, run)
            except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
                report["skipped"].append({"evidence_id": item.id, "reason": "invalid_or_incomplete_evidence"})
                continue
            cache = {}
            for kind, value in nodes:
                identity_kind = "domain" if kind == "subdomain" else kind
                key = hashlib.sha256(value.encode("utf-8")).hexdigest()
                found = db.scalar(select(Entity).where(Entity.case_id == case_id, Entity.entity_type == identity_kind, Entity.canonical_hash == key))
                if found is None:
                    found = Entity(case_id=case_id, entity_type=identity_kind, canonical_value=value, canonical_hash=key, attributes_json={})
                    db.add(found)
                    db.flush()
                    report["entities_created"] += 1
                cache[(kind, value)] = found
            for left, right, relation in edges:
                a, b = cache[left], cache[right]
                exists = db.scalar(select(Relationship.id).where(Relationship.case_id == case_id, Relationship.from_entity_id == a.id, Relationship.to_entity_id == b.id, Relationship.relation_type == relation, Relationship.evidence_id == item.id))
                if exists is None:
                    db.add(Relationship(case_id=case_id, from_entity_id=a.id, to_entity_id=b.id, relation_type=relation, confidence=RULES[relation][0], evidence_id=item.id))
                    db.flush()
                    report["supports_created"] += 1
            report["processed"] += 1
        db.flush()
    return report


def graph(db, case_id):
    nodes = list(db.scalars(select(Entity).where(Entity.case_id == case_id).order_by(Entity.id).limit(5001)))
    node_ids = {node.id for node in nodes[:5000]}
    rows = db.execute(select(Relationship, Evidence).join(Evidence, Relationship.evidence_id == Evidence.id).join(CollectorRun, Evidence.run_id == CollectorRun.id).join(Target, CollectorRun.target_id == Target.id).where(Relationship.case_id == case_id, Target.case_id == case_id).order_by(Relationship.id).limit(10001)).all()
    groups = defaultdict(list)
    for relation, evidence in rows[:10000]:
        if relation.from_entity_id in node_ids and relation.to_entity_id in node_ids:
            # Preserve legacy supports while displaying a single semantic CT edge.
            kind = "certificate_observed_on" if relation.relation_type == "certificate_names" else relation.relation_type
            groups[(relation.from_entity_id, relation.to_entity_id, kind)].append((relation, evidence))
    edges = []
    for (left, right, kind), supports in sorted(groups.items()):
        rule = RULES.get(kind, (None, "legacy_observation", "Preserved prior-phase relationship"))
        edges.append({"from": left, "to": right, "type": kind, "classification": rule[1], "rule": rule[2], "confidence": min(row.confidence for row, _ in supports), "evidence_ids": sorted({ev.id for _, ev in supports}), "support_ids": sorted(row.id for row, _ in supports), "first_seen": min(ev.captured_at for _, ev in supports), "last_seen": max(ev.captured_at for _, ev in supports)})
    subdomains = {edge["from"] for edge in edges if edge["type"] == "subdomain_of"}
    return {"case_id": case_id, "version": VERSION, "entities": [{"id": n.id, "type": n.entity_type, "roles": ["subdomain"] if n.id in subdomains else [], "value": n.canonical_value, "attributes": n.attributes_json} for n in nodes[:5000]], "relationships": edges, "truncated": len(nodes) > 5000 or len(rows) > 10000, "limits": {"entities": 5000, "support_rows": 10000}, "scope_note": "Historical evidence retained after target archive/exclusion; no authorization or live ownership implied."}
