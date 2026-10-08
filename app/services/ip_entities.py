"""Minimal IP/PTR evidence projection, sharing Phase 04 case canonical keys."""
import hashlib
import ipaddress

from sqlalchemy import select

from app.db.models import Entity, Relationship
from app.services.normalization import domain


def project_ip_evidence(db, case_id, address, records):
    def node(kind, value):
        canonical = str(ipaddress.ip_address(value)) if kind == "ip" else domain(value)
        key = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        found = db.scalar(select(Entity).where(Entity.case_id == case_id, Entity.entity_type == kind, Entity.canonical_hash == key))
        if found is None:
            found = Entity(case_id=case_id, entity_type=kind, canonical_value=canonical, canonical_hash=key, attributes_json={})
            db.add(found)
            db.flush()
        return found
    for record in records:
        parsed = record.parsed_json
        if parsed.get("status") != "ok" or record.source_type not in {"reverse_dns", "ip_rdap", "ip_asn"} or parsed.get("dns_error"):
            continue
        ip_node = node("ip", address)
        if record.source_type == "reverse_dns":
            for ptr in parsed["records"]:
                host = node("domain", ptr["name"])
                exists = db.scalar(select(Relationship.id).where(Relationship.from_entity_id == ip_node.id,
                    Relationship.to_entity_id == host.id, Relationship.relation_type == "ptr_observed", Relationship.evidence_id == record.id))
                if exists is None:
                    db.add(Relationship(case_id=case_id, from_entity_id=ip_node.id, to_entity_id=host.id,
                        relation_type="ptr_observed", confidence=0.95, evidence_id=record.id))
                    db.flush()
