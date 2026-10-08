"""Domain-specific fact projection, not a generic correlation/graph engine."""
import hashlib
import threading

from sqlalchemy import select

from app.db.models import Entity, Relationship
from app.services.normalization import domain, normalize

domain_write_lock = threading.RLock()


def project_domain_evidence(db, case_id, seed, records):
    def node(kind, value):
        canonical = normalize("ipv4" if ":" not in value else "ipv6", value)[1] if kind == "ip" else domain(value) if kind in {"domain", "subdomain"} else value
        key = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        found = db.scalar(select(Entity).where(Entity.case_id == case_id, Entity.entity_type == kind, Entity.canonical_hash == key))
        if found is None:
            found = Entity(case_id=case_id, entity_type=kind, canonical_value=canonical, canonical_hash=key, attributes_json={})
            db.add(found)
            db.flush()
        return found
    def name_node(value):
        # A subdomain type is relative to this seed; case reuse remains deterministic
        # by representing all concrete DNS names as domain entities.
        return node("domain", value)
    def edge(left, right, kind, evidence_id, confidence):
        exists = db.scalar(select(Relationship.id).where(Relationship.from_entity_id == left.id, Relationship.to_entity_id == right.id,
                           Relationship.relation_type == kind, Relationship.evidence_id == evidence_id))
        if exists is None:
            db.add(Relationship(case_id=case_id, from_entity_id=left.id, to_entity_id=right.id,
                                relation_type=kind, evidence_id=evidence_id, confidence=confidence))
            db.flush()
    for evidence in records:
        parsed = evidence.parsed_json
        if parsed.get("status") != "ok" or evidence.source_type not in {"dns", "rdap", "ct"}:
            continue
        root = name_node(seed)
        if evidence.source_type == "dns":
            for record in parsed.get("records", []):
                left = name_node(record["owner"])
                kind = record["record_type"]
                if kind in {"A", "AAAA"}:
                    edge(left, node("ip", record["value"]), "resolves_to", evidence.id, 0.95)
                elif kind in {"NS", "MX", "CNAME"} and record["value"] != ".":
                    edge(left, name_node(record["value"]), {"NS": "nameserver", "MX": "mail_server", "CNAME": "alias_of"}[kind], evidence.id, 0.95)
        elif evidence.source_type == "rdap":
            for value in parsed.get("nameservers", []):
                edge(root, name_node(value), "registration_nameserver", evidence.id, 0.9)
        elif evidence.source_type == "ct":
            for cert in parsed.get("certificates", []):
                certificate = node("certificate", cert["sha256"])
                for value in cert["dns_names"]:
                    edge(certificate, name_node(value), "certificate_names", evidence.id, 0.9)
                    if value != seed and value.endswith("." + seed):
                        edge(name_node(value), root, "subdomain_of", evidence.id, 0.95)
                # Wildcards remain certificate metadata only; no fictitious host nodes.
