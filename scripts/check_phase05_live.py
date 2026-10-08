"""Check retained live IP runs; export public, contact-redacted parser fixtures."""
import base64
import hashlib
import json
from pathlib import Path

from sqlalchemy import select, text

from app.config import get_settings
from app.db.models import AuditLog, Case, CollectorRun, Evidence, Relationship, Target
from app.db.session import make_session_factory
from app.security.url_policy import public_address
from app.services.evidence import canonical_bytes


def redact_entities(entities):
    result = []
    for entity in entities:
        card = entity.get("vcardArray", ["vcard", []])
        properties = [prop for prop in card[1] if prop[0] in {"kind", "org"}]
        if any(prop[0] == "kind" and prop[3] == "org" for prop in properties):
            properties += [prop for prop in card[1] if prop[0] == "fn"]
        children = redact_entities(entity.get("entities", []))
        if properties or children:
            result.append({"roles": entity.get("roles", []), "vcardArray": ["vcard", properties], "entities": children})
    return result


def main():
    factory = make_session_factory(get_settings())
    with factory() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "005"
        all_evidence = list(db.scalars(select(Evidence)))
        for item in all_evidence:
            assert item.sha256 == hashlib.sha256(canonical_bytes(item.raw_json)).hexdigest()
        case = db.scalar(select(Case).where(Case.title == "Phase 05 live provider verification").order_by(Case.id.desc()))
        assert case is not None
        targets = list(db.scalars(select(Target).where(Target.case_id == case.id)))
        assert {target.type for target in targets} >= {"ipv4", "ipv6"}
        runs = list(db.scalars(select(CollectorRun).where(CollectorRun.target_id.in_([target.id for target in targets]),
            CollectorRun.collector.in_(["reverse_dns", "ip_rdap", "ip_asn"]))))
        for target in targets:
            if target.type in {"ipv4", "ipv6"}:
                assert {run.collector for run in runs if run.target_id == target.id and run.status == "completed"} == {"reverse_dns", "ip_rdap", "ip_asn"}
        records = list(db.scalars(select(Evidence).where(Evidence.run_id.in_([run.id for run in runs]))))
        for item in records:
            metadata = item.raw_json["metadata"]
            assert not metadata.get("synthetic_fixture")
            assert metadata["status"] == 200 and metadata["resolved_ip"] == public_address(metadata["resolved_ip"])
            assert item.source_ref.startswith("https://") and item.parsed_json["provider"]
        relations = list(db.scalars(select(Relationship)))
        for relation in relations:
            evidence = db.get(Evidence, relation.evidence_id)
            run = db.get(CollectorRun, evidence.run_id)
            target = db.get(Target, run.target_id)
            assert target.case_id == relation.case_id and 0 <= relation.confidence <= 1
        audits = list(db.scalars(select(AuditLog).where(AuditLog.object_type == "case", AuditLog.object_id == case.id)))
        for run in runs:
            assert any(row.action == "collector.started" and row.metadata_json.get("run_id") == run.id for row in audits)
            assert any(row.action == "collector.completed" and row.metadata_json.get("run_id") == run.id for row in audits)
        fixture = {"notice": "Recorded public provider response shapes, 2026-10-05. RDAP personal contacts and unrelated fields removed. Fixtures never imply live/current intelligence."}
        for item in records:
            target = db.get(Target, db.get(CollectorRun, item.run_id).target_id)
            if target.type != "ipv4":
                continue
            source = item.source_type
            if source == "reverse_dns":
                fixture["ptr_body_base64"] = item.raw_json["body_base64"]
            elif source in {"ip_rdap", "ip_asn", "ip_asn_holder"}:
                document = json.loads(base64.b64decode(item.raw_json["body_base64"]))
                if source == "ip_rdap":
                    document = {key: document[key] for key in ("objectClassName", "ipVersion", "startAddress", "endAddress", "handle", "name", "type", "country", "status", "events") if key in document}
                    original = json.loads(base64.b64decode(item.raw_json["body_base64"]))
                    document["entities"] = redact_entities(original.get("entities", []))
                fixture[source] = document
        Path("tests/fixtures/ip_recorded_provider_shapes.json").write_text(json.dumps(fixture, indent=2), encoding="utf-8")
        report = {"case_id": case.id, "target_ids": [target.id for target in targets], "run_ids": [run.id for run in runs],
            "evidence_ids": [item.id for item in records], "all_hashes_verified": len(all_evidence), "relationships_verified": len(relations), "revision": "005"}
        Path(".local/phase05-live-verification.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report))


if __name__ == "__main__":
    main()
