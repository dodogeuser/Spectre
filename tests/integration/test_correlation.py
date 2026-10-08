import hashlib
from datetime import datetime
from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.db.models import CollectorRun, Evidence, Entity, Relationship
from app.services.correlation import canonical, plan
from app.services.evidence import canonical_bytes
from tests.integration.test_accounts_cases import system, login


def seed(client, factory, source="dns", parsed=None, raw=None, target_type="domain", value="example.com"):
    headers = login(client, "owner")
    case = client.post("/api/cases", json={"title": "Correlation fixture"}, headers=headers).json()["id"]
    target = client.post(f"/api/cases/{case}/targets", json={"type": target_type, "value": value}, headers=headers).json()["id"]
    raw = raw or {"fixture": True}
    parsed = parsed or {"status": "ok", "rcode": "NOERROR", "records": [{"owner": "example.com", "record_type": "A", "value": "8.8.8.8"}]}
    with factory() as db:
        run = CollectorRun(target_id=target, actor_id=2, collector=source, version="1.0.0", status="completed", target_snapshot={"type": target_type, "normalized_value": value, "scope_status": "passive_allowed"})
        db.add(run); db.flush()
        evidence = Evidence(run_id=run.id, source_type=source, source_ref="fixture://stored", raw_json=raw, parsed_json=parsed, sha256=hashlib.sha256(canonical_bytes(raw)).hexdigest(), captured_at=datetime(2026, 10, 6))
        db.add(evidence); db.commit()
        evidence_id = evidence.id
    return headers, case, target, evidence_id


def test_replay_aggregation_isolation_and_rbac(system):
    client, factory = system
    headers, case, target, evidence_id = seed(client, factory)
    endpoint = f"/api/cases/{case}"
    with patch("socket.create_connection", side_effect=AssertionError("Correlation cannot collect")), patch("socket.getaddrinfo", side_effect=AssertionError("Correlation cannot resolve")):
        first = client.post(endpoint + "/correlation/jobs", headers=headers).json()
        graph = client.get(endpoint + "/graph").json()
        second = client.post(endpoint + "/correlation/jobs", headers=headers).json()
        assert first["entities_created"] == 2 and first["supports_created"] == 1
        assert second["entities_created"] == second["supports_created"] == 0
        assert client.get(endpoint + "/graph").json() == graph
    edge = graph["relationships"][0]
    assert edge["evidence_ids"] == [evidence_id]
    assert edge["first_seen"] == edge["last_seen"] == "2026-10-06T00:00:00"
    assert edge["classification"] == "observed" and edge["confidence"] == .95
    assert client.get(endpoint + "/entities").json() == graph["entities"]
    assert client.get(endpoint + "/relationships").json() == graph["relationships"]
    assert len(client.get(endpoint + "/correlation/jobs").json()) == 2
    assert client.post(endpoint + "/correlation/jobs").status_code == 403
    assert client.put(endpoint + "/members/4", headers=headers).status_code == 204
    viewer = login(client, "viewer")
    assert client.get(endpoint + "/graph").status_code == 200
    assert client.post(endpoint + "/correlation/jobs", headers=viewer).status_code == 403
    other = login(client, "other")
    for route in ("graph", "entities", "relationships"):
        assert client.get(endpoint + "/" + route).status_code == 404
    assert client.post(endpoint + "/correlation/jobs", headers=other).status_code == 404
    headers2, case2, _, _ = seed(client, factory)
    assert client.get(f"/api/cases/{case2}/graph").json()["entities"] == []
    assert client.post(f"/api/cases/{case2}/correlation/jobs", headers=headers2).json()["entities_created"] == 2
    assert {n["id"] for n in client.get(f"/api/cases/{case2}/graph").json()["entities"]}.isdisjoint({n["id"] for n in graph["entities"]})


def test_multiple_supports_and_archive_preserves_history(system):
    client, factory = system
    headers, case, target, evidence_id = seed(client, factory)
    with factory() as db:
        original = db.get(Evidence, evidence_id)
        db.add(Evidence(run_id=original.run_id, source_type=original.source_type, source_ref=original.source_ref, raw_json=original.raw_json, parsed_json=original.parsed_json, sha256=original.sha256, captured_at=datetime(2026, 10, 7)))
        db.commit()
    base = f"/api/cases/{case}"
    client.post(base + "/correlation/jobs", headers=headers)
    graph = client.get(base + "/graph").json()
    assert len(graph["relationships"]) == 1 and len(graph["relationships"][0]["evidence_ids"]) == 2
    assert graph["relationships"][0]["last_seen"] == "2026-10-07T00:00:00"
    client.delete(f"{base}/targets/{target}", headers=headers)
    assert client.post(base + "/correlation/jobs", headers=headers).json()["processed"] == 0
    assert client.get(base + "/graph").json() == graph
    client.put(base, json={"title": "Archived", "status": "archived"}, headers=headers)
    assert client.post(base + "/correlation/jobs", headers=headers).status_code == 403
    assert client.get(base + "/graph").status_code == 200


@pytest.mark.parametrize("damage", ["malformed", "hash", "scope", "snapshot"])
def test_invalid_evidence_and_scope_produce_no_edges(system, damage):
    client, factory = system
    headers, case, target, evidence_id = seed(client, factory)
    with factory() as db:
        item = db.get(Evidence, evidence_id)
        if damage == "malformed": item.parsed_json = {"status": "ok", "records": [None]}
        elif damage == "hash": item.sha256 = "0" * 64
        elif damage == "scope":
            from app.db.models import Target
            db.get(Target, target).scope_status = "excluded"
        else: db.get(CollectorRun, item.run_id).target_snapshot = {"scope_status": "excluded"}
        db.commit()
    response = client.post(f"/api/cases/{case}/correlation/jobs", headers=headers)
    assert response.status_code == 201 and response.json()["skipped"]
    assert client.get(f"/api/cases/{case}/graph").json()["relationships"] == []


@pytest.mark.parametrize("source,target_type,value,parsed,raw,relation", [
    ("rdap", "domain", "example.com", {"domain": "example.com", "nameservers": ["ns.example.com"]}, {}, "registration_nameserver"),
    ("ct", "domain", "example.com", {"certificates": [{"sha256": "a"*64, "dns_names": ["www.example.com"]}]}, {}, "certificate_observed_on"),
    ("reverse_dns", "ipv4", "8.8.8.8", {"ip": "8.8.8.8", "records": [{"name": "dns.google"}]}, {}, "ptr_observed"),
    ("ip_asn", "ipv4", "8.8.8.8", {"ip": "8.8.8.8", "availability": "observed", "prefix": "8.8.8.0/24", "asns": [15169]}, {}, "announced_by"),
    ("ip_rdap", "ipv4", "8.8.8.8", {"ip": "8.8.8.8", "start_address": "8.8.8.0", "end_address": "8.8.8.255", "organizations": [{"name": "Google LLC", "roles": ["registrant"]}]}, {}, "registered_to"),
    ("web_metadata", "url", "https://example.com/", {"requested_url": "https://example.com/", "final_url": "https://example.org/", "availability": "observed", "http_status": 200}, {"metadata": {"redirects": [{"url": "https://example.com/", "status": 302, "location": "https://example.org/"}]}}, "redirects_to"),
])
def test_typed_rules_have_evidence_and_deterministic_replay(system, source, target_type, value, parsed, raw, relation):
    client, factory = system
    headers, case, _, evidence_id = seed(client, factory, source, {"status": "ok", **parsed}, raw, target_type, value)
    base = f"/api/cases/{case}"
    assert client.post(base + "/correlation/jobs", headers=headers).status_code == 201
    graph = client.get(base + "/graph").json()
    assert any(row["type"] == relation for row in graph["relationships"])
    assert all(row["evidence_ids"] == [evidence_id] for row in graph["relationships"])
    assert client.post(base + "/correlation/jobs", headers=headers).json()["supports_created"] == 0
    assert client.get(base + "/graph").json() == graph


def test_canonical_entities_and_ambiguous_data():
    assert canonical("organization", "  ACME  Corp ") == "acme corp"
    assert canonical("asn", "AS0015169") == "AS15169"
    assert canonical("ip", "2001:4860:4860:0:0:0:0:8888") == "2001:4860:4860::8888"
    assert canonical("url", "HTTPS://EXAMPLE.COM:443") == "https://example.com/"
    for kind, value in [("certificate", "bad"), ("asn", "AS0"), ("domain", "*.example.com")]:
        with pytest.raises(ValueError): canonical(kind, value)


def test_all_dns_edges_and_failure_is_atomic(system, monkeypatch):
    client, factory = system
    parsed = {"status": "ok", "rcode": "NOERROR", "records": [{"owner": "www.example.com", "record_type": kind, "value": value} for kind, value in [("A", "8.8.8.8"), ("AAAA", "2001:4860:4860::8888"), ("NS", "ns.example.com"), ("MX", "mail.example.com"), ("CNAME", "alias.example.com")]]}
    headers, case, _, evidence_id = seed(client, factory, parsed=parsed)
    base = f"/api/cases/{case}"
    from app.api import correlation
    original = correlation.correlate
    def fail_after_projection(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("fixture failure")
    monkeypatch.setattr(correlation, "correlate", fail_after_projection)
    assert client.post(base + "/correlation/jobs", headers=headers).status_code == 500
    with factory() as db:
        assert list(db.scalars(select(Entity))) == [] and list(db.scalars(select(Relationship))) == []
    assert client.get(base + "/correlation/jobs").json()[0]["status"] == "failed"
    monkeypatch.setattr(correlation, "correlate", original)
    client.post(base + "/correlation/jobs", headers=headers)
    graph = client.get(base + "/graph").json()
    assert {row["type"] for row in graph["relationships"]} == {"resolves_to", "nameserver", "mail_server", "alias_of", "subdomain_of"}
    assert all(row["evidence_ids"] == [evidence_id] for row in graph["relationships"])
    assert any(node["roles"] == ["subdomain"] for node in graph["entities"])
    assert len({(n["type"], n["value"]) for n in graph["entities"]}) == len(graph["entities"])


def test_graph_filters_foreign_support_and_foreign_keys_prevent_evidence_delete(system):
    from sqlalchemy.exc import IntegrityError
    client, factory = system
    headers, case, _, evidence_id = seed(client, factory)
    client.post(f"/api/cases/{case}/correlation/jobs", headers=headers)
    _, _, _, other_evidence = seed(client, factory)
    with factory() as db:
        relation = db.scalar(select(Relationship).where(Relationship.evidence_id == evidence_id))
        db.add(Relationship(case_id=case, from_entity_id=relation.from_entity_id, to_entity_id=relation.to_entity_id, relation_type=relation.relation_type, evidence_id=other_evidence, confidence=.1))
        db.commit()
        db.delete(db.get(Evidence, evidence_id))
        with pytest.raises(IntegrityError): db.commit()
        db.rollback()
    graph = client.get(f"/api/cases/{case}/graph").json()
    assert graph["relationships"][0]["evidence_ids"] == [evidence_id]
    assert graph["relationships"][0]["confidence"] == .95


def test_bounded_job_cursor_preserves_all_supports(system):
    client, factory = system
    headers, case, _, evidence_id = seed(client, factory)
    with factory() as db:
        item = db.get(Evidence, evidence_id)
        db.add_all([Evidence(run_id=item.run_id, source_type=item.source_type, source_ref=item.source_ref, raw_json=item.raw_json, parsed_json=item.parsed_json, sha256=item.sha256) for _ in range(500)])
        db.commit()
    base = f"/api/cases/{case}"
    first = client.post(base + "/correlation/jobs", headers=headers).json()
    assert first["processed"] == 500 and first["has_more"]
    second = client.post(base + f"/correlation/jobs?after={first['next_after']}", headers=headers).json()
    assert second["processed"] == 1 and not second["has_more"]
    assert len(client.get(base + "/graph").json()["relationships"][0]["evidence_ids"]) == 501
