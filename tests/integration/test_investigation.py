from unittest.mock import patch
from datetime import datetime

from sqlalchemy import select

from app.db.models import Evidence, Entity, Relationship
from tests.integration.test_accounts_cases import system, login
from tests.integration.test_correlation import seed


def prepare(system):
    client, factory = system
    headers, case, target, evidence = seed(client, factory)
    client.post(f"/api/cases/{case}/correlation/jobs", headers=headers)
    return client, factory, headers, case, evidence


def test_graph_details_timeline_linkage_and_no_collection(system):
    client, _, _, case, evidence = prepare(system)
    with patch("socket.create_connection", side_effect=AssertionError("Read must not collect")), patch("socket.getaddrinfo", side_effect=AssertionError("Read must not resolve")):
        base = f"/api/cases/{case}"
        data = client.get(base + "/investigation").json()
        assert data["relationships"][0]["sources"] == ["dns"]
        assert data["evidence"][0]["id"] == evidence
        for node in data["entities"]:
            detail = client.get(f"{base}/entities/{node['id']}/detail").json()
            assert detail["evidence"][0]["id"] == evidence
            assert detail["first_seen"] == detail["last_seen"] == "2026-10-06T00:00:00"
        timeline = client.get(base + "/timeline").json()
        assert [row["type"] for row in timeline["events"]] == ["evidence.captured", "relationship.first_seen"]
        assert all(row["evidence_ids"] == [evidence] for row in timeline["events"])
        assert client.get(base + "/timeline").json() == timeline
        assert client.get(base + "/timeline?limit=1").json()["has_more"]
        assert client.get(base + "/timeline?limit=1&offset=1").json()["events"] == timeline["events"][1:]
        assert client.get(base + "/timeline?limit=101").status_code == 422


def test_rbac_empty_case_and_cross_case_inspection(system):
    client, _, headers, case, _ = prepare(system)
    base = f"/api/cases/{case}"
    entity = client.get(base + "/investigation").json()["entities"][0]["id"]
    client.put(base + "/members/4", headers=headers)
    viewer = login(client, "viewer")
    for route in ("investigation", "timeline", f"entities/{entity}/detail"):
        assert client.get(base + "/" + route).status_code == 200
    other = login(client, "other")
    for route in ("investigation", "timeline", f"entities/{entity}/detail"):
        assert client.get(base + "/" + route).status_code == 404
    empty = client.post("/api/cases", json={"title": "Empty case"}, headers=other).json()["id"]
    assert client.get(f"/api/cases/{empty}/timeline").json()["events"] == []
    assert client.get(f"/api/cases/{empty}/investigation").json()["entities"] == []
    assert client.get(f"/api/cases/{empty}/entities/{entity}/detail").status_code == 404


def test_standalone_web_node_provenance_and_replay_timeline(system):
    client, factory = system
    parsed = {"status": "ok", "availability": "observed", "http_status": 200, "requested_url": "https://example.com/", "final_url": "https://example.com/"}
    headers, case, _, evidence = seed(client, factory, "web_metadata", parsed, target_type="url", value="https://example.com/")
    base = f"/api/cases/{case}"
    client.post(base + "/correlation/jobs", headers=headers)
    graph = client.get(base + "/investigation").json()
    assert graph["relationships"] == []
    node = graph["entities"][0]
    assert node["sources"] == ["web_metadata"] and node["evidence_ids"] == [evidence]
    assert client.get(f"{base}/entities/{node['id']}/detail").json()["evidence"][0]["id"] == evidence
    before = client.get(base + "/timeline").json()
    client.post(base + "/correlation/jobs", headers=headers)
    assert client.get(base + "/timeline").json() == before


def test_large_graph_limits_and_timeline_pagination(system):
    client, factory, _, case, evidence = prepare(system)
    import hashlib
    with factory() as db:
        for number in range(5050):
            value = f"node{number}.example.com"
            db.add(Entity(case_id=case, entity_type="domain", canonical_value=value, canonical_hash=hashlib.sha256(value.encode()).hexdigest(), attributes_json={}))
        item = db.get(Evidence, evidence)
        db.add_all([Evidence(run_id=item.run_id, source_type=item.source_type, source_ref=item.source_ref, raw_json=item.raw_json, parsed_json=item.parsed_json, sha256=item.sha256, captured_at=datetime(2026,10,6)) for _ in range(125)])
        db.commit()
    graph = client.get(f"/api/cases/{case}/investigation").json()
    assert graph["truncated"] and len(graph["entities"]) == 5000
    first = client.get(f"/api/cases/{case}/timeline").json()
    second = client.get(f"/api/cases/{case}/timeline?offset=100").json()
    assert len(first["events"]) == 100 and first["has_more"]
    keys = [row["key"] for row in first["events"] + second["events"]]
    assert len(keys) == len(set(keys))
    assert first == client.get(f"/api/cases/{case}/timeline").json()


def test_foreign_case_relationship_support_never_leaks(system):
    client, factory, headers, case, evidence = prepare(system)
    _, other_case, _, other_evidence = seed(client, factory)
    with factory() as db:
        relation = db.scalar(select(Relationship).where(Relationship.evidence_id == evidence))
        db.add(Relationship(case_id=case, from_entity_id=relation.from_entity_id, to_entity_id=relation.to_entity_id, relation_type="resolves_to", confidence=.1, evidence_id=other_evidence))
        db.commit()
    for route in ("investigation", "timeline"):
        result = client.get(f"/api/cases/{case}/{route}").json()
        assert str(other_evidence) not in [str(row.get("id")) for row in result.get("evidence", [])]
        assert all(other_evidence not in row["evidence_ids"] for row in result.get("events", []))
    assert client.get(f"/api/cases/{other_case}/investigation").json()["relationships"] == []
