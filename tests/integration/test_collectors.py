import asyncio
import hashlib
import socket

import pytest
from sqlalchemy import select

from tests.integration.test_accounts_cases import system, login
from app.collectors.base import Collector, CollectorResult, EvidenceItem
from app.collectors.mock import MockCollector
from app.collectors.registry import CollectorRegistry
from app.db.models import AuditLog, Case, CollectorRun, Evidence
from app.services.evidence import canonical_bytes


def setup(client):
    headers = login(client, "owner")
    case_id = client.post("/api/cases", json={"title": "Collector test"}, headers=headers).json()["id"]
    target_id = client.post(f"/api/cases/{case_id}/targets", json={"type": "domain", "value": "example.com"}, headers=headers).json()["id"]
    return headers, case_id, target_id


def test_mock_provenance_no_network_and_case_access(system, monkeypatch):
    client, factory = system
    headers, case_id, target_id = setup(client)
    def denied(*a, **k):
        raise AssertionError("No external network in mock collection")
    monkeypatch.setattr(socket, "getaddrinfo", denied)
    # Windows asyncio uses a loopback socketpair for its own event loop.
    # Block the outbound transport primitive without blocking that control pipe.
    monkeypatch.setattr(socket, "create_connection", denied)
    base = f"/api/cases/{case_id}"
    response = client.post(f"{base}/targets/{target_id}/collectors/mock/runs", headers=headers)
    assert response.status_code == 201
    run = response.json()
    assert run["status"] == "completed" and run["version"] == "1.0.0"
    assert run["ended_at"] >= run["started_at"]
    records = client.get(f"{base}/runs/{run['id']}/evidence").json()
    assert len(records) == 1
    assert records[0]["sha256"] == hashlib.sha256(canonical_bytes(records[0]["raw_json"])).hexdigest()
    assert records[0]["source_type"] == "synthetic"
    assert records[0]["captured_at"]
    assert records[0]["parsed_json"]["synthetic"] is True
    assert client.get(f"{base}/targets/{target_id}/runs").json()[0]["id"] == run["id"]
    client.put(f"{base}/members/4", headers=headers)
    viewer = login(client, "viewer")
    assert client.get(f"{base}/runs/{run['id']}/evidence").status_code == 200
    assert client.post(f"{base}/targets/{target_id}/collectors/mock/runs", headers=viewer).status_code == 403
    other = login(client, "other")
    assert client.get(f"{base}/runs/{run['id']}/evidence").status_code == 404
    assert client.post(f"{base}/targets/{target_id}/collectors/mock/runs", headers=other).status_code == 404
    with factory() as db:
        assert list(db.scalars(select(AuditLog.action).where(AuditLog.action.like("collector.%")))) == ["collector.started", "collector.completed"]


def test_scope_archive_disabled_and_csrf(system):
    client, factory = system
    headers, case_id, target_id = setup(client)
    base = f"/api/cases/{case_id}/targets/{target_id}"
    endpoint = f"{base}/collectors/mock/runs"
    assert client.post(endpoint).status_code == 403
    client.app.state.collector_registry = CollectorRegistry((MockCollector(),), frozenset({"mock"}))
    assert client.post(endpoint, headers=headers).status_code == 404
    client.app.state.collector_registry = CollectorRegistry((MockCollector(),))
    client.put(base, json={"type": "domain", "value": "example.com", "scope_status": "excluded"}, headers=headers)
    assert client.post(endpoint, headers=headers).status_code == 403
    client.put(base, json={"type": "domain", "value": "example.com", "scope_status": "active_authorized"}, headers=headers)
    assert client.post(endpoint, headers=headers).json()["status"] == "completed"  # Still passive only.
    client.delete(base, headers=headers)
    assert client.post(endpoint, headers=headers).status_code == 403
    with factory() as db:
        assert len(list(db.scalars(select(CollectorRun)))) == 1
        assert len(list(db.scalars(select(AuditLog).where(AuditLog.action == "collector.denied")))) == 3


class FailingCollector(MockCollector):
    name = "failing"
    async def collect(self, target, context):
        raise RuntimeError("password=must-not-appear")


class SlowCollector(MockCollector):
    name = "slow"
    async def collect(self, target, context):
        await asyncio.sleep(1)
        return CollectorResult()


class OversizedCollector(MockCollector):
    name = "oversized"
    async def collect(self, target, context):
        return CollectorResult(evidence=[EvidenceItem(source_type="synthetic", source_ref="mock://size",
            raw_json={"large": "x" * 10000}, parsed_json={})])


class GuardedCollector(MockCollector):
    name = "guarded"
    async def collect(self, target, context):
        await context.http.get("https://169.254.169.254/latest/meta-data")
        return CollectorResult()


class CancelledCollector(MockCollector):
    name = "cancelled"
    async def collect(self, target, context):
        raise asyncio.CancelledError()


@pytest.mark.parametrize("collector,error", [(FailingCollector(), "collector_error"), (SlowCollector(), "timeout"), (OversizedCollector(), "invalid_or_oversized_result"), (GuardedCollector(), "network_policy"), (CancelledCollector(), "cancelled")])
def test_failure_atomicity_and_sanitized_audits(system, collector, error):
    client, factory = system
    headers, case_id, target_id = setup(client)
    client.app.state.settings.collector_timeout_seconds = 0.1
    client.app.state.settings.collector_max_response_bytes = 1024
    client.app.state.collector_registry = CollectorRegistry((collector,))
    response = client.post(f"/api/cases/{case_id}/targets/{target_id}/collectors/{collector.name}/runs", headers=headers)
    assert response.status_code == 201
    assert response.json()["status"] == "failed"
    assert response.json()["error_code"] == error
    assert "must-not-appear" not in response.text
    with factory() as db:
        assert db.get(Case, case_id).title == "Collector test"
        assert list(db.scalars(select(Evidence))) == []
        entries = list(db.scalars(select(AuditLog).where(AuditLog.action.like("collector.%"))))
        assert [entry.action for entry in entries] == ["collector.started", "collector.failed"]
        assert "must-not-appear" not in str([entry.metadata_json for entry in entries])


def test_registry_rejects_active_and_duplicate_plugins():
    with pytest.raises(ValueError):
        CollectorRegistry((MockCollector(), MockCollector()))
    active = MockCollector()
    active.passive = False
    with pytest.raises(ValueError):
        CollectorRegistry((active,))


def test_framework_concurrency_and_unsupported_types(system):
    client, _ = system
    headers, case_id, target_id = setup(client)
    endpoint = f"/api/cases/{case_id}/targets/{target_id}/collectors/mock/runs"
    admission = client.app.state.collector_admission
    for _ in range(4):
        admission.acquire()
    try:
        assert client.post(endpoint, headers=headers).status_code == 429
    finally:
        for _ in range(4):
            admission.release()
    collector = MockCollector()
    collector.supported_types = frozenset({"ipv4"})
    client.app.state.collector_registry = CollectorRegistry((collector,))
    assert client.post(endpoint, headers=headers).status_code == 422


def test_partial_evidence_write_rolls_back_on_repository_error(system, monkeypatch):
    client, factory = system
    headers, case_id, target_id = setup(client)
    def fail_after_write(db, run_id, *args):
        db.add(Evidence(run_id=run_id, source_type="synthetic", source_ref="mock://partial",
                        sha256="0" * 64, raw_json={}, parsed_json={}))
        db.flush()
        raise RuntimeError("repository fixture error")
    monkeypatch.setattr("app.services.collection.store_evidence", fail_after_write)
    response = client.post(f"/api/cases/{case_id}/targets/{target_id}/collectors/mock/runs", headers=headers)
    assert response.json()["status"] == "failed"
    with factory() as db:
        assert list(db.scalars(select(Evidence))) == []
        assert db.get(Case, case_id).title == "Collector test"
