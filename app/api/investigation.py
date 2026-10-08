"""Read-only graph inspection and chronological views of existing case records."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.auth import current_user
from app.db.models import CollectorRun, Evidence, Target, User
from app.db.session import get_db
from app.security.rbac import require_case
from app.services.correlation import graph, plan

router = APIRouter(prefix="/api/cases/{case_id}", tags=["graph and timeline views"])


def evidence_rows(db, case_id, ids=None, limit=10001):
    query = select(Evidence, CollectorRun).join(CollectorRun, Evidence.run_id == CollectorRun.id).join(Target, CollectorRun.target_id == Target.id).where(Target.case_id == case_id)
    if ids is not None:
        query = query.where(Evidence.id.in_(ids))
    return db.execute(query.order_by(Evidence.captured_at, Evidence.id).limit(limit)).all()


def summary(item, run):
    parsed = item.parsed_json if isinstance(item.parsed_json, dict) else {}
    raw = item.raw_json if isinstance(item.raw_json, dict) else {}
    metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
    return {"id": item.id, "run_id": run.id, "target_id": run.target_id, "source_type": item.source_type, "source_ref": item.source_ref, "provider": parsed.get("provider"), "captured_at": item.captured_at, "sha256": item.sha256, "collector": run.collector, "version": run.version, "synthetic_fixture": bool(metadata.get("synthetic_fixture"))}


def view(db, case_id):
    data = graph(db, case_id)
    ids = {eid for edge in data["relationships"] for eid in edge["evidence_ids"]}
    rows = evidence_rows(db, case_id)
    nodes = {(node["type"], node["value"]): node for node in data["entities"]}
    by_id = {node["id"]: node for node in data["entities"]}
    for node in data["entities"]:
        node["evidence_ids"] = []
        node["sources"] = []
    for item, run in rows[:10000]:
        try:
            literals, _ = plan(item, run)
            for literal in literals:
                if literal in nodes:
                    node = nodes[literal]
                    node["evidence_ids"].append(item.id)
                    node["sources"].append(item.source_type)
                    ids.add(item.id)
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
            continue
    evidence = {item.id: summary(item, run) for item, run in rows[:10000] if item.id in ids}
    for edge in data["relationships"]:
        edge["sources"] = sorted({evidence[eid]["source_type"] for eid in edge["evidence_ids"] if eid in evidence})
        for entity_id in {edge["from"], edge["to"]}:
            node = by_id.get(entity_id)
            if node is not None:
                node["evidence_ids"].extend(edge["evidence_ids"])
                node["sources"].extend(edge["sources"])
    for node in data["entities"]:
        node["evidence_ids"] = sorted(set(node["evidence_ids"]))
        node["sources"] = sorted(set(node["sources"]))
    data["truncated"] = data["truncated"] or len(rows) > 10000
    data["evidence"] = list(evidence.values())
    return data


@router.get("/investigation")
def investigation(case_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_case(db, user, case_id)
    result = view(db, case_id)
    db.commit()
    return result


@router.get("/entities/{entity_id}/detail")
def detail(case_id: int, entity_id: int, offset: int = Query(0, ge=0), user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_case(db, user, case_id)
    data = view(db, case_id)
    node = next((n for n in data["entities"] if n["id"] == entity_id), None)
    if node is None:
        raise HTTPException(404, "Entity not found in bounded graph")
    related = [edge for edge in data["relationships"] if entity_id in {edge["from"], edge["to"]}]
    ids = set(node["evidence_ids"])
    evidence = [row for row in data["evidence"] if row["id"] in ids]
    result = {"entity": node, "relationships": related, "evidence": evidence[offset:offset+100], "has_more": len(evidence) > offset+100, "first_seen": min((row["captured_at"] for row in evidence), default=None), "last_seen": max((row["captured_at"] for row in evidence), default=None), "truncated": data["truncated"]}
    db.commit()
    return result


@router.get("/timeline")
def timeline(case_id: int, offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=100), user: User = Depends(current_user), db: Session = Depends(get_db)):
    require_case(db, user, case_id)
    data = graph(db, case_id)
    rows = evidence_rows(db, case_id)
    events = [{"timestamp": item.captured_at, "type": "evidence.captured", "key": f"evidence:{item.id}", "evidence_ids": [item.id], "run_ids": [run.id], "entity_ids": [], "source": item.source_type, "source_ref": item.source_ref} for item, run in rows[:10000]]
    for edge in data["relationships"]:
        events.append({"timestamp": edge["first_seen"], "type": "relationship.first_seen", "key": f"relationship:{edge['from']}:{edge['to']}:{edge['type']}", "evidence_ids": edge["evidence_ids"], "run_ids": [], "entity_ids": [edge["from"], edge["to"]], "source": edge["type"], "classification": edge["classification"]})
    from app.active.views import stored,events as active_events
    events.extend(active_events(stored(db,case_id)))
    events.sort(key=lambda e: (e["timestamp"], e["type"], e["key"]))
    result = {"events": events[offset:offset+limit], "offset": offset, "limit": limit, "has_more": len(events) > offset+limit, "truncated": data["truncated"] or len(rows) > 10000, "ordering": "stored timestamp, event type, stable event key; timestamps are UTC", "bounded_total": len(events)}
    db.commit()
    return result
