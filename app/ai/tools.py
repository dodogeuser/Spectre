"""Application-controlled, read-only and independently authorized retrieval."""
import hashlib
from sqlalchemy import select
from fastapi import HTTPException

from app.db.models import CollectorRun, Entity, Evidence, Finding, FindingEvidence, FindingRelationship, Relationship, Target
from app.security.rbac import require_case
from app.services.evidence import canonical_bytes


class CaseReadTools:
    def __init__(self, db, user, case_id):
        self._db, self._user, self.case_id = db, user, case_id
        self.case = require_case(db, user, case_id)
        self._evidence_cache = None  # Per request and case only; never conversation state.
        self.truncated = False

    def get_case_summary(self):
        # Investigator text is explicitly untrusted and bounded, not instructions.
        return {"id": self.case_id, "title": self.case.title[:200],
                "investigator_text": self.case.description[:500], "status": self.case.status}

    def search_entities(self, query=""):
        statement = select(Entity).where(Entity.case_id == self.case_id)
        if query:
            statement = statement.where(Entity.canonical_value.contains(query[:100], autoescape=True))
        return list(self._db.scalars(statement.order_by(Entity.id).limit(51)))

    def evidence(self):
        if self._evidence_cache is not None:
            return self._evidence_cache
        rows = self._db.execute(select(Evidence, CollectorRun, Target).join(CollectorRun, Evidence.run_id == CollectorRun.id)
               .join(Target, CollectorRun.target_id == Target.id).where(Target.case_id == self.case_id)
               .order_by(Evidence.id.desc()).limit(101)).all()
        self.truncated = len(rows) > 100
        valid = []
        for item, run, target in rows:
            try:
                if hashlib.sha256(canonical_bytes(item.raw_json)).hexdigest() != item.sha256:
                    continue
            except (ValueError, TypeError):
                continue
            valid.append((item, run, target))
        self._evidence_cache = valid
        return valid

    def get_entity_evidence(self, entity_id):
        entity = self._db.scalar(select(Entity).where(Entity.id == entity_id, Entity.case_id == self.case_id))
        if entity is None:
            raise HTTPException(404, "Entity not found")
        ids = set(self._db.scalars(select(Relationship.evidence_id).where(Relationship.case_id == self.case_id,
                  (Relationship.from_entity_id == entity_id) | (Relationship.to_entity_id == entity_id))))
        return [row for row in self.evidence() if row[0].id in ids]

    def list_findings(self):
        return list(self._db.scalars(select(Finding).join(Target, Finding.target_id == Target.id)
                    .where(Finding.case_id == self.case_id, Target.case_id == self.case_id)
                    .order_by(Finding.id).limit(51)))

    def explain_relationship(self, relationship_id):
        rel = self._db.scalar(select(Relationship).where(Relationship.id == relationship_id,
                                                        Relationship.case_id == self.case_id))
        if rel is None:
            raise HTTPException(404, "Relationship not found")
        a, b = self._db.get(Entity, rel.from_entity_id), self._db.get(Entity, rel.to_entity_id)
        evidence = next((row for row in self.evidence() if row[0].id == rel.evidence_id), None)
        if a is None or b is None or a.case_id != self.case_id or b.case_id != self.case_id or evidence is None:
            raise HTTPException(404, "Relationship not found")
        return rel, a, b, evidence

    def finding_evidence(self, finding):
        if not isinstance(finding.generated_json, dict):
            return []
        ids = set(self._db.scalars(select(FindingEvidence.evidence_id).where(FindingEvidence.finding_id == finding.id)))
        active = set(finding.generated_json.get("evidence_ids", []))
        return [row for row in self.evidence() if row[0].id in ids & active]

    def finding_links(self, finding):
        records = [{"type": "finding", "id": finding.id}, {"type": "target", "id": finding.target_id}]
        if finding.entity_id:
            entity = self._db.get(Entity, finding.entity_id)
            if entity is not None and entity.case_id == self.case_id:
                records.append({"type": "entity", "id": entity.id})
        for rel_id in self._db.scalars(select(FindingRelationship.relationship_id)
                                      .where(FindingRelationship.finding_id == finding.id).limit(20)):
            try:
                self.explain_relationship(rel_id)
            except HTTPException:
                continue
            records.append({"type": "relationship", "id": rel_id})
        return records
