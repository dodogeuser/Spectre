"""Extractive grounding: provider selects facts; server owns claims and citations."""
import json
import re

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt
from sqlalchemy import select

from app.ai.provider import ProviderError
from app.ai.tools import CaseReadTools
from app.db.models import Relationship
from app.services.correlation import RULES as CORRELATION_RULES

INSUFFICIENT = "The stored evidence in this case is insufficient to determine that."
NOTICE = "AI-generated analysis is not evidence. This is an AI-selected summary of stored records, not independently verified facts."


class Selection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fact_id: str = Field(max_length=100)
    evidence_ids: list[StrictInt] = Field(min_length=1, max_length=20)


class Answer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    insufficient: StrictBool
    selections: list[Selection] = Field(max_length=12)


def intent(question):
    # Defense in depth, not the capability boundary. Even obfuscated requests
    # cannot execute: providers receive data and return validated selections only.
    if re.search(r"https?://|\b(scan|scanning|execute|powershell|shell|python|credentials?|passwords?|secrets?|collect|collectors?|browse|fetch|brute|exploit|delete|modify|change|create|other case|another case)\b", question, re.I):
        return "prohibited"
    for name, pattern in (("findings", r"finding|severity|confidence"), ("relationships", r"relationship|correlation"),
                          ("entities", r"entit"), ("timeline", r"timeline|chronolog"),
                          ("evidence", r"evidence|observation|metadata"), ("summary", r"summar|overview")):
        if re.search(pattern, question, re.I):
            return name
    return "unsupported"


def context_for(tools: CaseReadTools, mode, entity_id=None, relationship_id=None):
    rows = tools.get_entity_evidence(entity_id) if entity_id else tools.evidence()
    if mode == "timeline":
        rows = sorted(rows, key=lambda row: (row[0].captured_at, row[0].id))
    facts = []
    def add(key, category, text, support, records):
        ids = sorted({row[0].id for row in support})[:20]
        if not ids:
            return
        facts.append({"fact_id": key, "category": category, "text": text[:2000],
                      "evidence_ids": ids, "records": records})
    if mode in ("findings", "summary"):
        for finding in tools.list_findings()[:50]:
            support = tools.finding_evidence(finding)
            # A malformed or disconnected finding never becomes an AI fact.
            data = finding.generated_json
            if not isinstance(data, dict) or not support:
                continue
            text = (f"Stored deterministic Finding #{finding.id}: {finding.title}. "
                    f"Status: {finding.status}; severity: {finding.severity_override or data.get('severity')}; "
                    f"confidence: {data.get('confidence')} (separate from severity). "
                    f"Rule: {finding.rule_id} version {finding.rule_version}. "
                    f"Original rule severity: {finding.original_json.get('severity')}. "
                    f"Rule state: {data.get('rule_state')}. Reasoning: {json.dumps(data.get('why', []), ensure_ascii=False)}. "
                    "This stored finding is not proof of exploitation or compromise.")
            add(f"finding:{finding.id}", "deterministic_finding", text, support,
                tools.finding_links(finding))
    if mode in ("relationships", "summary") or relationship_id:
        ids = [relationship_id] if relationship_id else list(tools._db.scalars(select(Relationship.id)
              .where(Relationship.case_id == tools.case_id).order_by(Relationship.id).limit(50)))
        for rel_id in ids:
            try:
                rel, a, b, support = tools.explain_relationship(rel_id)
            except Exception as exc:
                from fastapi import HTTPException
                if not isinstance(exc, HTTPException) or relationship_id:
                    raise
                continue
            classification = CORRELATION_RULES.get(rel.relation_type, (None, "legacy_observation", "Preserved stored support"))
            add(f"relationship:{rel.id}", classification[1] + "_relationship", f"Stored {classification[1]} relationship #{rel.id}: "
                f"Entity #{a.id} ({a.canonical_value}) --{rel.relation_type}--> Entity #{b.id} ({b.canonical_value}); "
                f"stored confidence {rel.confidence}. Rule: {classification[2]}. Supporting Evidence #{rel.evidence_id}. "
                "This is a stored correlation, not an AI inference or proof of ownership.", [support],
                [{"type": "relationship", "id": rel.id}, {"type": "entity", "id": a.id}, {"type": "entity", "id": b.id}])
    if mode == "entities":
        for entity in tools.search_entities()[:50]:
            if entity_id and entity.id != entity_id:
                continue
            add(f"entity:{entity.id}", "stored_entity", f"Stored Entity #{entity.id}: {entity.entity_type} {entity.canonical_value}.",
                tools.get_entity_evidence(entity.id), [{"type": "entity", "id": entity.id}])
    if mode in ("evidence", "timeline", "summary"):
        for item, run, target in rows[:50]:
            parsed = item.parsed_json if isinstance(item.parsed_json, dict) else {}
            # Only bounded, named observation fields; never raw HTTP bodies,
            # credentials, contact records or provider payload dumps.
            selected = {key: parsed[key] for key in ("availability", "status", "http_status", "title", "rcode", "query_type", "caveat")
                        if key in parsed and isinstance(parsed[key], (str, int, bool, type(None)))}
            raw = item.raw_json if isinstance(item.raw_json, dict) else {}
            metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
            synthetic = item.source_type == "synthetic" or bool(raw.get("synthetic")) or bool(metadata.get("synthetic_fixture"))
            add(f"evidence:{item.id}", "synthetic_fixture" if synthetic else "stored_observation", f"Evidence #{item.id}, captured {item.captured_at.isoformat()}; "
                f"source type {item.source_type}; run #{run.id} ({run.collector} {run.version}, {run.status}); "
                f"target #{target.id}; normalized observation fields (untrusted data): {json.dumps(selected, ensure_ascii=False)[:1000]}. "
                "Unavailable, partial or failed intelligence is not a confirmed negative result.", [(item, run, target)],
                [{"type": "run", "id": run.id}, {"type": "target", "id": target.id}])
    # Explicit byte budget; deterministic newest evidence and ascending record IDs.
    context = {"case": tools.get_case_summary(), "facts": [], "truncated": tools.truncated}
    for fact in facts:
        context["facts"].append(fact)
        if len(json.dumps(context, ensure_ascii=False).encode()) > 24000:
            context["facts"].pop(); context["truncated"] = True; break
    if len(rows) > 50 or len(facts) >= 50:
        context["truncated"] = True
    return context


def validate_answer(value, context):
    try:
        result = Answer.model_validate(value)
    except Exception:
        raise ProviderError("malformed_output") from None
    if result.insufficient:
        if result.selections:
            raise ProviderError("invalid_citations")
        return {"status": "insufficient", "message": INSUFFICIENT, "claims": [], "notice": NOTICE}
    catalog = {fact["fact_id"]: fact for fact in context["facts"]}
    claims, seen = [], set()
    for selection in result.selections:
        fact = catalog.get(selection.fact_id)
        if fact is None or sorted(selection.evidence_ids) != fact["evidence_ids"] or selection.fact_id in seen:
            raise ProviderError("invalid_citations")
        seen.add(selection.fact_id); claims.append(fact)
    if not claims:
        raise ProviderError("invalid_citations")
    return {"status": "answered", "message": "AI selected these stored records. No new facts were inferred.",
            "claims": claims, "notice": NOTICE, "truncated": context["truncated"]}
