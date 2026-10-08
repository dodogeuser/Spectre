"""Atomic evidence persistence with reproducible hashes; no write API exposed."""
import hashlib
import json

from app.collectors.base import CollectorResult
from app.db.models import Evidence


def canonical_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def store_evidence(db, run_id: int, result: CollectorResult, max_bytes: int):
    total = 0
    records = []
    for item in result.evidence:
        raw = canonical_bytes(item.raw_json)
        parsed = canonical_bytes(item.parsed_json)
        total += len(raw) + len(parsed) + len(item.source_ref.encode("utf-8"))
        if total > max_bytes:
            raise ValueError("Evidence payload exceeds policy")
        records.append(Evidence(run_id=run_id, source_type=item.source_type, source_ref=item.source_ref,
                                sha256=hashlib.sha256(raw).hexdigest(), raw_json=item.raw_json, parsed_json=item.parsed_json))
    db.add_all(records)
    return records
