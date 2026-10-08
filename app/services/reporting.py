"""Deterministic exports of authorized stored records. No AI, collection or file writes."""
import base64
import hashlib
import html
import json
import math
import re
from datetime import datetime
from io import BytesIO
from pathlib import Path
from urllib.parse import unquote

from fastapi import HTTPException
from sqlalchemy import select

from app.api.investigation import view
from app.db.models import AuditLog, CollectorRun, Evidence, Finding, FindingEvidence, FindingRelationship, Relationship, Target, User
from app.services.evidence import canonical_bytes

BRAND_LOGO = Path(__file__).resolve().parents[1] / "static" / "images" / "branding" / "spectre-report.png"
VERSION = "1.0.0"
LIMIT = 10000
MAX_CONTEXT_BYTES = 8 * 1024 * 1024
LIMITATIONS = "Stored passive observations describe capture-time results, not current availability, ownership, exploitability or authorization for active assessment. Missing, failed, partial and unavailable intelligence are not proof of absence. Confidence measures observation support independently of severity. CT names do not establish a live service. AI output and browser-local graph layouts are excluded."


def clean_text(value, secrets=()):
    text = str(value)
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    text = re.sub(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", r"\1 [REDACTED]", text)
    text = re.sub(r"(?i)((?:[\"']?[\w-]*(?:password|passwd|token|api[_-]?key|secret|authorization)[\"']?)\s*[=:]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;&]+)", r"\1[REDACTED]", text)
    text = re.sub(r"(://)[^\s/@]+:[^\s/@]+@", r"\1[REDACTED]@", text)
    # Encoded query names still cannot smuggle credentials into a source reference.
    def query_value(match):
        key = unquote(match[2])
        return match[1]+match[2]+"=[REDACTED]" if re.search(r"(?i)password|passwd|token|api.?key|secret|authorization",key) else match[0]
    text = re.sub(r"([?&])([^\s=&]+)=([^\s&#]*)",query_value,text)
    return "".join(c for c in text if ord(c) >= 32 or c in "\n\t")


def normalize(value, secrets):
    if isinstance(value, datetime):
        return value.isoformat() + "Z"
    if isinstance(value, str):
        return clean_text(value, secrets)
    if isinstance(value, list):
        return [normalize(v, secrets) for v in value]
    if isinstance(value, dict):
        return {str(k): "[REDACTED]" if re.search(r"(?i)password|passwd|token|api.?key|secret|authorization",str(k)) else normalize(v, secrets) for k, v in value.items()}
    return value


def bounded(db, query):
    rows = list(db.scalars(query.limit(LIMIT + 1)))
    if len(rows) > LIMIT:
        raise HTTPException(413, "Case exceeds complete-report limits; no partial report was exported")
    return rows


def snapshot(db, case, redact_notes=True, secrets=()):
    targets = bounded(db, select(Target).where(Target.case_id == case.id).order_by(Target.id))
    runs = bounded(db, select(CollectorRun).join(Target).where(Target.case_id == case.id).order_by(CollectorRun.id))
    evidence = bounded(db, select(Evidence).join(CollectorRun).join(Target).where(Target.case_id == case.id).order_by(Evidence.id))
    findings = bounded(db, select(Finding).where(Finding.case_id == case.id).order_by(Finding.id))
    graph = view(db, case.id)
    if graph["truncated"]:
        raise HTTPException(413, "Case graph exceeds complete-report limits; no partial report was exported")
    evidence_ids = {e.id for e in evidence}
    target_ids = {t.id for t in targets}
    entity_ids = {n["id"] for n in graph["entities"]}
    support_ids = {sid for e in graph["relationships"] for sid in e["support_ids"]}
    run_map = {r.id: r for r in runs}
    evidence_index = []
    for e in evidence:
        try:
            valid = hashlib.sha256(canonical_bytes(e.raw_json)).hexdigest() == e.sha256
        except (ValueError, TypeError, OverflowError):
            valid = False
        if not valid:
            raise HTTPException(409, "Stored evidence integrity verification failed; export blocked")
        parsed = e.parsed_json if isinstance(e.parsed_json, dict) else {}
        evidence_index.append({"id": e.id, "run_id": e.run_id, "target_id": run_map[e.run_id].target_id, "collector": run_map[e.run_id].collector, "version": run_map[e.run_id].version, "source_type": e.source_type, "source_ref": e.source_ref, "provider": parsed.get("provider") if isinstance(parsed.get("provider"),str) else None, "captured_at": e.captured_at, "sha256": e.sha256, "integrity": "verified", "availability": parsed.get("availability",parsed.get("status","not specified")), "dns_rcode": parsed.get("rcode")})
    finding_rows = []
    for f in findings:
        ids = sorted(db.scalars(select(FindingEvidence.evidence_id).where(FindingEvidence.finding_id == f.id)))
        rel_ids = sorted(db.scalars(select(FindingRelationship.relationship_id).where(FindingRelationship.finding_id == f.id)))
        g = f.generated_json if isinstance(f.generated_json, dict) else {}
        original = f.original_json if isinstance(f.original_json, dict) else {}
        active = g.get("evidence_ids", [])
        original_ids=original.get('evidence_ids',[])
        rel_evidence=set(db.scalars(select(Relationship.evidence_id).where(Relationship.id.in_(rel_ids)))) if rel_ids else set()
        if f.target_id not in target_ids or (f.entity_id is not None and f.entity_id not in entity_ids) or not ids or not set(ids) <= evidence_ids or not isinstance(active,list) or any(type(i) is not int for i in active) or not set(active) <= set(ids) or not isinstance(original_ids,list) or any(type(i) is not int for i in original_ids) or not set(original_ids)<=set(ids) or not set(rel_ids) <= support_ids or not rel_evidence<=set(ids) or (g.get("assessment_evidence_id") is not None and g["assessment_evidence_id"] not in ids):
            raise HTTPException(409, "Finding support is missing or outside this case; export blocked")
        finding_rows.append({"id": f.id, "target_id": f.target_id, "entity_id": f.entity_id, "finding_type":f.finding_type,"title": f.title, "description": f.description, "status": f.status, "rule_id": f.rule_id, "rule_version": f.rule_version,"scoring_version":g.get("scoring_version"), "severity": f.severity_override or g.get("severity","not specified"), "confidence": g.get("confidence"), "rule_severity": g.get("severity"), "original_rule_severity": original.get("severity"), "original_rule_confidence": original.get("confidence"), "why": g.get("why",[]),"recency":g.get("recency"), "assessment_state": g.get("assessment_state",g.get("rule_state","not specified")),"assessment_reason":g.get("assessment_reason"), "severity_override": f.severity_override, "override_reason": "[Analyst text omitted]" if redact_notes and f.override_reason else f.override_reason, "notes": "[Analyst text omitted]" if redact_notes and f.notes else f.notes, "evidence_ids": ids, "active_evidence_ids": active, "relationship_support_ids": rel_ids, "created_at": f.created_at, "updated_at": f.updated_at})
    for edge in graph["relationships"]:
        if not set(edge["evidence_ids"]) <= evidence_ids:
            raise HTTPException(409, "Relationship evidence is outside this case; export blocked")
    for node in graph['entities']:
        if not set(node['evidence_ids'])<=evidence_ids:
            raise HTTPException(409,"Entity evidence is outside this case; export blocked")
    events = []
    def event(at,kind,key,description):
        if at is not None:
            events.append({"timestamp": at, "type": kind, "key": key, "description": description})
    for r in runs:
        event(r.started_at,"collector.started",f"run:{r.id}:start",f"Run #{r.id}: {r.collector} {r.version}; Target #{r.target_id}")
        event(r.ended_at,"collector."+r.status,f"run:{r.id}:end",f"Run #{r.id}: {r.status}; error {r.error_code or 'none'}")
    for e in evidence:
        event(e.captured_at,"evidence.captured",f"evidence:{e.id}",f"Evidence #{e.id}; Run #{e.run_id}; {e.source_type}")
    for edge in graph["relationships"]:
        event(edge["first_seen"],"relationship.first_seen",f"relationship:{edge['from']}:{edge['to']}:{edge['type']}",f"Entity #{edge['from']} - {edge['type']} - Entity #{edge['to']}; Evidence {edge['evidence_ids']}")
    for f in findings:
        event(f.created_at,"finding.created",f"finding:{f.id}",f"Finding #{f.id}: {f.title}")
    # Export/auth/admin-access events are excluded so repeated exports reproduce.
    actions = bounded(db,select(AuditLog).where(AuditLog.object_type=="case",AuditLog.object_id==case.id,AuditLog.action.in_(["case.create","case.update","target.create","target.update","target.archive","finding.generated","finding.regenerated","finding.updated","finding.status_changed","finding.severity_overridden","findings.generated","correlation.completed"])).order_by(AuditLog.id))
    for a in actions:
        event(a.timestamp,a.action,f"audit:{a.id}",f"{a.action}; User #{a.actor_id}; Audit #{a.id}")
    owner = db.scalar(select(User.username).where(User.id==case.owner_id))
    result = normalize({"report_version": VERSION,"case": {"id":case.id,"title":case.title,"description":"[Analyst text omitted]" if redact_notes and case.description else case.description,"status":case.status,"owner_id":case.owner_id,"owner":owner,"created_at":case.created_at},"redact_notes":redact_notes,"targets":[{k:getattr(t,k) for k in ("id","type","normalized_value","scope_status","archived","created_at","updated_at")} for t in targets],"runs":[{k:getattr(r,k) for k in ("id","target_id","actor_id","collector","version","status","error_code","started_at","ended_at","warnings_json")} for r in runs],"evidence":evidence_index,"entities":[{k:n[k] for k in ("id","type","roles","value","evidence_ids","sources")} for n in graph["entities"]],"relationships":graph["relationships"],"findings":finding_rows,"events":events,"limitations":LIMITATIONS},secrets)
    result["events"].sort(key=lambda e:(e["timestamp"],e["type"],e["key"]))
    from app.active.views import stored,events as active_events
    active=stored(db,case.id,redact_notes)
    if active:
        result['active_verification']=normalize(active,secrets)
        result['active_verification']['authorizations']=[normalize(g,secrets) for g in active['authorizations']]
        for safe_run,original_run in zip(result['active_verification']['runs'],active['runs']):
            safe_run['authorization_id']=original_run['authorization_id']
        for e in active_events(active):
            result['events'].append(normalize({'timestamp':e['timestamp'],'type':e['type'],'key':e['key'],'description':e['source']},secrets))
        result['events'].sort(key=lambda e:(e['timestamp'],e['type'],e['key']))
    if any(redacted['sha256']!=original.sha256 for redacted,original in zip(result['evidence'],evidence)):
        raise HTTPException(409,"Evidence hash cannot be represented safely; export blocked")
    result["counts"]={name:len(result[name]) for name in ("targets","runs","evidence","entities","relationships","findings")}
    content=json.dumps(result,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    if len(content)>MAX_CONTEXT_BYTES:
        raise HTTPException(413,"Case exceeds report size budget; no partial report was exported")
    result["snapshot_sha256"]=hashlib.sha256(content).hexdigest()
    return result


def sections(s):
    """Shared content for HTML and PDF; IDs are validated before rendering."""
    c=s["case"];counts=s["counts"]
    yield "Case information",[(None,f"Case #{c['id']}: {c['title']}"),(None,f"Status: {c['status']} | Owner: {c['owner']} (#{c['owner_id']}) | Created: {c['created_at']}"),(None,c["description"] or "No case description stored.")]
    yield "Executive summary",[(None,f"Stored investigation contains {counts['targets']} targets, {counts['runs']} collector runs, {counts['evidence']} evidence records, {counts['entities']} entities, {counts['relationships']} logical relationships and {counts['findings']} findings. Failed runs: {sum(r['status']=='failed' for r in s['runs'])}. These counts are observations, not a vulnerability or ownership assessment.")]
    yield "Scope and methodology",[(None,"Only stored authorized case data is exported. Reports perform no DNS, HTTP, provider or AI requests. Historical records remain after archive/exclusion; current target scope does not retroactively authorize collection. Analyst-text redaction: "+str(s["redact_notes"])),(None,"A snapshot digest identifies the exported content. Evidence raw SHA-256 values were verified against stored raw JSON. Raw provider bodies, account secrets, AI output and browser graph layouts are not included.")]
    yield "Targets",[(f"target-{t['id']}",f"Target #{t['id']} | {t['type']} | {t['normalized_value']} | Scope: {t['scope_status']} | Archived: {t['archived']} | Created {t['created_at']} | Updated {t['updated_at']}") for t in s["targets"]]
    yield "Discovered infrastructure",[(f"entity-{n['id']}",f"Entity #{n['id']} | {n['type']} {', '.join(n['roles'])} | {n['value']} | Sources: {', '.join(n['sources']) or 'not established'} | Evidence: {', '.join('#'+str(i) for i in n['evidence_ids']) or 'no direct support in stored graph'}") for n in s["entities"]]
    names={n["id"]:n["value"] for n in s["entities"]}
    yield "Relationships",[(f"relationship-{e['support_ids'][0]}",f"{names[e['from']]} (#{e['from']}) - {e['type']} - {names[e['to']]} (#{e['to']}) | {e['classification']} | Support confidence: {e['confidence']} | Rule: {e['rule']} | Evidence: {e['evidence_ids']} | Support IDs: {e['support_ids']} | First/last capture: {e['first_seen']} / {e['last_seen']}") for e in s["relationships"]]
    rows=[]
    for f in s["findings"]:
        rows.append((f"finding-{f['id']}",f"Finding #{f['id']}: {f['title']}\n{f['description']}\nSeverity: {f['severity']} | Confidence: {f['confidence']} | Status: {f['status']} | Target #{f['target_id']} | Entity {f['entity_id']}\nRule: {f['rule_id']} v{f['rule_version']} | Rule severity: {f['rule_severity']} | Original rule: {f['original_rule_severity']} / {f['original_rule_confidence']}\nWhy: {'; '.join(str(v) for v in f['why']) if isinstance(f['why'],list) else 'not specified'}\nAssessment: {f['assessment_state']} | Analyst override: {f['severity_override']} | Reason: {f['override_reason']} | Notes: {f['notes']}\nEvidence: {f['evidence_ids']} (active: {f['active_evidence_ids']}) | Relationship supports: {f['relationship_support_ids']}\nCreated/updated: {f['created_at']} / {f['updated_at']}"))
    yield "Findings",rows
    yield "Finding rubric",[(None,"Severity is potential importance; confidence is observation support. Phase 09 missing-header rules retain informational rule severity and 0.95 confidence for the captured observation; neither establishes a vulnerability. Recency is relative to the newest stored case capture, with a 30-day recent threshold. No numeric risk score. An analyst override changes displayed severity, not rule confidence or the original rule result."),*[(None,f"Finding #{f['id']} | Scoring version: {f['scoring_version']} | Recency: {f['recency']} | Current assessment reason: {f['assessment_reason'] or 'not specified'}") for f in s['findings']]]
    yield "Collector run history",[(f"run-{r['id']}",f"Run #{r['id']} | {r['collector']} v{r['version']} | Target #{r['target_id']} | {r['status']} | Started: {r['started_at']} | Ended: {r['ended_at']} | Error: {r['error_code'] or 'none'} | Warnings: {'; '.join(str(w) for w in r['warnings_json'])}") for r in s["runs"]]
    if 'active_verification' in s:
        active=s['active_verification']
        yield 'Active Verification',[(None,'ACTIVE VERIFICATION is direct contact under a recorded exact-target grant. Passive observations remain historical and separate. Captures establish only the observed response at that time, not exploitability or broader authorization. Case kill switch stopped: '+str(active['case_stopped'])),*[(None,f"Authorization #{g['id']} | Target #{g['target_id']} | Granted by User #{g['granted_by']} at {g['granted_at']} | Scope: {g['scope_json']} | Revoked: {g['revoked_at']} | Note: {g['note']}") for g in active['authorizations']],*[(None,f"ACTIVE run #{r['id']} | Target #{r['target_id']} | {r['module']} v{r['version']} | {r['status']} | Authorization #{r['authorization_id']} | Action: {r['action_json']} | Requested/started/ended {r['requested_at']} / {r['started_at']} / {r['ended_at']} | Error: {r['error_code']} | Evidence: {r['evidence_ids']} | Measurements: {r['result_json']}") for r in active['runs']],*[(None,f"Finding #{v['finding_id']} | Active run #{v['active_run_id']} | {v['state']} | {v['reason']} | Evidence #{v['evidence_id']}") for v in active['verifications']]]
    yield "Investigation timeline",[(None,f"{e['timestamp']} | {e['type']} | {e['description']}") for e in s["events"]]
    yield "Evidence appendix",[(f"evidence-{e['id']}",f"Evidence #{e['id']} | Run #{e['run_id']} | Target #{e['target_id']} | Entities: {[n['id'] for n in s['entities'] if e['id'] in n['evidence_ids']]}\n{e['collector']} v{e['version']} | {e['source_type']} | Provider: {e['provider'] or 'not specified'}\nCaptured: {e['captured_at']} | Availability: {e['availability']} | DNS result: {e['dns_rcode'] or 'not specified'}\nSource: {e['source_ref']}\nSHA-256: {e['sha256']} | Integrity: {e['integrity']}") for e in s["evidence"]]
    yield "Limitations",[(None,s["limitations"]),(None,"Case update time and target notes are not stored by the current schema and are not invented. The graph schematic omits certificate nodes and is bounded to 32 nodes for legibility; the infrastructure and relationship indexes retain the complete stored snapshot.")]


def diagram(s):
    nodes=[n for n in s["entities"] if n["type"]!="certificate"][:32]
    positions={n["id"]:(60+(i%4)*120,35+(i//4)*65) for i,n in enumerate(nodes)}
    height=max(120,math.ceil(len(nodes)/4)*65+35)
    return nodes,positions,height


def references(s, anchor):
    if not anchor:
        return []
    if anchor.startswith('finding-'):
        return next(f['evidence_ids'] for f in s['findings'] if anchor==f"finding-{f['id']}")
    if anchor.startswith('relationship-'):
        return next(e['evidence_ids'] for e in s['relationships'] if anchor==f"relationship-{e['support_ids'][0]}")
    if anchor.startswith('entity-'):
        return next(n['evidence_ids'] for n in s['entities'] if anchor==f"entity-{n['id']}")
    return []


def pdf_label_lines(value):
    """Measured, deterministic display wrapping; never changes entity data."""
    from reportlab.pdfbase.pdfmetrics import stringWidth
    remaining=str(value).encode('cp1252',errors='backslashreplace').decode('cp1252')
    lines=[]
    while remaining and len(lines)<3:
        length=0
        for char in remaining:
            if stringWidth(remaining[:length+1],"Helvetica",8)>108:
                break
            length+=1
        if length==len(remaining):
            lines.append(remaining);break
        # Prefer DNS/path boundaries without discarding punctuation or characters.
        boundary=max(remaining.rfind(mark,0,length)+1 for mark in ('.','/','-',' '))
        if boundary>=length//2:length=boundary
        if len(lines)==2:
            # Exceptional long values remain fully available in the entity index.
            while stringWidth(remaining[:length]+"...","Helvetica",8)>108:length-=1
            lines.append(remaining[:length]+"...");break
        lines.append(remaining[:length]);remaining=remaining[length:]
    return lines


def html_report(s):
    esc=lambda v:html.escape(str(v),quote=True)
    nodes,positions,height=diagram(s)
    svg=[f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 480 {height}" role="img" aria-label="Stored relationship schematic">']
    for e in s["relationships"]:
        if e["from"] in positions and e["to"] in positions:
            a,b=positions[e["from"]],positions[e["to"]];svg.append(f'<line x1="{a[0]}" y1="{a[1]}" x2="{b[0]}" y2="{b[1]}" stroke="#bdcbd5"'+(' stroke-dasharray="4 3"' if e["classification"]=="derived" else '')+'/>')
    for n in nodes:
        x,y=positions[n["id"]];svg.append(f'<a href="#entity-{n["id"]}"><circle cx="{x}" cy="{y}" r="7" fill="#287d80"/><rect x="{x-56}" y="{y+9}" width="112" height="29" fill="white"/><text x="{x}" y="{y+20}" text-anchor="middle" font-size="9">{esc(n["value"][:18])}</text><text x="{x}" y="{y+33}" text-anchor="middle" font-size="8">#{n["id"]} {esc(n["type"])}</text></a>')
    svg.append('</svg>')
    logo=base64.b64encode(BRAND_LOGO.read_bytes()).decode('ascii')
    body=[f'<div class="report-brand"><img src="data:image/png;base64,{logo}" width="48" alt=""><span>SPECTRE</span></div><h1>SPECTRE investigation report</h1><p>Report v{VERSION} · Case #{s["case"]["id"]}</p><p class="digest">Snapshot SHA-256: {s["snapshot_sha256"]}</p>']
    for title,rows in sections(s):
        body.append(f'<section><h2>{esc(title)}</h2>')
        if title=="Discovered infrastructure":body.append('<h3>Stored entity graph snapshot</h3>'+''.join(svg)+'<p>Solid: observed. Dashed: derived. Complete nodes/relationships are indexed below.</p>')
        if not rows:body.append('<p>No stored records in this section. Absence of data is not a confirmed negative finding.</p>')
        for anchor,text in rows:
            # Only validated evidence IDs create navigation; all data remains escaped text.
            refs=[f'<a href="#evidence-{i}">Evidence #{i}</a>' for i in references(s,anchor)]
            body.append(f'<article{(" id="+chr(34)+anchor+chr(34)) if anchor else ""}><p>{esc(text).replace(chr(10),"<br>")}</p>{" · ".join(refs)}</article>')
        body.append('</section>')
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8"><title>SPECTRE case report</title><style>body{font:15px/1.65 Arial,sans-serif;color:#152b3b;max-width:1050px;margin:48px auto;padding:0 28px}.report-brand{display:flex;align-items:center;gap:12px;font-weight:bold;letter-spacing:.12em}.report-brand img{height:auto;background:#111b28;padding:4px}h1{font-size:30px}h2{border-bottom:2px solid #287d80;margin-top:36px;padding-bottom:8px}article{border-bottom:1px solid #dce4eb;padding:8px 0;overflow-wrap:anywhere}a{color:#206c76}svg{width:100%;max-width:680px}p.digest{font:12px monospace;overflow-wrap:anywhere}@media print{body{margin:0}article{break-inside:avoid}h2{break-after:avoid}}</style></head><body>'+''.join(body)+'</body></html>').encode('utf-8')


def pdf_report(s):
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,KeepTogether,Image
    from reportlab.graphics.shapes import Drawing,Line,Circle,String,Rect
    from reportlab.pdfgen import canvas
    output=BytesIO();styles=getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportBody",fontName="Helvetica",fontSize=9,leading=13,spaceAfter=8,splitLongWords=True))
    styles['Heading1'].keepWithNext=True
    def para(text,style="ReportBody",anchor=None):
        # Built-in portable fonts: preserve unsupported characters as Unicode escapes.
        text=str(text).encode('cp1252',errors='backslashreplace').decode('cp1252')
        markup=html.escape(text,quote=True).replace('\n','<br/>')
        if anchor:markup=f'<a name="{anchor}"/>'+markup
        if anchor and anchor.startswith('finding-'):
            first,separator,rest=markup.partition('<br/>');markup='<b>'+first+'</b>'+separator+rest
        return Paragraph(markup,styles[style])
    logo=Image(str(BRAND_LOGO),width=38,height=38*121/128);logo.hAlign='LEFT'
    story=[KeepTogether([logo,Spacer(1,6),para('SPECTRE investigation report','Title')]),para(f"Case #{s['case']['id']} | Report v{VERSION}"),para('Snapshot SHA-256: '+s['snapshot_sha256']),Spacer(1,10)]
    for title,rows in sections(s):
        heading=para(title,'Heading1')
        if title=="Discovered infrastructure":
            nodes,pos,height=diagram(s);d=Drawing(480,height)
            for e in s['relationships']:
                if e['from'] in pos and e['to'] in pos:
                    a,b=pos[e['from']],pos[e['to']];d.add(Line(a[0],height-a[1],b[0],height-b[1],strokeColor=colors.HexColor('#bdcbd5'),strokeDashArray=[4,3] if e['classification']=='derived' else None))
            for n in nodes:
                x,y=pos[n['id']];y=height-y
                lines=pdf_label_lines(n['value'])
                label_bottom=23+10*len(lines)
                d.add(Circle(x,y,7,fillColor=colors.HexColor('#287d80'),strokeColor=None))
                d.add(Rect(x-56,y-label_bottom-5,112,label_bottom-4,fillColor=colors.white,strokeColor=None))
                for index,line in enumerate(lines):
                    d.add(String(x,y-20-index*10,line,fontName='Helvetica',fontSize=8,textAnchor='middle'))
                d.add(String(x,y-label_bottom,f"#{n['id']} {n['type']}",fontSize=7,textAnchor='middle'))
            d.scale(.95,.95);d.width*=.95;d.height*=.95;story.append(KeepTogether([heading,d,para('Stored non-certificate schematic. Solid: observed; dashed: derived. Full indexes follow.')]));heading=None
        if not rows:
            empty=[para('No stored records. Missing intelligence is not proof of absence.')]
            if heading:empty.insert(0,heading)
            story.append(KeepTogether(empty))
        for anchor,text in rows:
            record=[para(text,anchor=anchor)]
            if heading:record.insert(0,heading);heading=None
            refs=references(s,anchor)
            if refs:
                record.append(Paragraph(' | '.join(f'<link href="#evidence-{i}">Evidence #{i}</link>' for i in refs),styles['ReportBody']))
            story.append(KeepTogether(record))
    def footer(c,doc):
        c.saveState();c.setFont('Helvetica',8);c.setFillColor(colors.HexColor('#516575'));c.drawString(42,25,f"SPECTRE | Case #{s['case']['id']} | Stored evidence report");c.drawRightString(A4[0]-42,25,str(doc.page));c.restoreState()
    def deterministic_canvas(*args,**kwargs):
        kwargs['invariant']=1;return canvas.Canvas(*args,**kwargs)
    doc=SimpleDocTemplate(output,pagesize=A4,rightMargin=42,leftMargin=42,topMargin=42,bottomMargin=42,title='SPECTRE case report',author='SPECTRE')
    doc.build(story,onFirstPage=footer,onLaterPages=footer,canvasmaker=deterministic_canvas)
    return output.getvalue()
