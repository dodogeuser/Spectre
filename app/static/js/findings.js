"use strict";
(() => {
  let generation=0,inspection=0,offset=0,after=0,busy=false;
  const el=id=>document.getElementById(id);
  const text=(parent,value,tag="p")=>{const node=document.createElement(tag);node.textContent=value;parent.append(node);return node;};
  const valid=(id,token)=>selectedCase&&selectedCase.id===id&&generation===token;
  const button=(parent,label,action)=>{const node=document.createElement("button");node.type="button";node.textContent=label;node.onclick=()=>Promise.resolve().then(action).catch(showError);parent.append(node);return node;};
  function controls(){el("findings-generate").disabled=busy||!selectedCase||user.role==="viewer"||selectedCase.status==="archived";}
  window.configureFindings=controls;
  window.inspectStoredFinding=async id=>{if(window.consoleNavigate)window.consoleNavigate("findings");await inspect(id);};
  window.resetFindings=()=>{++generation;++inspection;offset=0;after=0;el("findings-controls").hidden=true;el("findings-list").replaceChildren();el("finding-detail").replaceChildren();el("finding-evidence").replaceChildren();el("findings-message").textContent="";el("findings-status").value="";el("findings-severity").value="";};
  async function load(){
    const id=selectedCase.id,token=generation;
    const query=new URLSearchParams({offset:String(offset)});
    if(el("findings-status").value)query.set("status",el("findings-status").value);
    if(el("findings-severity").value)query.set("severity",el("findings-severity").value);
    const result=await api(`/api/cases/${id}/findings?${query}`);
    if(!valid(id,token))return;
    el("findings-controls").hidden=false;el("findings-list").replaceChildren();
    if(!result.findings.length)text(el("findings-list"),"No stored findings match this view. Review evidence or adjust filters. No findings does not establish that a target is safe.");
    for(const item of result.findings){
      const card=document.createElement("article");
      const badges=document.createElement("div");badges.className="finding-badges";
      text(badges,`Severity · ${item.severity}`,"span").className=`severity-${item.severity}`;
      text(badges,`Confidence · ${Math.round(item.confidence*100)}%`,"span");card.append(badges);
      text(card,`Finding #${item.id}: ${item.title}`,"h4");
      text(card,item.description);
      if(item.generated_json.affected_url)text(card,`Target #${item.target_id} · ${item.generated_json.affected_url}`);
      text(card,`Severity: ${item.severity}${item.severity_override?" (analyst override)":" (rule)"} · Confidence: ${Math.round(item.confidence*100)}% for the observation · Status: ${item.status}`);
      text(card,`Rule: ${item.rule_id} v${item.rule_version} · ${item.generated_json.rule_state}`);
      button(card,"Why this finding / evidence",()=>inspect(item.id));
      for(const evidenceId of item.generated_json.evidence_ids||[])button(card,`Evidence #${evidenceId}`,()=>evidence(evidenceId));
      el("findings-list").append(card);
    }
    el("findings-previous").disabled=offset===0;el("findings-next").disabled=!result.has_more;controls();
  }
  async function evidence(evidenceId){
    const id=selectedCase.id,token=generation,request=++inspection;
    const item=await api(`/api/cases/${id}/evidence/${evidenceId}`);
    if(!valid(id,token)||inspection!==request)return;
    const panel=el("finding-evidence");panel.replaceChildren();
    text(panel,`Evidence #${item.id} · run #${item.run_id} · captured ${item.captured_at} UTC`,"h4");
    text(panel,`Source: ${item.source_type} · ${item.source_ref} · SHA-256: ${item.sha256}`);
    text(panel,JSON.stringify({parsed:item.parsed_json,raw:item.raw_json},null,2),"pre");
    panel.scrollIntoView?.({block:"start",behavior:"auto"});
  }
  async function inspect(findingId,evidenceOffset=0){
    const id=selectedCase.id,token=generation,request=++inspection;
    const item=await api(`/api/cases/${id}/findings/${findingId}?offset=${evidenceOffset}`);
    if(!valid(id,token)||inspection!==request)return;
    const panel=el("finding-detail");panel.replaceChildren();el("finding-evidence").replaceChildren();
    panel.scrollIntoView?.({block:"start",behavior:"auto"});
    text(panel,`Finding #${item.id}: ${item.title}`,"h4");text(panel,item.description);
    text(panel,`Severity: ${item.severity} · Confidence: ${Math.round(item.confidence*100)}% recorded-observation support strength (not a calibrated probability). Rule priority: ${item.generated_json.priority}`);
    text(panel,`Rule ${item.rule_id} v${item.rule_version} · Type ${item.finding_type} · Rule state ${item.generated_json.rule_state} · Latest assessment ${item.generated_json.assessment_state}`);
    if(item.generated_json.assessment_reason)text(panel,item.generated_json.assessment_reason);
    text(panel,`Affected captured URL: ${item.generated_json.affected_url} · Target #${item.target_id} (${item.target.scope_status}${item.target.archived?", archived":""})`);
    text(panel,`Created ${item.created_at} UTC · Updated ${item.updated_at} UTC`);
    text(panel,"Why this finding / rubric","h4");for(const reason of item.generated_json.why)text(panel,reason);
    if(item.generated_json.recency)text(panel,`Recency: ${item.generated_json.recency.category}, ${item.generated_json.recency.age_days} days relative to stored case capture ${item.generated_json.recency.reference_captured_at} UTC.`);
    for(const v of item.verifications||[]){text(panel,`Active verification #${v.id}: ${v.state} · ${v.reason}`);if(v.evidence_id)button(panel,`Verification evidence #${v.evidence_id}`,()=>evidence(v.evidence_id));}
    if(user.role!=="viewer"&&item.rule_id.startsWith("web.missing_header.")){
      text(panel,"Prepares the Active / Validation form without contacting the target. Confirm authority again and explicitly execute the request there.");
      button(panel,"Prepare authorized verification",()=>{
        if(typeof window.openActiveVerification!=="function")throw Error("Verification controls are unavailable. Reload SPECTRE and reopen this finding; no request was sent.");
        return window.openActiveVerification(item);
      });
    }
    text(panel,"Original rule result (preserved)","h4");text(panel,JSON.stringify(item.original_json,null,2),"pre");
    if(item.severity_override)text(panel,`Analyst severity override: ${item.severity_override} · Reason: ${item.override_reason}. The original severity/confidence remains unchanged.`);
    if(item.entity_id!==null)button(panel,`Inspect affected entity #${item.entity_id}`,()=>window.inspectStoredEntity(item.entity_id));
    text(panel,"Supporting and assessment evidence","h4");
    for(const evidenceId of item.generated_json.evidence_ids||[])button(panel,`Inspect current supporting evidence #${evidenceId}`,()=>evidence(evidenceId));
    if(item.generated_json.assessment_evidence_id&&!item.generated_json.evidence_ids.includes(item.generated_json.assessment_evidence_id))button(panel,`Inspect latest assessment evidence #${item.generated_json.assessment_evidence_id}`,()=>evidence(item.generated_json.assessment_evidence_id));
    for(const row of item.evidence){text(panel,`Evidence #${row.id} · ${row.source_type} · captured ${row.captured_at} UTC · ${row.active_support?"historical/active header support":"retained history"}${row.assessment_support?" / latest assessment":""}`);button(panel,`Inspect evidence #${row.id}`,()=>evidence(row.id));}
    if(evidenceOffset>0)button(panel,"Previous evidence",()=>inspect(findingId,Math.max(0,evidenceOffset-100)));
    if(item.evidence_has_more)button(panel,"Next evidence",()=>inspect(findingId,evidenceOffset+100));
    for(const rel of item.relationships){text(panel,`Relationship support #${rel.id}: ${rel.from} → ${rel.type} → ${rel.to} · contextual redirect support, not a vulnerability claim · evidence #${rel.evidence_id}`);button(panel,`Inspect relationship evidence #${rel.evidence_id}`,()=>evidence(rel.evidence_id));}
    text(panel,"Recent revision history (latest 50)","h4");
    for(const rev of item.revisions)text(panel,`${rev.created_at} UTC · ${rev.change_type} · actor #${rev.actor_id} · status ${rev.snapshot.status} · override ${rev.snapshot.severity_override||"none"} · reason ${rev.snapshot.override_reason||"none"}`);
    if(user.role!=="viewer"&&selectedCase.status!=="archived"){
      const form=document.createElement("form");
      const select=(label,values,current)=>{const wrap=text(form,label,"label"),input=document.createElement("select");for(const value of values){const opt=document.createElement("option");opt.value=value;opt.textContent=value||"Use rule severity";input.append(opt);}input.value=current;wrap.append(input);return input;};
      const status=select("Analyst status",["open","accepted","false_positive","informational","resolved"],item.status);
      const severity=select("Manual severity (confidence stays unchanged)",["","informational","low","medium","high","critical"],item.severity_override||"");
      const notesLabel=text(form,"Analyst notes","label"),notes=document.createElement("textarea");notes.maxLength=10000;notes.value=item.notes;notesLabel.append(notes);
      const reasonLabel=text(form,"Required reason for severity change or reset","label"),reason=document.createElement("textarea");reason.maxLength=2000;reasonLabel.append(reason);
      const save=document.createElement("button");save.textContent="Save analyst review";form.append(save);
      form.onsubmit=async event=>{
        event.preventDefault();save.disabled=true;
        try{
          const body={status:status.value,notes:notes.value};
          if(severity.value!==(item.severity_override||"")){body.severity_override=severity.value||null;body.override_reason=reason.value;}
          await api(`/api/cases/${id}/findings/${item.id}`,"PATCH",body);
          if(valid(id,token)){await load();await inspect(item.id);await refreshAudit(id,token);}
        }catch(error){showError(error);}finally{save.disabled=false;}
      };panel.append(form);
    }
  }
  async function refreshAudit(id,token){const rows=await api(`/api/cases/${id}/audit`);if(!valid(id,token))return;el("audit").replaceChildren();for(const row of rows)text(el("audit"),`${row.timestamp} · ${row.action} · actor ${row.actor_id}`,"li");}
  el("findings-load").onclick=()=>load().catch(showError);
  el("findings-generate").onclick=async()=>{
    if(busy||!selectedCase)return;
    const id=selectedCase.id,token=generation;busy=true;controls();
    try{
      const result=await api(`/api/cases/${id}/findings/generate?after=${after}`,"POST");
      if(!valid(id,token))return;
      after=result.has_more?result.next_after:0;
      el("findings-message").textContent=`Created ${result.created}, updated ${result.updated}, unchanged ${result.unchanged}. ${result.skipped.length} targets skipped. ${result.has_more?"Click Generate again to continue the bounded batch.":"No collection performed."}`;
      await load();await refreshAudit(id,token);
    }catch(error){showError(error);}finally{busy=false;controls();}
  };
  el("findings-filter").onclick=()=>{offset=0;load().catch(showError);};
  el("findings-previous").onclick=()=>{offset=Math.max(0,offset-100);load().catch(showError);};
  el("findings-next").onclick=()=>{offset+=100;load().catch(showError);};
})();
