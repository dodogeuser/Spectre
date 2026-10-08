"use strict";
(() => {
  const el=id=>document.getElementById(id),shell=el("workspace");
  let active="graph",generation=0,graph=null,timeline=null,targets=[],findings=[],registry=[],runs=[],targetBounded=false,findingBounded=false;
  let poll=null,pollBusy=false,evidenceOffset=0,evidenceRequest=0,collectorRequest=0,collectorLoaded=false;
  let collectorBounded=true,activityTimeline=null;
  let collectorTarget=null;
  const evidenceCache=new Map(),hashCache=new Map(),integrityCells=new Map();
  const valid=(id,token)=>selectedCase&&selectedCase.id===id&&generation===token;
  const text=(parent,value,tag="p",className="")=>{const node=document.createElement(tag);node.textContent=value;node.className=className;parent.append(node);return node;};
  const button=(parent,label,handler)=>{const node=document.createElement("button");node.type="button";node.textContent=label;node.onclick=()=>Promise.resolve(handler()).catch(showError);parent.append(node);return node;};
  const lower=(value,bounded)=>`${value}${bounded?"+":""}`;
  function setInspector(open){shell.dataset.inspector=open?"open":"closed";el("inspector-shell").hidden=!open;el("inspector-open").hidden=open||!selectedCase;el("inspector-toggle").setAttribute("aria-expanded",String(open));window.resizeInvestigation?.();}
  window.consoleInspector=setInspector;
  function navigate(name,options={}){
    if(!selectedCase)return;
    if(!document.querySelector(`[data-pane="${name}"]`))return;
    active=name;
    for(const pane of document.querySelectorAll("[data-pane]"))pane.hidden=pane.dataset.pane!==name;
    for(const nav of document.querySelectorAll("[data-nav]"))nav.setAttribute("aria-current",nav.dataset.nav===name?"page":"false");
    setInspector(false);
    if(name==="graph")window.resizeInvestigation?.();
    if(name==="findings")el("findings-load").onclick();
    if(name==="evidence")loadEvidence().catch(showError);
    if(name==="collectors"&&!collectorLoaded)loadCollectors().catch(showError);
    if(name==="timeline"&&graph)window.refreshStoredTimeline?.().catch(showError);
    if(name==="reports")window.openReports?.();
    if(name==="active"&&!options.preparedVerification)window.openActive?.().catch(showError);
    el("message").textContent="";
    if(window.matchMedia?.("(max-width: 680px)").matches){shell.dataset.sidebar="collapsed";el("sidebar-toggle").setAttribute("aria-expanded","false");}
  }
  window.consoleNavigate=navigate;
  for(const nav of document.querySelectorAll("[data-nav]"))nav.onclick=()=>navigate(nav.dataset.nav);
  for(const node of document.querySelectorAll("[data-go]"))node.onclick=()=>navigate(node.dataset.go);
  function library(){el("case-library").showModal();}
  el("case-picker-open").onclick=library;el("choose-case").onclick=library;el("case-picker-close").onclick=()=>el("case-library").close();
  el("sidebar-toggle").onclick=()=>{const collapsed=shell.dataset.sidebar!=="collapsed";shell.dataset.sidebar=collapsed?"collapsed":"expanded";el("sidebar-toggle").setAttribute("aria-expanded",String(!collapsed));window.resizeInvestigation?.();};
  el("inspector-toggle").onclick=()=>setInspector(false);el("inspector-open").onclick=()=>setInspector(true);el("inspector-timeline").onclick=()=>navigate("timeline");
  el("activity-toggle").onclick=()=>{el("activity-expanded").hidden=!el("activity-expanded").hidden;el("activity-toggle").setAttribute("aria-expanded",String(!el("activity-expanded").hidden));};
  window.consoleHealth=online=>{el("local-indicator").textContent=online?"● LOCAL":"○ OFFLINE";el("local-indicator").dataset.state=online?"online":"offline";};
  window.consoleWorkspace=()=>{el("auth-panel").hidden=true;setInspector(false);if(window.matchMedia?.("(max-width: 680px)").matches)shell.dataset.sidebar="collapsed";library();};
  window.consoleCaseChanging=id=>{
    window.resetReports?.();
    window.resetActive?.();
    ++generation;++evidenceRequest;++collectorRequest;if(poll)clearInterval(poll);poll=null;pollBusy=false;
    if(selectedCase?.id!==id)active="graph";
    graph=null;timeline=null;activityTimeline=null;targets=[];findings=[];registry=[];runs=[];collectorTarget=null;collectorLoaded=false;collectorBounded=true;targetBounded=false;findingBounded=false;evidenceOffset=0;
    evidenceCache.clear();hashCache.clear();integrityCells.clear();
    el("case-detail").hidden=true;el("current-case").textContent="Loading authorized case…";el("activity-feed").textContent="Loading stored records…";
    el("collector-runs").replaceChildren();el("evidence-list").replaceChildren();el("activity-expanded").replaceChildren();el("activity-expanded").hidden=true;
    for(const nav of document.querySelectorAll("[data-nav]"))el(`nav-${nav.dataset.nav}-count`).textContent="";
  };
  window.consoleTargets=(rows,offset)=>{window.updateInvestigationTargets?.(rows,offset);if(offset!==0)return;targets=rows;targetBounded=rows.length===100;updateMetrics();renderCollectorTargets();};
  window.consoleCaseReady=async()=>{
    const id=selectedCase.id,token=generation;el("case-library").close();el("no-case").hidden=true;el("current-case").textContent=`Case: ${selectedCase.title} · #${id}`;
    navigate(active);
    const results=await Promise.allSettled([api(`/api/cases/${id}/findings`),api(`/api/cases/${id}/collectors`)]);
    if(!valid(id,token))return;
    if(results[0].status==="fulfilled"){findings=results[0].value.findings;findingBounded=results[0].value.has_more;}else showError(results[0].reason);
    if(results[1].status==="fulfilled"){registry=results[1].value;renderRegistry();}else showError(results[1].reason);
    await el("graph-load").onclick();if(!valid(id,token))return;updateMetrics();
    poll=setInterval(()=>refreshSnapshot().catch(()=>{}),12000);
  };
  async function refreshSnapshot(){
    if(!selectedCase||!graph||pollBusy||document.hidden||active!=="graph")return;
    const id=selectedCase.id,token=generation;pollBusy=true;
    try{const next=await api(`/api/cases/${id}/investigation`);if(!valid(id,token))return;
      window.updateInvestigationSnapshot(next);await window.refreshStoredTimeline();
    }catch(error){if(valid(id,token))el("graph-message").textContent="Stored graph refresh unavailable. Last authorized snapshot retained.";}
    finally{if(valid(id,token))pollBusy=false;}
  }
  window.onInvestigationData=(next)=>{graph=next;for(const row of graph.evidence)evidenceCache.set(row.id,row);updateMetrics();};
  window.onStoredTimeline=result=>{if(result.offset===0||!timeline){if(JSON.stringify(timeline)===JSON.stringify(result))return;timeline=result;activityTimeline=result;updateMetrics();renderActivity();if(result.has_more){const id=selectedCase.id,token=generation;api(`/api/cases/${id}/timeline?offset=${Math.max(0,result.bounded_total-8)}&limit=8`).then(tail=>{if(valid(id,token)){activityTimeline=tail;renderActivity();}}).catch(()=>{});}}};
  window.findingsForEntity=id=>findings.filter(finding=>finding.entity_id===id);
  window.evidenceProvenance=id=>evidenceCache.get(id);
  function updateMetrics(){
    const evidenceCount=timeline?new Set(timeline.events.filter(event=>event.type==="evidence.captured").flatMap(event=>event.evidence_ids)).size:null;
    const knownRuns=new Set([...(timeline?.events||[]).flatMap(event=>event.run_ids),...runs.map(run=>run.id)]).size;
    const stats=[["Targets",lower(targets.length,targetBounded)],["Entities",graph?lower(graph.entities.length,graph.truncated):"—"],["Relationships",graph?lower(graph.relationships.length,graph.truncated):"—"],["Evidence",evidenceCount===null?"—":lower(evidenceCount,timeline.truncated||timeline.has_more)],["Findings",lower(findings.length,findingBounded)],["Known collector runs",lower(knownRuns,collectorBounded)]];
    el("overview-stats").replaceChildren();for(const [name,count]of stats){const card=document.createElement("div");card.className="stat-card";text(card,name,"span");text(card,count,"strong");el("overview-stats").append(card);}
    for(const [name,value]of [["targets",stats[0][1]],["evidence",stats[3][1]],["findings",stats[4][1]]])el(`nav-${name}-count`).textContent=value==="0"?"":value;
    el("scope-summary").replaceChildren();for(const scope of ["passive_allowed","active_authorized","excluded"]){const row=document.createElement("div");row.className="scope-row";text(row,scope.replaceAll("_"," "),"span");text(row,lower(targets.filter(target=>target.scope_status===scope).length,targetBounded),"strong");el("scope-summary").append(row);}
    text(el("scope-summary"),`${targets.filter(target=>target.archived).length} archived targets in loaded page. Active-authorized scope does not enable active assessment.`,"p","muted");
    el("overview-limits").textContent="A + means at least this many records are available in the loaded pages. Evidence counts come from captured records in the timeline; collector totals become more complete when you open Collectors.";
    if(el("overview-primary")){const primary=el("overview-primary"),hasTargets=targets.some(t=>!t.archived),hasIntelligence=(graph?.entities.length||0)>0||(timeline?.events.length||0)>0;primary.textContent=!hasTargets?"Add a target":hasIntelligence?"Open graph":"Begin investigation";primary.onclick=()=>navigate(!hasTargets?"targets":hasIntelligence?"graph":"collectors");}
  }
  function eventLabel(event){return event.type==="evidence.captured"?`${event.source.toUpperCase()} evidence captured · Evidence #${event.evidence_ids[0]}`:event.type==="relationship.first_seen"?`Relationship ${event.source} first observed`:event.source;}
  function renderActivity(){
    const events=(activityTimeline?.events||[]).slice(-8).reverse();
    el("activity-feed").textContent=events.length?events.slice(0,3).map(eventLabel).join("  ·  "):"No stored activity in this case.";
    for(const id of ["activity-expanded","overview-activity"]){el(id).replaceChildren();if(!events.length)text(el(id),"No stored activity.");for(const event of events.slice(0,id==="overview-activity"?5:8)){const row=document.createElement("div");row.className="recent-event";text(row,event.timestamp+" UTC","time");text(row,eventLabel(event));button(row,"View event / evidence",()=>{navigate("timeline");if(event.evidence_ids.length)return window.inspectStoredEvidence(event.evidence_ids[0]);});el(id).append(row);}}
    if(timeline?.truncated)text(el("activity-expanded"),"Timeline is bounded; more stored events may exist.","p","muted");
  }
  const collectorLabels={dns:["DNS records","Read public DNS records for a domain."],rdap:["Domain registration","Read public registration records."],ct:["Certificate transparency","Read publicly logged certificates."],reverse_dns:["Reverse DNS","Read public reverse-DNS records."],ip_rdap:["IP registration","Read address allocation records."],ip_asn:["IP / ASN enrichment","Read public network and ASN attribution."],web_metadata:["Web metadata","Capture one public HTTPS page and its headers."],mock:["Offline framework test","Synthetic test only; no intelligence is collected."]};
  const providerName=name=>collectorLabels[name]?.[0]||name.replaceAll("_"," ");
  window.openStoredCollectorControls=async target=>{
    collectorTarget=target;renderRegistry();navigate("collectors");
    if(target.type==="domain")await openDomain(target);else if(target.type==="url")await openWeb(target);else if(["ipv4","ipv6"].includes(target.type))await openIP(target);
    else el("collector-message").textContent="No real collection controls are available for this target type.";
  };
  function renderRegistry(){
    el("collector-registry").replaceChildren();
    for(const provider of registry){
      const card=document.createElement("div");card.className="registry-card";
      const applicable=collectorTarget&&(provider.supported_types||[]).includes(collectorTarget.type);
      const blocked=collectorTarget&&(collectorTarget.archived||collectorTarget.scope_status==="excluded");
      const state=!collectorTarget?"Select a target":!applicable?"Not applicable":!provider.enabled?"Unavailable":blocked?"Scope blocked":"Applicable";
      const latest=runs.find(run=>run.target_id===collectorTarget?.id&&run.collector===provider.name);
      text(card,providerName(provider.name),"h4");text(card,collectorLabels[provider.name]?.[1]||"Registered collector. Review its controls before collection.");
      text(card,state,"strong","collector-compatibility");
      if(latest)text(card,`Last run: ${latest.status} · #${latest.id}`);
      text(card,`Version ${provider.version} · Target types: ${(provider.supported_types||[]).join(", ")||"Not supplied"}`,"small");
      const open=button(card,"Open controls",()=>window.openStoredCollectorControls(collectorTarget));
      open.disabled=!collectorTarget||!applicable||!provider.enabled||blocked||!["domain","url","ipv4","ipv6"].includes(collectorTarget.type)||provider.name==="mock";
      el("collector-registry").append(card);
    }
  }
  function renderCollectorTargets(){el("collector-targets").replaceChildren();for(const target of targets){if(target.archived)continue;button(el("collector-targets"),`${target.normalized_value} · ${target.type}`,()=>window.openStoredCollectorControls(target));}if(!targets.some(t=>!t.archived)){text(el("collector-targets"),"Add a target to choose collection controls.");button(el("collector-targets"),"Add a target",()=>navigate("targets"));}}
  async function loadCollectors(){
    const id=selectedCase.id,token=generation,request=++collectorRequest;el("collector-message").textContent="Reading stored run states…";
    const batches=await Promise.allSettled(targets.slice(0,20).map(target=>api(`/api/cases/${id}/targets/${target.id}/runs`)));
    if(!valid(id,token)||request!==collectorRequest)return;runs=[];let failures=0;
    for(let i=0;i<batches.length;i++){const result=batches[i];if(result.status!=="fulfilled"){failures++;continue;}for(const run of result.value)runs.push({...run,page_bounded:result.value.length===100,target_value:targets[i].normalized_value});}
    runs.sort((a,b)=>b.id-a.id);collectorLoaded=true;collectorBounded=failures>0||targetBounded||targets.length>20||runs.some(run=>run.page_bounded);el("collector-runs").replaceChildren();
    for(const run of runs.slice(0,100)){const row=document.createElement("div");row.className="run-card";text(row,run.collector.replaceAll("_"," "),"strong");text(row,`Run #${run.id} · ${run.target_value} · ${run.started_at} UTC${run.error_code?" · "+run.error_code:""}`,"span");text(row,run.status,"span","run-state");if(run.warnings_json?.length)text(row,run.warnings_json.join("; "),"small");el("collector-runs").append(row);}
    if(!runs.length)text(el("collector-runs"),"No stored runs yet. Select a target above to review collection controls.");
    el("collector-message").textContent=`Latest collection activity for ${Math.min(targets.length,20)} targets. Opening controls never starts collection. ${failures?`${failures} target activity views unavailable.`:""}`;renderRegistry();updateMetrics();
  }
  async function loadEvidence(){
    const id=selectedCase.id,token=generation,request=++evidenceRequest;
    const result=await api(`/api/cases/${id}/timeline?offset=${evidenceOffset}`);if(!valid(id,token)||request!==evidenceRequest)return;
    const events=result.events.filter(event=>event.type==="evidence.captured"), runIds=[...new Set(events.flatMap(event=>event.run_ids))];
    const missing=runIds.filter(runId=>events.some(event=>event.run_ids.includes(runId)&&!evidenceCache.get(event.evidence_ids[0])?.target_id));
    const batches=await Promise.allSettled(missing.map(runId=>api(`/api/cases/${id}/runs/${runId}/evidence`)));
    if(!valid(id,token)||request!==evidenceRequest)return;
    batches.forEach(result=>{if(result.status==="fulfilled")for(const item of result.value)evidenceCache.set(item.id,{...evidenceCache.get(item.id),...item});});
    el("evidence-list").replaceChildren();integrityCells.clear();
    for(const event of events){const evidenceId=event.evidence_ids[0],item=evidenceCache.get(evidenceId)||{},row=document.createElement("tr");text(row,`#${evidenceId}`,"td");const type=text(row,item.source_type||event.source,"td");text(type,item.collector?`${item.collector} ${item.version}`:"Run #"+event.run_ids[0],"small");const source=text(row,item.source_ref||event.source_ref,"td");if(item.target_id)text(source,`Target #${item.target_id}`,"small");text(row,event.timestamp,"td");integrityCells.set(evidenceId,text(row,hashCache.get(evidenceId)||"Stored hash · not checked","td"));const cell=document.createElement("td");button(cell,"Inspect",()=>window.inspectStoredEvidence(evidenceId));row.append(cell);el("evidence-list").append(row);}
    el("evidence-message").textContent=events.length?"Inspect a record to see its source, collector, timestamps and evidence hash.":result.bounded_total===0?"No evidence captured yet. Review targets and open Collectors to begin an authorized investigation.":"No evidence captures on this page. Use Previous or Next to browse other events.";
    el("evidence-previous").disabled=evidenceOffset===0;el("evidence-next").disabled=!result.has_more;
  }
  function canonical(value){if(Array.isArray(value))return"["+value.map(canonical).join(",")+"]";if(value&&typeof value==="object")return"{"+Object.keys(value).sort((a,b)=>{const x=Array.from(a,c=>c.codePointAt(0)),y=Array.from(b,c=>c.codePointAt(0));for(let i=0;i<Math.min(x.length,y.length);i++)if(x[i]!==y[i])return x[i]-y[i];return x.length-y.length;}).map(key=>JSON.stringify(key)+":"+canonical(value[key])).join(",")+"}";return JSON.stringify(value);}
  window.verifyStoredEvidence=async item=>{
    const id=selectedCase.id,token=generation;if(!window.crypto?.subtle)return"Hash verification unavailable in this browser. Stored SHA-256 remains visible.";
    const bytes=new TextEncoder().encode(canonical(item.raw_json)),digest=await window.crypto.subtle.digest("SHA-256",bytes),hash=Array.from(new Uint8Array(digest),byte=>byte.toString(16).padStart(2,"0")).join("");
    if(!valid(id,token))return"Case changed; verification result discarded.";
    const result=hash===item.sha256?"Verified · raw SHA-256 matches":"Browser hash differs · verify Python canonicalization before assuming corruption";hashCache.set(item.id,result);const cell=integrityCells.get(item.id);if(cell){cell.textContent=result;cell.className=hash===item.sha256?"integrity-ok":"";}return result;
  };
  el("evidence-refresh").onclick=()=>loadEvidence().catch(showError);el("evidence-previous").onclick=()=>{evidenceOffset=Math.max(0,evidenceOffset-100);loadEvidence().catch(showError);};el("evidence-next").onclick=()=>{evidenceOffset+=100;loadEvidence().catch(showError);};el("collectors-refresh").onclick=()=>loadCollectors().catch(showError);
  // Existing health probe is authoritative; future checks run at a low frequency.
  if(el("health").textContent==="Local server is online.")window.consoleHealth(true);
  else if(/unavailable|failed/.test(el("health").textContent))window.consoleHealth(false);
  setInterval(()=>{if(!document.hidden)checkHealth();},30000);
})();
