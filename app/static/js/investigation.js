
"use strict";
// All visual entities/edges originate from stored case snapshots.
function storedGraphSelection(data, options = {}) {
  const confidence = Number(options.confidence || 0), source = options.source || "", type = options.type || "";
  const edges = data.relationships.filter(e => e.confidence >= confidence && (!source || (e.sources || []).includes(source)));
  const endpoints = new Set(edges.flatMap(e => [e.from, e.to]));
  const nodes = data.entities.filter(n => (!type || n.type === type || (n.roles || []).includes(type)) && (!source || endpoints.has(n.id) || (n.sources || []).includes(source)));
  const ids = new Set(nodes.map(n => n.id));
  return {nodes, edges: edges.filter(e => ids.has(e.from) && ids.has(e.to))};
}
function storedEdgeKey(edge) {return `e:${edge.from}:${edge.to}:${edge.type}`;}
// Target markers are presentation only: never entities, evidence or edge endpoints.
function storedTargetRoots(targets, entities) {
  const types={ipv4:"ip",ipv6:"ip"};
  return targets.filter(t=>!t.archived).map(target=>({target,entity:entities.find(n=>n.type===(types[target.type]||target.type)&&n.value===target.normalized_value)||null}));
}
function storedGraphDelta(previous, next) {
  if (!previous) return {nodes: [], edges: []}; // Initial load/refresh is not discovery.
  const nodes = new Set(previous.entities.map(n => n.id)), edges = new Set(previous.relationships.map(storedEdgeKey));
  return {nodes: next.entities.filter(n => !nodes.has(n.id)).map(n => n.id), edges: next.relationships.filter(e => !edges.has(storedEdgeKey(e))).map(storedEdgeKey)};
}
class GraphPresentationState {
  constructor(storage,userId,caseId) {
    this.storage=storage;this.key=`spectre.graph.v1.u${userId}.c${caseId}`;
    this.value={version:1,nodes:{},viewport:null,certificates:"collapsed",hostnames:"expanded",hiddenTypes:[],edgeLabels:false};
    this.available=Boolean(storage);
    try {const raw=storage?.getItem(this.key);if(raw&&raw.length<=300000)this.restore(JSON.parse(raw));}catch(_){this.available=false;}
  }
  restore(input) {
    if(!input||input.version!==1)return;
    const finite=n=>Number.isFinite(n)&&Math.abs(n)<=1000000;
    for(const [id,node]of Object.entries(input.nodes||{}).slice(0,2000))if(/^[nt]\d+$/.test(id)&&node&&finite(node.x)&&finite(node.y))this.value.nodes[id]={x:node.x,y:node.y,size:Number.isFinite(node.size)?Math.max(24,Math.min(100,node.size)):32};
    const view=input.viewport;if(view&&Number.isFinite(view.zoom)&&view.zoom>=.05&&view.zoom<=4&&finite(view.pan?.x)&&finite(view.pan?.y))this.value.viewport={zoom:view.zoom,pan:{x:view.pan.x,y:view.pan.y}};
    for(const field of ["certificates","hostnames"])if(["collapsed","expanded","hidden"].includes(input[field]))this.value[field]=input[field];
    this.value.hiddenTypes=(Array.isArray(input.hiddenTypes)?input.hiddenTypes:[]).filter(t=>["domain","ip","asn","certificate","organization","url"].includes(t));
    this.value.edgeLabels=input.edgeLabels===true;
  }
  save() {try{const json=JSON.stringify(this.value);if(json.length>300000)return false;if(!this.storage)return false;this.storage.setItem(this.key,json);this.available=true;return true;}catch(_){this.available=false;return false;}}
}
function graphDisplaySelection(data,options,presentation) {
  const selected=storedGraphSelection(data,options);
  const nodes=selected.nodes.filter(n=>!presentation.hiddenTypes.includes(n.type)&&(n.type!=="certificate"||presentation.certificates==="expanded")&&(!(n.roles||[]).includes("subdomain")||presentation.hostnames==="expanded"));
  const ids=new Set(nodes.map(n=>n.id));return {nodes,edges:selected.edges.filter(e=>ids.has(e.from)&&ids.has(e.to))};
}
if (typeof module !== "undefined") module.exports = {storedGraphSelection, storedGraphDelta, storedTargetRoots,GraphPresentationState,graphDisplaySelection};

if (typeof document !== "undefined") (() => {
  let data = null, cy = null, caseId = null, generation = 0, inspection = 0;
  let cap = 200, selected = null, focusedIds = null, timelineOffset = 0, timelineRequest = 0;
  let needsFit = true;
  const timers = new Set(), highlighted = new Map();
  const seenNodes=new Set(),seenEdges=new Set();
  let initialized=false, targetRows=[];
  let presentation=null,applying=false,saveTimer=null;
  const presentationMemory=new Map();
  const el = id => document.getElementById(id);
  const text = (parent, value, tag = "p", className = "") => {const node = document.createElement(tag); node.textContent = value; node.className = className; parent.append(node); return node;};
  const current = (id, token) => selectedCase && selectedCase.id === id && caseId === id && generation === token;
  const reduced = () => typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const action = (parent, label, handler) => {const button = document.createElement("button"); button.type = "button"; button.textContent = label; button.onclick = () => Promise.resolve(handler()).catch(showError); parent.append(button); return button;};
  const typeName = n => n.roles?.includes("subdomain") ? "HOSTNAME" : n.type==="ip"?(n.value.includes(":")?"IPv6":"IPv4"):({domain:"DOMAIN",asn:"ASN",certificate:"CERTIFICATE",organization:"ORGANIZATION",url:"URL"}[n.type] || n.type.toUpperCase());
  const label = n => n.type === "certificate" ? `${n.value.slice(0,10)}…\nCERTIFICATE` : `${n.value.length>26?n.value.slice(0,23)+"…":n.value}\n${typeName(n)}`;
  function loadPresentation() {
    const userId=typeof user!=="undefined"?user?.id:null;let storage=null;
    try{if(userId)storage=window.localStorage;}catch(_){}
    const key=`${userId||"session"}:${caseId}`;presentation=presentationMemory.get(key)||new GraphPresentationState(storage,userId||"session",caseId);presentationMemory.set(key,presentation);
    el("graph-certificates").value=presentation.value.certificates;el("graph-hostnames").value=presentation.value.hostnames;el("graph-edge-labels").checked=presentation.value.edgeLabels;
    for(const type of ["domain","ip","asn","organization","url"])el(`graph-show-${type}`).checked=!presentation.value.hiddenTypes.includes(type);
  }
  function savePresentation() {
    if(!presentation||!cy||applying)return;
    for(const n of cy.nodes()){const p=n.position();if(Number.isFinite(p.x)&&Number.isFinite(p.y))presentation.value.nodes[n.id()]={x:p.x,y:p.y,size:n.data("size")};}
    presentation.value.viewport={zoom:cy.zoom(),pan:{...cy.pan()}};
    if(Object.keys(presentation.value.nodes).length>2000)presentation.value.nodes=Object.fromEntries(Object.entries(presentation.value.nodes).slice(-2000));
    const saved=presentation.save();el("graph-layout-status").textContent=saved?"Layout saved locally":"Layout kept for this session; browser storage unavailable";
  }
  function scheduleSave(){if(applying||!presentation)return;if(saveTimer)clearTimeout(saveTimer);saveTimer=setTimeout(()=>{saveTimer=null;savePresentation();},250);}
  function updateSelectionStatus(value="None"){el("graph-selected").textContent=`Selected: ${value}`;const active=cy?.nodes(":selected").length>0;for(const id of ["graph-size-up","graph-size-down","graph-size-reset"])el(id).disabled=!active;}
  function revealStoredNode(n) {
    if(!n||!presentation)return;
    if(n.type==="certificate"){presentation.value.certificates="expanded";el("graph-certificates").value="expanded";}
    if((n.roles||[]).includes("subdomain")){presentation.value.hostnames="expanded";el("graph-hostnames").value="expanded";}
    presentation.value.hiddenTypes=presentation.value.hiddenTypes.filter(type=>type!==n.type);
    if(["domain","ip","asn","organization","url"].includes(n.type))el(`graph-show-${n.type}`).checked=true;
  }
  function link(parent, id) {action(parent, `Inspect evidence #${id}`, () => inspectEvidence(id));}
  function evidenceList(parent, rows) {
    for (const row of rows) {
      text(parent, `Evidence #${row.id} · ${row.source_type} · ${row.provider || row.collector} ${row.version} · captured ${row.captured_at} UTC · run #${row.run_id}${row.synthetic_fixture ? " · synthetic fixture" : ""}`);
      text(parent, `Source: ${row.source_ref} · SHA-256: ${row.sha256}`); link(parent,row.id);
      const run = document.createElement("a"); run.href = `/api/cases/${caseId}/runs/${row.run_id}/evidence`; run.target = "_blank"; run.rel = "noopener"; run.textContent = `Run #${row.run_id} evidence`; parent.append(run);
    }
  }
  function revealInspector() {if (window.consoleInspector) window.consoleInspector(true);}
  async function inspectTarget(target) {
    selected=null;++inspection;cy?.elements().removeClass("muted adjacent").unselect();
    const root=storedTargetRoots(targetRows,data.entities).find(r=>r.target.id===target.id);
    if(root?.entity)return inspectNode(root.entity.id);
    revealInspector();el("graph-expand").disabled=true;
    const panel=el("graph-detail");panel.replaceChildren();
    text(panel,"TARGET · "+target.type.toUpperCase(),"p","inspector-label");text(panel,target.normalized_value,"p","inspector-value");
    text(panel,`Target #${target.id}`,"h4");text(panel,"Scope: "+target.scope_status.replaceAll("_"," "));
    cy?.getElementById(`t${target.id}`).select();updateSelectionStatus(target.normalized_value);
    text(panel,"No correlated infrastructure discovered yet. This marker represents your stored target, not a collected entity or confirmed finding.");
    text(panel,`Created: ${target.created_at} UTC · Updated: ${target.updated_at} UTC`);
    action(panel,"Go to collectors",()=>window.openStoredCollectorControls?.(target));
    action(panel,"Manage target",()=>window.consoleNavigate?.("targets"));
  }
  async function inspectEvidence(id) {
    const savedCase = caseId, token = generation, request = ++inspection;
    const item = await api(`/api/cases/${savedCase}/evidence/${id}`);
    if (!current(savedCase, token) || request !== inspection) return;
    revealInspector(); const panel = el("graph-detail"); panel.replaceChildren();
    text(panel,`Evidence #${id} · run #${item.run_id}`,"h4");
    text(panel,`Captured ${item.captured_at} UTC · source ${item.source_type} · ${item.source_ref}`);
    const provenance=window.evidenceProvenance?.(id)||data.evidence.find(row=>row.id===id);
    if(provenance?.collector)text(panel,`Collector: ${provenance.collector} · version ${provenance.version}`);
    if(provenance?.target_id)text(panel,`Target #${provenance.target_id}`);
    const runLink=document.createElement("a");runLink.href=`/api/cases/${savedCase}/runs/${item.run_id}/evidence`;runLink.target="_blank";runLink.rel="noopener";runLink.textContent=`Run #${item.run_id} evidence`;panel.append(runLink);
    text(panel,`Stored SHA-256: ${item.sha256}`);
    if (window.verifyStoredEvidence) action(panel,"Verify raw evidence hash",async()=>{const result=await window.verifyStoredEvidence(item); if(current(savedCase,token)&&request===inspection)text(panel,result);});
    action(panel,"View stored collector activity",()=>window.consoleNavigate?.("collectors"));
    text(panel,"Normalized observation / raw provenance","p","inspector-label");
    text(panel,JSON.stringify({parsed:item.parsed_json,raw:item.raw_json},null,2),"pre");
  }
  function emphasize(id) {
    if (!cy) return;
    cy.elements().removeClass("muted adjacent");
    const node=cy.getElementById(`n${id}`);
    if (node.empty()) return;
    cy.elements().unselect(); node.select();
    const neighbors=node.closedNeighborhood(); cy.elements().difference(neighbors).addClass("muted"); neighbors.addClass("adjacent");
  }
  async function inspectNode(id, offset = 0) {
    selected=id; el("graph-expand").disabled=false; emphasize(id);
    updateSelectionStatus(data.entities.find(n=>n.id===id)?.value||`Entity #${id}`);
    const savedCase=caseId,token=generation,request=++inspection;
    const detail=await api(`/api/cases/${savedCase}/entities/${id}/detail?offset=${offset}`);
    if(!current(savedCase,token)||request!==inspection)return;
    revealInspector(); const panel=el("graph-detail"); panel.replaceChildren();
    text(panel,typeName(detail.entity),"p","inspector-label");text(panel,detail.entity.value,"p","inspector-value");text(panel,`Entity #${id}`,"h4");
    text(panel,`Sources: ${(data.entities.find(n=>n.id===id)?.sources||[]).join(", ")||"Not supplied"}`);
    for(const root of storedTargetRoots(targetRows,data.entities).filter(r=>r.entity?.id===id))text(panel,`TARGET #${root.target.id} · ${root.target.scope_status.replaceAll("_"," ")}`);
    text(panel,`First seen: ${detail.first_seen ? detail.first_seen+" UTC" : "Not established"}`);
    text(panel,`Last seen: ${detail.last_seen ? detail.last_seen+" UTC" : "Not established"}`);
    const confidence=detail.relationships.map(e=>e.confidence).filter(Number.isFinite);
    if(confidence.length)text(panel,`Related evidence support confidence: ${Math.round(Math.min(...confidence)*100)}–${Math.round(Math.max(...confidence)*100)}%. Not an entity certainty score.`);
    text(panel,`Relationships (${detail.relationships.length})`,"p","inspector-label");
    for(const edge of detail.relationships){const a=data.entities.find(n=>n.id===edge.from),b=data.entities.find(n=>n.id===edge.to);action(panel,`${a?.value||"#"+edge.from} → ${edge.type} → ${b?.value||"#"+edge.to}`,()=>inspectEdge(edge));}
    action(panel,"Focus neighbors",()=>{focusedIds=new Set([id]);el("graph-expand").onclick();});
    action(panel,"View timeline",()=>{if(window.consoleNavigate)window.consoleNavigate("timeline");});
    if(window.findingsForEntity){const findings=window.findingsForEntity(id);if(findings.length){text(panel,`Affected findings (${findings.length})`,"p","inspector-label");for(const finding of findings)action(panel,`Finding #${finding.id}: ${finding.title}`,()=>window.inspectStoredFinding(finding.id));}}
    text(panel,"Supporting evidence","p","inspector-label");evidenceList(panel,detail.evidence);
    if(!detail.evidence.length)text(panel,"No related evidence established in this bounded view; no timestamp is inferred.");
    if(detail.truncated)text(panel,"Inspection is bounded; additional stored records may exist.");
    if(offset>0)action(panel,"Previous evidence",()=>inspectNode(id,Math.max(0,offset-100)));
    if(detail.has_more)action(panel,"Next evidence",()=>inspectNode(id,offset+100));
    if(Object.keys(detail.entity.attributes||{}).length){text(panel,"Stored attributes","p","inspector-label");text(panel,JSON.stringify(detail.entity.attributes,null,2),"pre");}
  }
  function inspectEdge(edge) {
    ++inspection;revealInspector();const panel=el("graph-detail");panel.replaceChildren();
    if(cy){cy.elements().removeClass("muted adjacent").unselect();cy.getElementById(storedEdgeKey(edge)).select();}
    selected=null;el("graph-expand").disabled=true;updateSelectionStatus(edge.type);
    const a=data.entities.find(n=>n.id===edge.from),b=data.entities.find(n=>n.id===edge.to);
    text(panel,edge.type,"h4");text(panel,`${a?.value||"#"+edge.from} → ${b?.value||"#"+edge.to}`,"p","inspector-value");
    text(panel,`${edge.classification} · confidence ${Math.round(edge.confidence*100)}%`);
    text(panel,"Why are these connected?","p","inspector-label");text(panel,edge.rule);
    text(panel,`First seen ${edge.first_seen} UTC · Last seen ${edge.last_seen} UTC`);
    if(edge.support_ids?.length)text(panel,`Stored relationship/support IDs: ${edge.support_ids.map(id=>"#"+id).join(", ")}`);
    evidenceList(panel,data.evidence.filter(row=>edge.evidence_ids.includes(row.id)));
    const present=new Set(data.evidence.map(row=>row.id));for(const id of edge.evidence_ids)if(!present.has(id))link(panel,id);
    for(const id of [edge.from,edge.to])action(panel,`Inspect entity #${id}`,()=>inspectNode(id));
  }
  function options(){return{type:el("graph-type").value,confidence:Math.min(1,Math.max(0,Number(el("graph-confidence").value)||0)),source:el("graph-source").value};}
  const styles=[
    {selector:"node",style:{"background-color":"data(color)",shape:"data(shape)",width:"data(size)",height:"data(size)",label:"data(label)",color:"#ccd9e6","font-size":11,"text-wrap":"wrap","text-max-width":150,"text-valign":"bottom","text-margin-y":9,"border-width":1,"border-color":"#9cb4c6","text-background-color":"#0c1520","text-background-opacity":.92,"text-background-padding":3}},
    {selector:"edge",style:{width:1.5,"line-color":"#526a80","target-arrow-color":"#526a80","target-arrow-shape":"triangle","curve-style":"bezier","control-point-step-size":70,label:"data(label)",color:"#a2b5c8","font-size":8,"text-opacity":0,"text-margin-y":-8,"text-rotation":"autorotate","text-background-color":"#0c1520","text-background-opacity":.95,"text-background-padding":3}},
    {selector:"edge.labels, edge:selected, edge.adjacent, edge.hovered",style:{"text-opacity":1}},
    {selector:"edge[derived = 1]",style:{"line-style":"dashed"}},
    {selector:".muted",style:{opacity:.3}},{selector:".adjacent",style:{opacity:1}},
    {selector:"edge.adjacent",style:{width:2.5,"line-color":"#8cbbb9","target-arrow-color":"#8cbbb9"}},
    {selector:"node[root = 1]",style:{"border-width":3,"border-color":"#a3ded6","font-size":12,shape:"round-hexagon"}},
    {selector:"node:selected",style:{"border-width":4,"border-color":"#b7f1e6"}},
    {selector:"edge:selected",style:{"line-color":"#a2ded7","target-arrow-color":"#a2ded7",width:3}},
    {selector:".new-discovery",style:{"border-width":4,"border-color":"#a2e8df","line-color":"#a2e8df","target-arrow-color":"#a2e8df",opacity:1}}
  ];
  function render() {
    if(!data)return;
    const filtered=graphDisplaySelection(data,options(),presentation.value),available=focusedIds?filtered.nodes.filter(n=>focusedIds.has(n.id)):filtered.nodes;
    const roots=storedTargetRoots(targetRows,data.entities);
    const nodes=available.slice(0,cap);
    // Keep mapped roots locatable even when a filter hides their infrastructure.
    for(const root of roots)if(root.entity&&!nodes.some(n=>n.id===root.entity.id))nodes.push(root.entity);
    const virtual=roots.filter(r=>!r.entity),ids=new Set(nodes.map(n=>n.id)),filteredIds=new Set(available.map(n=>n.id)),edges=filtered.edges.filter(e=>ids.has(e.from)&&ids.has(e.to)&&filteredIds.has(e.from)&&filteredIds.has(e.to)).slice(0,3000);
    const colors={domain:"#66b7b3",ip:"#7da7ce",asn:"#999ec6",certificate:"#c0bea2",organization:"#94aeb9",url:"#75afbd"},shapes={domain:"ellipse",ip:"round-rectangle",asn:"hexagon",certificate:"diamond",organization:"round-rectangle",url:"rectangle"};
    const created=!cy;
    if(!cy){
      if(typeof cytoscape!=="function"){el("graph-message").textContent="Local graph library unavailable. Stored API views remain available.";return;}
      cy=cytoscape({container:el("case-graph"),elements:[],style:styles,layout:{name:"preset"},autoungrabify:false,autolock:false,minZoom:.05,maxZoom:4,wheelSensitivity:.3});
      cy.on("tap","node",event=>{const target=event.target.data("targetRecord");(target?inspectTarget(target):inspectNode(event.target.data("entityId"))).catch(showError);});
      cy.on("tap","edge",event=>inspectEdge(event.target.data("stored")));
      cy.on("tap",event=>{if(event.target!==cy)return;selected=null;++inspection;cy.elements().removeClass("muted adjacent").unselect();el("graph-expand").disabled=true;updateSelectionStatus();el("graph-detail").textContent="Select a target, entity or relationship to inspect it.";window.consoleInspector?.(false);});
      cy.on("dragfree","node",()=>savePresentation());cy.on("pan zoom",()=>scheduleSave());
      cy.on("mouseover","node",event=>{el("case-graph").title=event.target.data("fullValue");});cy.on("mouseout","node",()=>{el("case-graph").title="";});
      cy.on("mouseover","edge",event=>event.target.addClass("hovered"));cy.on("mouseout","edge",event=>event.target.removeClass("hovered"));
    }
    const first=cy.nodes().length===0&&(nodes.length+virtual.length)>0,desired=new Set([...nodes.map(n=>`n${n.id}`),...virtual.map(r=>`t${r.target.id}`),...edges.map(storedEdgeKey)]);
    if(!created)savePresentation();applying=true;cy.batch(()=>{
      cy.elements().removeClass("new-discovery");
      cy.elements().filter(element=>!desired.has(element.id())).remove();
      for(const n of nodes){const targetRoot=roots.find(r=>r.entity?.id===n.id),root=Boolean(targetRoot),saved=presentation.value.nodes[`n${n.id}`]||(targetRoot?presentation.value.nodes[`t${targetRoot.target.id}`]:null);const payload={id:`n${n.id}`,label:label(n),fullValue:n.value,size:saved?.size||(root?54:n.type==="certificate"?28:34),color:colors[n.type]||"#a3b3c2",shape:shapes[n.type]||"ellipse",entityId:n.id};const existing=cy.getElementById(payload.id);if(existing.empty()){const angle=(n.id*2.399963)% (2*Math.PI),incident=edges.find(e=>e.from===n.id||e.to===n.id),neighbor=incident?cy.getElementById(`n${incident.from===n.id?incident.to:incident.from}`):null,center=neighbor&&!neighbor.empty()?neighbor.position():{x:0,y:0},radius=first?210+Math.floor(nodes.indexOf(n)/10)*140:150;cy.add({data:payload,position:saved?{x:saved.x,y:saved.y}:root?{x:roots.findIndex(r=>r.entity?.id===n.id)*210,y:0}:{x:center.x+Math.cos(angle)*radius,y:center.y+Math.sin(angle)*radius}});}else for(const [key,value]of Object.entries(payload))existing.data(key,value);}
      for(const edge of edges){const payload={id:storedEdgeKey(edge),source:`n${edge.from}`,target:`n${edge.to}`,label:edge.type.replaceAll("_"," "),derived:edge.classification==="derived"?1:0,stored:edge};const existing=cy.getElementById(payload.id);if(existing.empty())cy.add({data:payload});else for(const [key,value]of Object.entries(payload))existing.data(key,value);}
      cy.nodes().data("root",0);
      for(const root of roots){if(root.entity){const n=root.entity;cy.getElementById(`n${n.id}`).data("root",1).data("label",`${n.value.length>26?n.value.slice(0,23)+"…":n.value}\nTARGET`);continue;}const saved=presentation.value.nodes[`t${root.target.id}`],payload={id:`t${root.target.id}`,label:`${root.target.normalized_value.length>26?root.target.normalized_value.slice(0,23)+"…":root.target.normalized_value}\nTARGET`,fullValue:root.target.normalized_value,size:saved?.size||54,color:"#66b7b3",shape:"round-hexagon",root:1,targetRecord:root.target};const existing=cy.getElementById(payload.id);if(existing.empty())cy.add({data:payload,position:saved?{x:saved.x,y:saved.y}:{x:virtual.indexOf(root)*210,y:0}});else for(const [key,value]of Object.entries(payload))existing.data(key,value);}
      for(const [id,expires] of highlighted)if(expires>Date.now())cy.getElementById(id).addClass("new-discovery");
    });
    applying=false;cy.edges().toggleClass("labels",presentation.value.edgeLabels);
    if(created){if(presentation.value.viewport){applying=true;cy.zoom(presentation.value.viewport.zoom);cy.pan("x",presentation.value.viewport.pan.x);cy.pan("y",presentation.value.viewport.pan.y);applying=false;needsFit=false;}else needsFit=true;}
    if(selected!==null){if(cy.getElementById(`n${selected}`).empty()){selected=null;updateSelectionStatus("Hidden by view controls");}else emphasize(selected);}
    el("graph-inspect").replaceChildren();const blank=document.createElement("option");blank.value="";blank.textContent="Choose an entity";el("graph-inspect").append(blank);
    for(const n of nodes){const option=document.createElement("option");option.value=n.id;option.textContent=`#${n.id} ${n.type}: ${n.value}`;el("graph-inspect").append(option);}
    for(const root of virtual){const option=document.createElement("option");option.value=`t${root.target.id}`;option.textContent=`TARGET: ${root.target.normalized_value}`;el("graph-inspect").append(option);}
    el("graph-message").textContent=`${nodes.length}/${data.entities.length} entities · ${roots.length} targets · ${edges.length}/${data.relationships.length} relationships. ${data.truncated?"More records may exist beyond this view. ":""}${!available.length&&data.entities.length?"No infrastructure matches these filters; targets remain visible.":"Select to inspect. Drag to arrange."}`;
    el("graph-groups").textContent=`Certificates (${data.entities.filter(n=>n.type==="certificate").length}): ${presentation.value.certificates} · Hostnames (${data.entities.filter(n=>(n.roles||[]).includes("subdomain")).length}): ${presentation.value.hostnames} · showing ${nodes.length}/${data.entities.length} entities`;
    el("graph-more").disabled=nodes.length>=available.length||cap>=1000;
    if(el("graph-empty")){el("graph-empty").hidden=data.entities.length>0;el("graph-empty-title").textContent=roots.length?"No infrastructure discovered yet":"No targets added to this case yet";el("graph-empty-action").textContent=roots.length?"Go to collectors":"Add a target";el("graph-empty-action").onclick=()=>window.consoleNavigate?.(roots.length?"collectors":"targets");}
  }
  function acceptSnapshot(next){
    const delta={nodes:initialized?next.entities.filter(n=>!seenNodes.has(n.id)).map(n=>n.id):[],edges:initialized?next.relationships.filter(e=>!seenEdges.has(storedEdgeKey(e))).map(storedEdgeKey):[]};data=next;initialized=true;
    for(const n of next.entities)seenNodes.add(n.id);for(const e of next.relationships)seenEdges.add(storedEdgeKey(e));
    for(const id of delta.nodes)highlighted.set(`n${id}`,Date.now()+1500);
    for(const id of delta.edges)highlighted.set(id,Date.now()+1500);
    const source=el("graph-source").value;el("graph-source").replaceChildren();
    for(const value of ["",...new Set(data.entities.flatMap(n=>n.sources||[]).concat(data.relationships.flatMap(e=>e.sources||[])))]){const option=document.createElement("option");option.value=value;option.textContent=value||"All sources";el("graph-source").append(option);}el("graph-source").value=source;
    render();
    if(delta.nodes.length||delta.edges.length){
      el("graph-message").textContent+=` Snapshot additions: ${delta.nodes.length} entities, ${delta.edges.length} logical relationships. New records outside current filters/display cap remain stored.`;
      const savedCase=caseId,savedCy=cy;
      // Reduced motion uses the same short static outline, without size animation.
      if(!reduced()&&cy&&!cy.headless())for(const id of delta.nodes){const node=cy.getElementById(`n${id}`);if(!node.empty())node.animate({style:{"border-width":2}},{duration:1200});}
      if(typeof setTimeout==="function"){const timer=setTimeout(()=>{timers.delete(timer);if(caseId!==savedCase||cy!==savedCy)return;for(const [id,expiry]of highlighted)if(expiry<=Date.now()){highlighted.delete(id);cy?.getElementById(id).removeClass("new-discovery").removeStyle("border-width");}},1600);timers.add(timer);}
    }
    if(window.onInvestigationData)window.onInvestigationData(data,delta);
  }
  async function loadTimeline(){
    const savedCase=caseId,token=generation,request=++timelineRequest,result=await api(`/api/cases/${savedCase}/timeline?offset=${timelineOffset}`);
    if(!current(savedCase,token)||request!==timelineRequest)return;
    const parent=el("timeline-events");parent.replaceChildren();
    for(const event of result.events){
      const values=(event.entity_ids||[]).map(id=>data.entities.find(n=>n.id===id)?.value||`Entity #${id}`);
      const description=event.type==="evidence.captured"?`${event.source.toUpperCase()} evidence captured`:event.type==="relationship.first_seen"?`${values.join(" → ")} · ${event.source} (${event.classification||"stored"})`:event.source;
      const item=text(parent,`${event.timestamp} UTC · ${description}`,"li");
      for(const id of event.evidence_ids.slice(0,20))link(item,id);
      if(event.evidence_ids.length>20)text(item,`${event.evidence_ids.length} stored support records; bounded links displayed.`);
      for(const id of event.entity_ids)action(item,`Entity #${id}`,()=>{if(window.consoleNavigate)window.consoleNavigate("graph");return inspectNode(id);});
      for(const id of event.run_ids){const anchor=document.createElement("a");anchor.href=`/api/cases/${caseId}/runs/${id}/evidence`;anchor.target="_blank";anchor.rel="noopener";anchor.textContent=`Run #${id}`;item.append(anchor);}
      if(event.type==="relationship.first_seen"){const edge=data.relationships.find(e=>`relationship:${e.from}:${e.to}:${e.type}`===event.key);if(edge)action(item,"Inspect relationship",()=>inspectEdge(edge));}
    }
    el("timeline-message").textContent=result.events.length?`Events ${timelineOffset+1}–${timelineOffset+result.events.length} of ${result.bounded_total}. ${result.truncated?"Additional events may exist.":"Chronological investigation activity."}`:"Your investigation timeline is empty. Add a target and review Collectors to begin; collection requires your explicit action.";
    if(!result.events.length){const item=text(parent,"Your next step","li","timeline-empty");action(item,targetRows.some(t=>!t.archived)?"Go to collectors":"Go to targets",()=>window.consoleNavigate?.(targetRows.some(t=>!t.archived)?"collectors":"targets"));}
    el("timeline-previous").disabled=timelineOffset===0;el("timeline-next").disabled=!result.has_more;
    if(window.onStoredTimeline)window.onStoredTimeline(result);
  }
  window.resetInvestigation=()=>{
    savePresentation();if(saveTimer)clearTimeout(saveTimer);saveTimer=null;presentation=null;
    ++generation;++inspection;++timelineRequest;data=null;caseId=null;selected=null;focusedIds=null;cap=200;timelineOffset=0;highlighted.clear();needsFit=true;targetRows=[];seenNodes.clear();seenEdges.clear();initialized=false;
    for(const timer of timers)clearTimeout(timer);timers.clear();if(cy){cy.destroy();cy=null;}
    updateSelectionStatus();
    el("graph-controls").hidden=true;el("graph-expand").disabled=true;el("graph-load").disabled=false;el("graph-detail").replaceChildren();el("graph-detail").textContent="Select an entity or relationship to inspect it.";el("timeline-events").replaceChildren();el("graph-search").value="";el("graph-type").value="";el("graph-confidence").value="0";
    el("graph-search-results").replaceChildren();el("graph-search-results").hidden=true;
  };
  window.inspectStoredEntity=async id=>{if(window.consoleNavigate)window.consoleNavigate("graph");if(!data||caseId!==selectedCase.id)await el("graph-load").onclick();revealStoredNode(data.entities.find(n=>n.id===id));render();await inspectNode(id);};
  window.updateInvestigationTargets=(rows,offset=0)=>{targetRows=offset?Array.from(new Map([...targetRows,...rows].map(t=>[t.id,t])).values()):rows;if(data&&caseId===selectedCase?.id)render();};
  window.inspectStoredTarget=async target=>{window.consoleNavigate?.("graph");if(!data||caseId!==selectedCase.id)await el("graph-load").onclick();await inspectTarget(target);const root=storedTargetRoots(targetRows,data.entities).find(r=>r.target.id===target.id),node=cy?.getElementById(root?.entity?`n${root.entity.id}`:`t${target.id}`);if(node&&!node.empty()){node.select();cy.animate({center:{eles:node}},{duration:reduced()?0:200});}};
  window.inspectStoredEvidence=async id=>{if(!data||caseId!==selectedCase.id)await el("graph-load").onclick();await inspectEvidence(id);};
  window.updateInvestigationSnapshot=next=>{if(caseId===selectedCase?.id&&next.case_id===caseId&&JSON.stringify(data)!==JSON.stringify(next))acceptSnapshot(next);};
  window.resizeInvestigation=()=>{cy?.resize();if(cy&&needsFit&&el("case-graph").clientWidth>0&&el("case-graph").clientHeight>0){cy.fit(undefined,50);needsFit=false;}};
  window.refreshStoredTimeline=()=>{timelineOffset=0;return loadTimeline();};
  el("graph-load").onclick=async()=>{
    if(!selectedCase)return;caseId=selectedCase.id;if(!presentation)loadPresentation();const savedCase=caseId,token=++generation;el("graph-load").disabled=true;
    try{const result=await api(`/api/cases/${savedCase}/investigation`);if(!current(savedCase,token))return;el("graph-controls").hidden=false;acceptSnapshot(result);await loadTimeline();}catch(error){showError(error);}finally{if(current(savedCase,token))el("graph-load").disabled=false;}
  };
  el("graph-apply").onclick=()=>{focusedIds=null;cap=200;render();};
  el("graph-more").onclick=()=>{cap=Math.min(1000,cap+200);render();};
  el("graph-focus").onclick=()=>{if(!data)return;el("graph-search-results").hidden=true;const query=el("graph-search").value.trim().toLowerCase();const match=storedGraphSelection(data,options()).nodes.find(n=>query&&(n.value.toLowerCase().includes(query)||String(n.id)===query));if(!match){const target=targetRows.find(t=>!t.archived&&query&&t.normalized_value.toLowerCase().includes(query));if(target){window.inspectStoredTarget(target).catch(showError);return;}el("graph-message").textContent="No matching targets or entities within current filters.";return;}revealStoredNode(match);selected=match.id;focusedIds=new Set([match.id]);render();cy?.fit(undefined,70);inspectNode(match.id).catch(showError);};
  el("graph-search").oninput=()=>{
    const parent=el("graph-search-results"),query=el("graph-search").value.trim().toLowerCase();parent.replaceChildren();parent.hidden=!query||!data;if(parent.hidden)return;
    const matches=storedGraphSelection(data,options()).nodes.filter(n=>n.value.toLowerCase().includes(query)||String(n.id)===query).slice(0,8);
    for(const n of matches)action(parent,`${typeName(n)} · ${n.value}`,()=>{parent.hidden=true;revealStoredNode(n);selected=n.id;focusedIds=new Set([n.id]);render();cy?.fit(undefined,70);return inspectNode(n.id);});
    for(const root of storedTargetRoots(targetRows,data.entities).filter(r=>!r.entity&&r.target.normalized_value.toLowerCase().includes(query)).slice(0,8))action(parent,`TARGET · ${root.target.normalized_value}`,()=>{parent.hidden=true;return window.inspectStoredTarget(root.target);});
    if(!parent.children.length)text(parent,"No matching targets or entities within these filters.");
  };
  el("graph-expand").onclick=()=>{if(!data||selected===null)return;const filtered=storedGraphSelection(data,options());focusedIds=focusedIds||new Set([selected]);for(const edge of filtered.edges)if(edge.from===selected||edge.to===selected){focusedIds.add(edge.from);focusedIds.add(edge.to);}render();cy?.fit(undefined,60);};
  el("graph-reset").onclick=()=>{focusedIds=null;selected=null;cap=200;el("graph-expand").disabled=true;el("graph-type").value="";el("graph-source").value="";el("graph-confidence").value="0";cy?.elements().removeClass("muted adjacent").unselect();render();};
  el("graph-fit").onclick=()=>{cy?.resize();cy?.fit(undefined,50);};
  el("graph-relayout").onclick=()=>{if(!cy)return;applying=true;cy.layout({name:el("graph-layout").value||"cose",animate:false,padding:90,randomize:false,nodeDimensionsIncludeLabels:true,nodeRepulsion:18000,idealEdgeLength:180,spacingFactor:1.5,roots:cy.nodes("[root = 1]"),directed:true}).run();applying=false;needsFit=false;savePresentation();};
  for(const field of ["certificates","hostnames"])el(`graph-${field}`).onchange=()=>{if(!presentation)return;presentation.value[field]=el(`graph-${field}`).value;focusedIds=null;render();savePresentation();};
  for(const type of ["domain","ip","asn","organization","url"])el(`graph-show-${type}`).onchange=()=>{if(!presentation)return;presentation.value.hiddenTypes=["domain","ip","asn","organization","url"].filter(t=>!el(`graph-show-${t}`).checked);render();savePresentation();};
  el("graph-edge-labels").onchange=()=>{if(!presentation)return;presentation.value.edgeLabels=el("graph-edge-labels").checked;cy?.edges().toggleClass("labels",presentation.value.edgeLabels);savePresentation();};
  const resizeNode=mode=>{const node=cy?.nodes(":selected").first();if(!node||node.empty())return;const base=node.data("root")?54:data.entities.find(n=>n.id===node.data("entityId"))?.type==="certificate"?28:34;node.data("size",mode==="reset"?base:Math.max(24,Math.min(100,node.data("size")+(mode==="up"?8:-8))));savePresentation();};
  for(const mode of ["up","down","reset"])el(`graph-size-${mode}`).onclick=()=>resizeNode(mode);
  for(const [id,factor]of [["graph-zoom-in",1.25],["graph-zoom-out",.8]])el(id).onclick=()=>{if(cy){cy.zoom({level:Math.max(.05,Math.min(4,cy.zoom()*factor)),renderedPosition:{x:cy.width()/2,y:cy.height()/2}});needsFit=false;savePresentation();}};
  if(typeof window.addEventListener==="function")window.addEventListener("pagehide",()=>savePresentation());
  el("graph-inspect").onchange=()=>{const value=el("graph-inspect").value;if(value.startsWith("t"))inspectTarget(targetRows.find(t=>t.id===Number(value.slice(1)))).catch(showError);else if(value)inspectNode(Number(value)).catch(showError);};
  el("timeline-previous").onclick=()=>{timelineOffset=Math.max(0,timelineOffset-100);loadTimeline().catch(showError);};
  el("timeline-next").onclick=()=>{timelineOffset+=100;loadTimeline().catch(showError);};
  el("timeline-refresh").onclick=()=>loadTimeline().catch(showError);
  if(typeof ResizeObserver==="function")new ResizeObserver(()=>window.resizeInvestigation()).observe(el("case-graph"));
})();
